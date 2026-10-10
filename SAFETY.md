# SAFETY.md — invariants scnr never breaks

scnr is a defensive discovery tool. It observes and reports; it never exploits.
These invariants are enforced in code and tests, not by policy alone.

1. **No exploitation code exists.** No payload execution, credential brute
   force, denial of service, or state-changing checks. `domain.Rule.Safety`
   has exactly two values, `safe` and `intrusive`; intrusive (Phase 4) means
   non-destructive only (POST <= 4 KiB, inert canaries) and loads only with
   `--allow-intrusive` plus consent.
2. **Authorization is acknowledged for every scan.** `authorization.acknowledged`
   in `scnr.yaml` (written by `scnr scope init` with OS user and time) or
   `--ack-authorized`. Missing acknowledgment exits 3 and is audited.
3. **Scope deny always wins.** Allow/deny entries are checked against the
   hostname and every resolved address. Cloud metadata and credential
   endpoints (`169.254.169.254`, `169.254.170.2`, `fd00:ec2::254`,
   `100.100.100.200`) are denied by default (`safety.BuiltinDeny`).
   URL allow entries match by parsed scheme, host, port and path segment,
   never by raw string prefix, and bound every HTTP request the native
   engines send: the scope-checked client validates the full URL of each
   request (first hop and redirects alike) in one place, and webscan skips
   template paths outside the allowed prefix instead of requesting them.
   *Residual (nuclei):* nuclei resolves and connects on its own, so
   hostname and URL deny entries are **not** enforced inside it; only the
   IP/CIDR deny list can be (and nuclei has no exclusion flag for the
   redirect targets it would otherwise follow, which is why redirects are
   disabled). Gate-time deny checks still apply to the target itself.
4. **Public targets need proof.** A public address must be in `scope.allow`
   and either interactively consented to (the plan is shown and the user
   types the target back) or covered by a non-expired ownership
   verification (DNS TXT or well-known file). `--non-interactive` without
   verification exits 3. The allow list alone is never proof of ownership.
5. **Scope is re-checked at dial time.** `safety.Dialer` resolves, compares
   the answer with the addresses pinned at authorization (DNS rebinding),
   re-applies deny/allow/private rules, and connects to the checked IP, not
   the hostname. HTTP redirects are re-validated per hop (max 5); an
   out-of-scope redirect becomes `web.redirect-out-of-scope` and is not
   followed. A scan that authorised a public target never dials or follows
   a redirect into loopback, RFC1918, link-local or ULA space; netscan's
   TLS probes use the same dialer.
   *Residual (nuclei):* the dialer cannot sit in nuclei's path. The adapter
   compensates by (a) rewriting a hostname target to the single address the
   gate pinned, with `-H "Host: <name>"` and `-sni <name>`, so nuclei never
   re-resolves the name; (b) refusing to run nuclei for a public hostname
   that was pinned to several addresses or to none (the engine is reported
   `skipped` with the reason and a `--skip-engines adapter:nuclei` hint;
   the scan is marked partial); (c) `-disable-redirects` and `-type http`
   so nuclei follows no redirect and runs no dns/tcp/ssl/javascript
   protocol templates. Private-only scans run nuclei unpinned by name: a
   rebinding of a private name to another private address during the run
   is not detected there. These flags are verified against fake binaries in
   tests; nuclei is not exercised against a live network in CI.
6. **Rate and concurrency are capped.** Private: 500 conn/s, 64 per host,
   20 HTTP rps/host. Public: 100, 16, 10. Raising above 2x needs
   `--i-understand-rate-limits` and is audited. CIDR caps: private <= /16,
   public <= /24, override `--max-hosts` is audited.
7. **Secrets are redacted before Evidence exists.** At most a quarter of a
   value (max 6 characters; 2 for values under 16, none under 8) plus an
   HMAC-SHA256 keyed with the per-install secret are ever stored or
   printed. Credentials in a target URL are rejected and never echoed.
   There is no `--show-secrets`. Logs pass through the same redactor.
8. **Audit log is append-only.** `store` contains no UPDATE/DELETE for
   `audit_log` (asserted by a test) and database triggers abort any
   UPDATE/DELETE. `scnr db migrate --down` refuses while `audit_log` has
   rows unless `--i-understand-audit-loss`, which is itself audited first.
   Every scan, gate refusal, verification, DB update and limit override
   writes one row.
9. **No telemetry.** Outbound connections scnr itself makes are only:
   in-scope targets, `api.osv.dev` (unless `--offline`; the image engine
   uses the same client for OS packages), `www.cisa.gov` and
   `epss.cyentia.com` with its redirect target `epss.empiricalsecurity.com`
   (only during `scnr db update`), and
   `osv-vulnerabilities.storage.googleapis.com` (only during `scnr db
   bundle build`). Every one of them goes through `safety.NewEndpointClient`,
   whose fixed host allowlist refuses any other destination, private
   addresses and redirects included. A component handed no client fails
   with "no HTTP client" rather than falling back to `http.DefaultClient`.
   `TestNoRawDialers` parses every non-test source under `internal/`,
   resolves `net`/`net/http` import aliases, and fails the build on:
   `net.Dial*`, `http.DefaultClient`/`DefaultTransport`, `http.Get`/`Post`/
   `Head`/`PostForm`; composite literals, `new()`, and value-typed
   variables, fields or type declarations of `net.Dialer` or
   `http.Transport`; any `http.Client` literal outside `internal/safety`
   (and, inside it, one without a `Transport`); and dot-imports of `net` or
   `net/http`. External tools run by adapters may fetch their own rule/DB
   bundles (item 10); `scnr doctor --online` lists both sets.
10. **External tools run with argument arrays, never shell strings**, a
    minimal environment, output caps (256 MiB) and timeouts. Forbidden
    flags (`--script`, `-sU`, `-O`, `-sC`, `-A`, `-dast`, `-fuzz`, `brute`,
    `-code`, `-headless`, `-fr`, `-follow-redirects`, and any combined nmap
    scan type such as `-sTU`/`-sVC` that switches on UDP or default scripts)
    are listed in `adapter.Forbidden`; `adapter.CheckForbidden` refuses
    them at exec time and `safety_invariants_test.go` inspects every
    adapter source file and arg builder. nmap receives the gate-pinned
    addresses (never a hostname, `-n`) and the deny list as `--exclude`;
    nuclei runs `-ni -type http -disable-redirects -duc` with
    `-et dos,fuzz,intrusive,bruteforce,dast` and
    `-response-size-save 65536`, against the pinned address (item 5). Tool
    output is parsed with field allowlists (over-long JSONL lines are
    dropped and counted, later lines still parsed), control characters
    stripped, and redacted before it becomes evidence. Absent tools degrade
    to `skipped`, never silently.
    *Phase 3 tools:* semgrep runs `scan --metrics=off --oss-only
    --disable-version-check` and never `--config auto` or `--autofix`
    (both in `adapter.Forbidden`); rules come from `tools.semgrep_rules`
    when set, else, on an online scan, the registry pack `p/default`,
    which semgrep downloads from semgrep.dev on every run (its only
    network; `scnr doctor` warns). On an `--offline` scan without
    `tools.semgrep_rules` the semgrep engine is reported `skipped` with the
    reason rather than fetching anything. trivy runs `--disable-telemetry
    --skip-version-check --offline-scan --tf-exclude-downloaded-modules`
    in every mode and never `--server`/`--token`. `--offline-scan` stops
    trivy from issuing API requests to resolve dependencies (Maven central
    for `pom.xml` parents and properties), so a scanned repository cannot
    choose an endpoint for trivy to contact. Its vulnerability and check
    databases still download from ghcr.io when the scan is online
    (`--offline` adds `--skip-db-update --skip-java-db-update
    --skip-check-update`). *Residual (trivy, unverified):* whether a
    current trivy release downloads remote Terraform modules named by a
    scanned `module` block while `--offline-scan` is set has not been
    verified against a live binary; `--tf-exclude-downloaded-modules` only
    keeps such modules out of the results. Run trivy with `--offline` or in
    a network-restricted environment when the scanned tree is untrusted.
    grype runs
    with `GRYPE_CHECK_FOR_APP_UPDATE=false` always and
    `GRYPE_DB_AUTO_UPDATE=false` when offline; `--only-fixed` is forbidden
    so unfixed findings are never hidden. Both image tools receive only
    local archive sources (item 13). `scnr doctor --online` lists what each
    tool contacts on its own.
    *Templates:* nuclei fetches its template corpus from GitHub on first
    run when its default template directory is empty; `-duc` disables only
    the periodic update check and cannot prevent that first-run download.
    Set `tools.nuclei_templates` (absolute path) in `scnr.yaml` to run
    against a local corpus you chose; it is passed as `-t` and `scnr doctor`
    reports which case applies. Whether a current nuclei release still
    performs the first-run install when `-t` names an existing directory
    has not been verified against a live binary.
13. **Container images are read from local archives only.** The native
    `image` engine and the trivy/grype adapters accept a `docker save`
    tarball (optionally gzipped) or an OCI image layout directory. Registry
    and daemon pulls are not implemented: they would run through the tools'
    own network stacks, outside `safety.Dialer`. A bare image reference is
    reported `skipped` with the `docker save` command to run instead. Only
    archive *files* (`*.tar`, `*.tar.gz`, `*.tgz`) are auto-detected as
    images; a directory is never reclassified from its content, so a
    repository that happens to contain `oci-layout` and `index.json` is
    still scanned as code. An OCI layout directory needs `--type image`
    and must carry `{"imageLayoutVersion":"1.x.y"}` in `oci-layout`. The
    archive is hostile input: tar entries with absolute, `..` or over-long
    (> 4096 byte) names are ignored and counted (`image.hostile-archive`),
    whiteouts are capped at 10,000 per layer, symlink and hardlink bodies
    are never read, nothing is extracted to disk, OCI digests must be 64 hex
    characters before they become a blob path, and decompressed bytes
    (headers and PAX records included, counted as streamed, never from
    declared sizes) are capped per layer (2 GiB) and per image (8 GiB) with
    per-layer and image-wide entry-count caps, collected-file caps and a
    metadata budget (256 small JSON blobs, 64 MiB together)
    (`image.too-large` when the byte caps are hit). zstd layers are
    refused (`image.unsupported-layer`), never shelled out to.
14. **IaC and code are parsed, never executed.** Dockerfiles use an own line
    parser; Kubernetes manifests are decoded with `yaml.v3` into nodes with
    document, depth and node-count caps (alias bombs are refused, not
    expanded); Terraform is parsed with `hashicorp/hcl` (files over 512 KiB
    skipped) and only constant-shaped expressions are evaluated
    (`jsonencode` is the one function allowed; `for`, splat and conditional
    expressions, template directives, other function calls and collections
    over 1,000 elements are rejected before evaluation; variables, locals
    and data references are unknown; none of these ever produce a finding).
    Both parsers recurse per nesting level and a Go stack overflow is fatal,
    so nesting depth is measured on the raw bytes first
    (`engine.BracketDepth`/`engine.YAMLDepth`, limit 100) and deeper files
    are skipped unparsed and reported once as `iac.file-skipped-too-complex`;
    the same pre-scan guards YAML lockfiles and webscan templates. The
    Terraform pass checks its context between blocks, and the engine Runner
    abandons any engine that is still running `AbandonGrace` after its
    timeout (the scan is marked partial; the goroutine is left to finish on
    its own with its findings refused). No `docker build`, `terraform
    init/plan`, package-manager scripts or SBOM tooling is run. Credentials
    found in `ENV`/`ARG`, env literals, variable defaults or Lambda
    environments are masked before Evidence exists (item 7), the raw value
    never leaves the engine, and their fingerprints ignore the line number
    (`domain.IsSecretRule`) like the secrets engine's.
15. **SCA tool output dedupes on the PURL, not on trust.** trivy and grype
    JSON is streamed element by element (256 MiB cap) with field allowlists;
    PURLs are re-parsed and stripped of qualifiers; paths are made relative
    to the scan root and traversal is refused; severities, IDs and CWEs are
    validated; description text is control-stripped and redacted; malformed
    elements are counted and reported, never silently dropped. SBOM output
    (`scnr sbom`, CycloneDX 1.5) goes through `cyclonedx-go`/`encoding/json`
    with every package string cleaned first, so a hostile lockfile cannot
    inject into the document.
12. **Web templates are safe matchers only.** Strict YAML, 1 MiB cap, IDs
    `^[a-z0-9-]{3,64}$`, paths `^/[A-Za-z0-9._~/-]*$` (no query, userinfo or
    `..`), RE2 regexes with a program-size cap, GET/HEAD only (POST only in
    intrusive templates, which do not load in this version), and tags such
    as dos/fuzz/bruteforce/exploit are rejected.
11. **All SQL is parameterised.** `database/sql` with `?` placeholders only.
17. **Offline bundles are signed before they are parsed.** `scnr db update
    --offline-bundle` reads only `manifest.json` (first entry, <= 1 MiB)
    and `manifest.sig` (second) until an ed25519 signature from
    `vulndb.trusted_keys` verifies over the exact manifest bytes; a
    failure is `E_BUNDLE_UNTRUSTED` (exit 3, audited) and no later byte is
    read, nothing in the database is touched. An unsigned bundle loads only
    with `--allow-unsigned` in an interactive session (refused with
    `--non-interactive`), and the acceptance is audited. After the
    signature: entry names must match a fixed grammar (no symlinks,
    hardlinks, directories, traversal or unlisted files), the decompressed
    stream is capped at 2 GiB, entries at 64, lines at 1 MiB, record counts
    must equal the manifest exactly, each record is decoded strictly
    (unknown fields rejected) and cleaned (control-stripped, redacted), and
    every file's SHA-256 must match the manifest. Rows are staged in one
    transaction and swapped in at commit; any failure rolls back, so
    `osv_affected`, `kev` and `epss` are never half-loaded. A bundle whose
    `created_at` is older than the loaded osv-offline data is refused as a
    downgrade (`E_BUNDLE_DOWNGRADE`, exit 3, audited) unless
    `--allow-downgrade` is given in an interactive session (gated and
    audited exactly like `--allow-unsigned`); a `created_at` more than 24h
    in the future is a bad bundle, so no bundle can claim a date that
    blocks later real ones. Any decompressed data after the tar end (a
    trailing gzip member) is a bad bundle and is counted against the 2 GiB
    cap while being drained. Offline matching evaluates semver ranges
    (events sorted by version, unparsable boundaries dropped) only for npm,
    Go, crates.io, Packagist, Hex and Pub; for every other ecosystem it
    relies on OSV's `versions[]` lists, and an advisory that declares
    ranges without a version list, or a range with a boundary that is not
    semver, is reported per ecosystem as `sca.range-unevaluated` with the
    engine run marked partial, never silently passed. An installed version
    that is not semver is reported as `sca.version-unparsed`. Bundles are
    built only from the OSV export bucket through the endpoint client (item
    9), assembled in a 0700 work directory and renamed into `--out`
    (refusing a symlink or non-regular file at the destination), and signed
    with a key that never leaves the building machine (`scnr db keygen`,
    0600).

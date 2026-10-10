# scnr — Defensive Vulnerability Discovery CLI

Status: draft for review | Date: 2026-10-10 | Size: L (multi-phase platform; Phase 1 MVP is ~M)

## 1. Overview and non-goals

### Goal

`scnr` is a single-binary CLI that lets someone with no penetration-testing background point it at *their own* thing (a URL, a server, a network range, a code repo, a container image, a cloud account), answer three or four questions, and get back a plain-English, prioritised list of vulnerabilities with a 0-100 posture score and a fix list. It aims to cover the everyday capability surface of nmap, Nuclei, Semgrep, Trivy/Grype, Prowler, Nessus-style vuln management and Invicti-style DAST, via **native lightweight engines** for the core plus **adapters** that orchestrate the real tools when installed and normalise their output into one Finding schema. It is strictly defensive: it discovers and reports, it never exploits.

### Why Go (settled)

Single static binary with `CGO_ENABLED=0` (pure-Go SQLite via `modernc.org/sqlite`), goroutines plus `x/sync` semaphores for bounded concurrent scanning, trivial cross-compilation for Linux/macOS/Windows release artefacts, and the scanning ecosystem we integrate with (nuclei, trivy, grype, gosec, go-containerregistry) is Go, so data models and parsers have reference implementations. Not re-litigated further.

### What "emulate" means here (honest scope)

| Capability class | Native engine (ours) | Adapter (orchestrates installed tool) | Not replicable |
|---|---|---|---|
| Network/port/service (nmap) | TCP connect scan, banner grab, TLS cert/version checks, service guess | `nmap` (-sV, XML output) | nmap OS fingerprint DB fidelity, SYN/UDP without root |
| Template web/network checks (Nuclei) | YAML template engine, safe matchers only, ~100 bundled templates | `nuclei` with intrusive/dos tags excluded | Nuclei's 9k-template corpus (use adapter) |
| SAST / code quality (Semgrep, Sonar, Checkmarx, Veracode) | Pattern-grade code checks (regex + file-type scoping), secrets | `semgrep` | Dataflow/taint analysis, Sonar quality gates, commercial engines |
| SCA / image / IaC / secrets / SBOM (Trivy, Grype, Snyk) | Lockfile SCA vs OSV, apk/dpkg image packages, Terraform/Dockerfile/K8s rules, secrets, CycloneDX SBOM | `trivy`, `grype` | Snyk proprietary advisory DB, rpm DB parsing (adapter) |
| CSPM (Prowler, Wiz, Orca) | ~25 high-value AWS checks | `prowler` (AWS/Azure/GCP) | Wiz/Orca security graph, agentless workload scanning |
| Vuln management (Nessus, Qualys, Rapid7) | Asset inventory, history, diff, trend, risk scoring (CVSS+EPSS+KEV), accept-risk, scheduler, policy gating | — | Nessus/Qualys plugin feeds, authenticated agent scans |
| DAST (Invicti, Acunetix) | Crawler + passive checks + safe active checks (canary reflection, open redirect) | `nuclei` templates | Authenticated/stateful business-logic testing, JS-heavy SPA crawling |

### Non-goals

- No exploitation, no proof-of-concept payload execution, no credential brute force, no DoS, no destructive or state-changing checks. There is no "attack" mode and no flag to add one.
- No replication of commercial vulnerability feeds or security graphs.
- No multi-user server, RBAC, or web UI in this spec (server mode is a designed-for path, Section 11 Phase 5, not built).
- No authenticated DAST (login flows) before Phase 5.
- No Windows-native engine support guarantees in Phases 1-4 (cross-compiles; adapters are Unix-first).
- No telemetry, ever, by default or opt-in in this spec.

## 2. Architecture and package layout

```
                 ┌──────────────────────────────────────────────────────────────┐
  user ───────►  │ cmd/scnr  (cobra)                                            │
                 │   wizard (huh) ──► target.Detect ──► safety.Gate ──► Runner  │
                 └───────────────┬────────────────────────────┬────────────────┘
                                 │                            │ emits Findings (stream)
                       ┌─────────▼─────────┐        ┌─────────▼──────────┐
                       │ engine registry   │        │ store (SQLite/WAL) │
                       │  native engines   │        │  assets, scans,    │
                       │  adapters (exec)  │        │  findings, audit   │
                       └───┬───────────┬───┘        └─────────┬──────────┘
                           │           │                      │
              ┌────────────▼─┐   ┌─────▼─────────┐   ┌────────▼────────┐
              │ safety.HTTP  │   │ adapter.Exec  │   │ risk + vulndb   │
              │ safety.Limit │   │ arg arrays,   │   │ CVSS/EPSS/KEV   │
              │ scope check  │   │ timeouts,     │   │ posture score   │
              │ at dial time │   │ hostile parse │   └────────┬────────┘
              └──────────────┘   └───────────────┘            │
                                                      ┌───────▼────────┐
                                                      │ report         │
                                                      │ html/json/sarif│
                                                      │ md/csv         │
                                                      └────────────────┘
```

Data flow: `Target` → detect type → safety gate (scope, consent, limits) → `Runner` selects engines for the profile → each engine streams `Finding`s via callback → fingerprint + dedupe + risk score → written to SQLite as they arrive (no in-memory accumulation) → reporters read from the store by scan ID with pagination.

### Package layout

```
cmd/scnr/main.go                   entrypoint; wires slog, config, store, registry; calls cli.Execute
internal/cli/                      one file per cobra command (scan.go, doctor.go, report.go, ...)
internal/wizard/                   huh forms; produces a cli ScanRequest, nothing else
internal/config/                   scnr.yaml + policy.yaml loading, defaults, validation
internal/domain/                   Target, Asset, Finding, Scan, Rule, Evidence, Severity, Fingerprint()
internal/target/                   type detection and normalisation
internal/safety/                   scope, consent, ownership verification, limits, safe HTTP client, redaction
internal/engine/                   Engine interface, Registry, Runner (bounded concurrency), Profile
internal/engine/netscan/           native TCP connect scan, banners, TLS checks
internal/engine/webscan/           native HTTP passive checks + template engine; templates/ embedded YAML
internal/engine/secrets/           regex + entropy secret detection; rules embedded
internal/engine/sca/               lockfile parsers, OSV client, package matching
internal/engine/codecheck/         pattern-grade code rules (Phase 3)
internal/engine/iac/               Terraform/Dockerfile/K8s rules (Phase 3)
internal/engine/image/             container image layer walk, apk/dpkg (Phase 3)
internal/engine/cloud/aws/         native AWS checks (Phase 4)
internal/adapter/                  Adapter interface, Base (exec, timeout, size caps), ToolInfo
internal/adapter/{nmap,nuclei,semgrep,trivy,grype,prowler}/   args builder + output parser each
internal/risk/                     risk score, posture score, grade
internal/vulndb/                   KEV + EPSS download/parse; OSV offline bundle (Phase 4)
internal/store/                    sqlite open/migrate; queries; migrations/ embedded NNNN_name.{up,down}.sql
internal/report/                   Reporter interface; html/ (embedded template+CSS), json, sarif, md, csv
internal/audit/                    append-only audit writer (store table + optional JSONL)
internal/doctor/                   tool discovery, version checks, install guidance text
internal/sched/                    cron parsing, daemon loop (Phase 4)
internal/plugin/                   exec-based plugin protocol (Phase 4)
internal/logx/                     slog handler setup (text for TTY, JSON otherwise)
testdata/                          fixtures: adapter outputs per tool version, lockfiles, templates
docs/                              this spec, ADRs, user docs
```

Everything under `internal/`; no public Go API in Phases 1-4. The JSON report schema (Section 8) is the public contract.

## 3. Core domain model (`internal/domain`)

```go
type TargetType string // "url" | "host" | "cidr" | "path" | "image" | "cloud"

type Target struct {
    Raw      string     // as typed by user
    Type     TargetType
    Value    string     // normalised: URL w/o fragment, IP, CIDR, abs path, image ref, "aws://profile"
    Hostname string     // for url/host; empty otherwise
    Public   bool       // resolves to / is a non-private address (drives consent + limits)
}

type Asset struct {
    ID        string    // 16-byte random hex
    Key       string    // stable natural key: "host:10.0.0.5", "url:https://x.io", "repo:/abs/path", "image:repo@sha256:..", "aws:123456789012"
    Type      TargetType
    Name      string
    Labels    map[string]string
    FirstSeen time.Time
    LastSeen  time.Time
}

type Severity int // Info=0, Low=1, Medium=2, High=3, Critical=4
type Confidence int // Tentative=0, Firm=1, Confirmed=2
type Status string // "open" | "fixed" | "accepted" | "suppressed"

type Evidence struct {
    Kind     string // "request", "response", "banner", "file", "cert", "cloud_resource", "tool_output"
    Location string // "file:line", "host:port", URL, ARN
    Redacted string // redaction applied before this struct is ever constructed; raw is never stored
    Hash     string // sha256 of raw, so re-scans can confirm "same secret" without storing it
}

type Finding struct {
    ID          string
    Fingerprint string     // Fingerprint(ruleID, assetKey, normalisedLocation)
    ScanID      string
    AssetKey    string
    RuleID      string     // "net.exposed-db-port", "sca.osv.GHSA-xxxx", "nuclei:<template-id>"
    Engine      string     // "netscan" | "sca" | "adapter:nmap" ...
    Title       string
    Severity    Severity   // as reported by rule/source
    Confidence  Confidence
    WhatItIs    string     // plain English, 1-3 sentences
    WhyItMatters string
    HowToFix    string
    Location    string
    Evidence    []Evidence // capped at 10 per finding, 4 KiB each
    CVEs        []string
    CWE         string
    CVSS        *CVSS      // Vector, Score
    EPSS        *float64   // 0..1
    KEV         bool
    Risk        int        // 0..100, Section 7
    References  []string
    Status      Status
    FirstSeen   time.Time
    LastSeen    time.Time
}

type Scan struct {
    ID         string
    StartedAt, FinishedAt time.Time
    Profile    string         // quick | standard | deep
    Targets    []Target
    Engines    []EngineRun    // name, version (adapters), status, duration, error
    Consent    ConsentRecord  // method: "interactive" | "dns-txt" | "well-known" | "private-range"; by; at
    ScopeHash  string         // sha256 of resolved allow/deny lists
    Partial    bool           // any engine skipped/failed
    Posture    PostureScore   // Score, Grade, counts per bucket
    ExitCode   int
}

type Rule struct {
    ID, Engine, Title string
    Severity   Severity
    CWE        string
    WhatItIs, WhyItMatters, HowToFix string
    References []string
    Safety     string   // "safe" | "intrusive"  (no third value exists)
    Tags       []string
}
```

`Fingerprint(ruleID, assetKey, location)` = hex(sha256(ruleID + "\x00" + assetKey + "\x00" + normalise(location))). `normalise` strips line numbers for secrets (uses evidence hash instead, so moving a secret within a file is the same finding), strips query strings for URLs, lowercases hosts. Adapters map tool-native IDs into `RuleID` (`nuclei:<id>`, `trivy:<vuln-id>@<pkg>`), so the same CVE in the same package from trivy and grype produces the same fingerprint via a shared `sca.osv.<id>@<purl>` scheme when a CVE/GHSA ID is present.

## 4. Engine and adapter interfaces (`internal/engine`, `internal/adapter`)

```go
type Options struct {
    Profile   Profile
    Limiter   *safety.Limits       // rate + concurrency budgets, already scoped to target publicness
    HTTP      *http.Client         // safety.NewHTTPClient: scope check at dial, redirect re-validation
    Scope     *safety.Scope
    Scratch   string               // per-scan temp dir, removed after run
    Log       *slog.Logger
    Online    bool                 // may contact osv.dev etc.
}

type Engine interface {
    Name() string
    Supports(t domain.Target) bool
    // Plan is shown to the user before consent and sizes the work: hosts*ports, files, requests.
    Plan(ctx context.Context, t domain.Target, o Options) (Plan, error)
    // Run streams findings; must honour ctx, o.Limiter, and never buffer all findings.
    Run(ctx context.Context, t domain.Target, o Options, emit func(domain.Finding) error) error
}

type Plan struct { Summary string; EstRequests int; EstDuration time.Duration; Network bool }

// Adapter is an Engine backed by an external binary.
type Adapter interface {
    Engine
    Binary() string                             // "nmap"
    MinVersion() string
    Detect(ctx context.Context) (ToolInfo, error) // exec.LookPath + "--version", parsed
    Args(t domain.Target, o Options) ([]string, error) // arg array; never a shell string
    Parse(r io.Reader, emit func(domain.Finding) error) error
}

type ToolInfo struct { Path, Version string; OK bool; Reason string }
```

`adapter.Base` provides: `exec.CommandContext` with the absolute path captured at `Detect`, `Env` limited to `PATH`, `HOME`, `TMPDIR` (+ cloud credential vars for prowler), stdout streamed to a file in `Scratch` (cap 256 MiB, then kill + error), stderr tail (last 8 KiB) kept for diagnostics, per-engine timeout from profile, exit-code mapping. Parsers use `json.Decoder` with `DisallowUnknownFields` off but field allowlists on (we only copy known fields), strip control characters from every string, cap evidence sizes. Adapter output is hostile input: a malicious template or tool must not be able to inject into reports (html/template escapes) or SQL (parameterised).

`engine.Registry` holds engines keyed by name; `engine.Runner` runs per target with `semaphore.NewWeighted(profile.MaxParallelEngines)`, each engine's network activity gated by the shared `Limits` so adapters plus native engines together stay under the cap (adapters get their cap passed as flags since we cannot meter their sockets: `nmap --max-rate N`, `nuclei -rl N -c M`).

## 5. Module designs

### 5.1 Target detection (`internal/target`)

Order, first match wins; `--type` overrides. (1) `http://`/`https://` → url. (2) `aws://`, `azure://`, `gcp://` → cloud. (3) path exists on disk → path (dir or file; `.git` presence sets label `repo`). (4) parses as IP → host; as CIDR → cidr. (5) matches image ref grammar (`[registry/]name[:tag][@sha256:...]` with a `/`, `:` tag or `@`) **and** hostname part does not resolve → image. (6) resolvable hostname → host. (7) else error `E_TARGET_AMBIGUOUS` listing candidates; wizard asks, non-interactive exits 2. `Public` is set by resolving all A/AAAA records and checking none are RFC1918/loopback/link-local/ULA; mixed results count as public.

### 5.2 Wizard UX (`internal/wizard`)

`scnr` with no args or `scnr scan` with no target launches it (only when stdin and stdout are TTYs; otherwise prints usage and exits 2). Steps: (1) "What do you want to check?" free text → detection result shown back ("Looks like a website: https://example.com. Correct?"). (2) Profile select with time estimates from `Plan`. (3) Scope and authorization: for private targets, a single confirm "I am authorised to scan this"; for public targets, the ownership/consent flow in Section 9 with the plan shown first (hosts, ports, request count, rate). (4) Online disclosure: "Package names and versions will be sent to osv.dev to look up vulnerabilities. OK?" (shown only if SCA engine applies). (5) Output dir and formats (defaults: `./scnr-out/<scan-id>/`, html+json). Then live progress (one line per engine, counts), then summary: score, grade, top 5 fixes, path to HTML report. Every wizard answer maps to a flag printed at the end ("Next time: `scnr scan https://example.com --profile standard --out ...`"), so users graduate to the CLI.

Profiles: `quick` (top 100 ports, passive web only, secrets + SCA, ~2 min), `standard` (top 1000 ports, templates safe, TLS checks, all native engines, adapters if installed, ~10 min), `deep` (all 65535 ports via nmap adapter if present else native top 1000 + extra, nuclei full safe set, semgrep/trivy/grype/prowler adapters, no time cap). Profiles are a struct in `engine/profile.go`, overridable by `scnr.yaml`.

### 5.3 netscan (native)

TCP connect scan (no raw sockets, no root): per-host worker pool bounded by `Limits.PerHostConcurrency` (default 64 private / 16 public) and global `rate.Limiter` on connection attempts. Port list embedded (`ports_top1000.txt`, compiled from the IANA service-name registry, not copied from nmap-services). Per open port: read banner with 2 s deadline (passive), if port in {443, 8443, or banner looks like TLS} do TLS handshakes: one with defaults (cert chain, expiry, hostname match, self-signed), then one each with `MaxVersion` pinned to TLS1.0 and TLS1.1 to detect legacy offers (handshake only, no data). HTTP ports: single `GET /` through `safety.HTTP` for a `Server` header and title (used as service label; header checks live in webscan). Rules: `net.open-port` (info), `net.exposed-admin-port` (telnet/rdp/vnc/winrm, high if public), `net.exposed-db-port` (redis/mongo/es/memcached/mysql/pg/mssql, high public / medium private), `net.tls.expired`, `net.tls.self-signed`, `net.tls.hostname-mismatch`, `net.tls.legacy-version` (medium), `net.tls.expiring-soon` (<14 d, low). Host caps: private ≤ /16, public ≤ /24, raise with `--max-hosts N` (still logged in audit). Hosts that time out on all probes are marked `unreachable` once, not retried.

### 5.4 webscan (native templates) + nuclei adapter

Passive checks on the response of `GET /` and a small fixed path set (`/robots.txt`, `/.git/HEAD`, `/.env`, `/server-status`, `/.well-known/security.txt`): missing security headers (CSP, HSTS on https, X-Content-Type-Options, X-Frame-Options/frame-ancestors), cookies without Secure/HttpOnly/SameSite, server/framework version disclosure, directory listing, exposed `.git`/`.env` (critical; evidence redacted), CORS `*` with credentials, mixed content links. Template engine: YAML, strict decode (`yaml.Decoder.KnownFields(true)`), 1 MiB cap, schema:

```yaml
id: exposed-env-file
info: { title, severity, cwe, what, why, fix, references, tags }
safety: safe            # "intrusive" templates load only with --allow-intrusive; still non-destructive
http:
  - method: GET          # GET | HEAD | POST(≤4 KiB body, intrusive only)
    path: ["/.env"]
    matchers-condition: and
    matchers:
      - { type: status, status: [200] }
      - { type: regex, regex: ['(?m)^[A-Z_]+=.+$'] }   # RE2 only; no DSL
```

Matchers: status, word, regex, header, size. Extractors: regex, header. No expression language (avoids an evaluator dependency and a code-execution surface). Template IDs are validated `^[a-z0-9-]{3,64}$`. User templates dir (`--templates`) merged with embedded ones; `scnr templates validate` lints. DAST active checks (Phase 4): crawler (same-origin, depth 3, 200 URLs cap, `x/net/html`), reflected-canary check (unique inert token in each query param; finding if reflected unescaped), open-redirect check (param values set to `https://scnr-canary.invalid`; finding if `Location` points there — never followed). Nothing submits forms that mutate server state without `--allow-intrusive` plus consent.

Nuclei adapter args: `-u <target> -jsonl -o <scratch>/nuclei.jsonl -silent -nc -duc -ni -type http -disable-redirects -response-size-save 65536 -rl <N> -c <M> -timeout 10 -et dos,fuzz,intrusive,bruteforce,dast -severity info,low,medium,high,critical [-H "Host: <name>" -sni <name>] [-t <tools.nuclei_templates>]` (`-dast` excluded because fuzzing is not safe-check-only; `-ni` disables interactsh so nothing phones an OOB server; `-type http` and `-disable-redirects` because nuclei bypasses the safety dialer). `<target>` is the gate-pinned address when the hostname resolved to exactly one, with the name carried in Host/SNI; a public hostname that cannot be pinned that way skips the engine (SAFETY.md item 5). Parser maps `template-id` → `nuclei:<id>`, `matched-at` → Location, `info.classification` → CVE/CWE/CVSS, `curl-command` dropped, request/response trimmed to 4 KiB and redacted; JSONL lines over 1 MiB are dropped and counted, later lines still parsed.

### 5.5 sast: codecheck (native, Phase 3) + semgrep adapter

Native `codecheck` is explicitly pattern-grade: ~30 rules, each regex scoped to file extensions, with `what/why/fix` text. Examples: `code.tls-verify-disabled` (`verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`), `code.eval-dynamic`, `code.sql-concat` (string concatenation adjacent to `SELECT|INSERT|UPDATE|DELETE`), `code.debug-true-config`, `code.weak-hash` (md5/sha1 for passwords by context words), `code.cors-wildcard`. Confidence is `Tentative` for all of these; the report says "pattern match, verify in context". File walker shared with `secrets` (same `fs.WalkDir`, same ignore rules: `.gitignore` honoured, `node_modules`, `vendor`, `.git`, binaries by sniffing first 512 bytes, files > 5 MiB skipped and counted). Semgrep adapter: `semgrep scan --config p/default --json --output <scratch>/semgrep.json --metrics=off --quiet <path>`; parse `results[]` → `semgrep:<check_id>`, `extra.severity` → Severity, `extra.metadata.cwe` → CWE, line snippet 4 KiB redacted.

### 5.6 sca / image / iac / secrets / sbom + trivy/grype adapters

**secrets** (Phase 1): ~40 own-authored regex rules (AWS access key, GCP service-account JSON, GitHub/GitLab/Slack/Stripe/Twilio tokens, private key blocks, JWTs, generic `password=`/`api_key=` with high-entropy value) plus Shannon entropy ≥ 4.0 on quoted strings ≥ 20 chars for `generic.high-entropy` (Tentative). Redaction before Evidence construction: length-aware mask (never more than a quarter of the value and at most 6 chars revealed; values under 16 chars reveal at most 2, under 8 nothing), store HMAC-SHA256 of raw keyed with the per-install secret (`~/.scnr/secret`) so fingerprints are stable across re-scans on one install but cannot be brute-forced offline from a report. Severity: provider-specific keys critical, generic high, entropy-only medium. Also scans git history? No (Phase 5 candidate); working tree only, stated in report.

**sca** (Phase 1 parsers: `go.mod`, `package-lock.json` v2/v3, `requirements.txt` pinned `==`; Phase 3 adds `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `Gemfile.lock`, `Cargo.lock`, `composer.lock`, `pom.xml` direct deps, `go.sum` ignored). Each parser yields `Package{Ecosystem, Name, Version, Direct bool, File, Line}`. OSV lookup: `POST https://api.osv.dev/v1/querybatch` in batches of 1000 with `{package:{name,ecosystem},version}`, then `GET /v1/vulns/<id>` for details (cached in `vuln_cache` table 7 days); concurrency 4, retry 3 with backoff on 429/5xx. Finding per (vuln, package): `sca.osv.<id>@<purl>`, severity from CVSS v3 in OSV (`severity[]`) else OSV `database_specific.severity` else Medium; `HowToFix` = "Upgrade `<pkg>` to `<first fixed version>`" from `affected[].ranges[].events[].fixed`. `--offline` with no local OSV bundle → engine reports `skipped: offline`, scan marked Partial.

**image** (Phase 3): `go-containerregistry` pulls manifest + layers (auth via docker config), streams each layer tar once, collects `/lib/apk/db/installed` (apk), `/var/lib/dpkg/status` (dpkg), and lockfiles → reuse `sca` parsers and OSV (ecosystems `Alpine`, `Debian`, `Ubuntu` with distro version from `/etc/os-release`). rpm-based images: native engine emits one info finding "RPM database found; install trivy or grype for OS package results" and the adapter covers it. Layer size cap 2 GiB, whole image 8 GiB, else skip with finding `image.too-large`.

**iac** (Phase 3): Dockerfile (own line parser: `USER` missing → runs as root, `ADD` from URL, `latest` tag, secrets in `ENV`/`ARG`), Kubernetes YAML (`privileged: true`, `hostNetwork`, no resource limits, `runAsNonRoot` absent, secrets in env literals), Terraform via `hashicorp/hcl/v2` (~20 rules: S3 public ACL / no block-public-access, SG `0.0.0.0/0` on 22/3389/all, RDS `publicly_accessible`, unencrypted EBS/RDS/S3, IAM `*` actions, CloudTrail disabled). Rules are Go code, one file per provider, each registering a `Rule` and a check func over the parsed structure.

**sbom** (Phase 3): `scnr sbom <path|image> --format cyclonedx-json` using `cyclonedx-go`, components from the same `Package` list with PURLs via `packageurl-go`.

**trivy** adapter: `trivy <fs|image|config> --format json --output <scratch>/trivy.json --scanners vuln,misconfig,secret --quiet --timeout 15m <target>`; parse `Results[].Vulnerabilities[]` → `sca.osv.<VulnerabilityID>@<purl>` (shared scheme → dedupes with native and grype), `Misconfigurations[]` → `trivy:<ID>`, `Secrets[]` → `secret:<RuleID>` with trivy's `Match` redacted again by our redactor. **grype** adapter: `grype <target> -o json --file <scratch>/grype.json -q`; parse `matches[]` similarly. Adapter `Detect` reads `--version`, enforces `MinVersion`, records version in `Scan.Engines`.

### 5.7 cloud (Phase 4): native AWS + prowler adapter

Native AWS uses `aws-sdk-go-v2` service modules only for: sts, iam, s3, ec2, rds, cloudtrail, kms (binary impact measured; budget +12 MiB). Read-only API calls only (`Get*`, `List*`, `Describe*`); IAM policy for the scanner documented as `SecurityAudit` managed policy. ~25 checks: root MFA, root access keys, IAM users without MFA, password policy, access keys > 90 d, S3 public/no public-access-block/no encryption/no logging, SG world-open 22/3389/all, default VPC SG allows all, EBS unencrypted, RDS public/unencrypted/no backups, CloudTrail missing/not multi-region/not validated, KMS rotation off. Account ID becomes the asset key `aws:<account-id>`; resource ARN is Location. Azure/GCP: prowler adapter only. Prowler adapter: `prowler <aws|azure|gcp> -M json-ocsf -o <scratch> -z -q [--profile p]`; parse OCSF `finding_info.uid` → `prowler:<check-id>`, `severity_id`, `resources[0].uid` → Location, `remediation.desc` → HowToFix. Cloud targets never go through network scope checks (they are API calls to the provider), but do require the authorization acknowledgment and the account ID is confirmed via `sts:GetCallerIdentity` before any check runs ("You are about to scan AWS account 1234... as arn:...; continue?").

### 5.8 vulnmgmt (store-backed)

Asset inventory is derived: every target and discovered host becomes an `assets` row (upsert by `Key`). History: `scan list`, `scan show <id>`. Diff: `scnr findings diff <scanA> <scanB>` = fingerprints new / fixed / unchanged; `scnr scan ... --diff latest` prints the delta against the previous scan with the same target set hash. Trend: `scnr assets show <key> --trend` prints posture score per scan (text sparkline). Status lifecycle: on each scan for a target set, fingerprints seen → `open` (LastSeen updated); fingerprints from the prior scan of the same target-set hash not seen now → `fixed`, but only when the finding's engine completed (`ok`) in the new scan — a finding whose engine was skipped, failed, timed out or deselected with `--engines`/`--skip-engines` stays `open`; `accepted`/`suppressed` persist until expiry, then revert to `open` with an audit entry. Accept-risk: `scnr accept <fingerprint|rule-id> --reason "..." --expires 90d [--asset key]`, reason mandatory, expiry mandatory (max 365 d). Baseline: `scnr baseline create --from <scan-id> > baseline.yaml` writes fingerprints + rule IDs; `--baseline baseline.yaml` on scan marks matches `suppressed` (reported in a separate section, never silently dropped). Policy-as-code (`policy.yaml`, strict YAML): `fail_on: high`, `fail_on_kev: true`, `max_findings: {critical: 0, high: 5}`, `min_score: 70`, `required_engines: [sca, secrets]`, `fail_on_partial: true` (default false; fails when any engine was skipped, failed or timed out, naming them); `scnr scan --policy policy.yaml` and `scnr policy check <scan-id>` evaluate it. Exit codes: 0 pass, 1 policy failed, 2 usage/target error, 3 safety gate refused, 4 all engines failed, 5 partial (some engine failed) when `--strict`, else 0 with Partial flag in output. Scheduler (Phase 4): `schedules` table with cron expressions (`robfig/cron/v3`), `scnr daemon run` executes due scans non-interactively (requires ownership verification or private range — no interactive consent path exists in daemon mode), writes reports to `--out`, optional webhook POST of the JSON summary (`--notify-url`, body is our schema, no third-party SDKs).

### 5.9 reporting (`internal/report`)

`Reporter interface { Write(ctx, store.FindingIterator, Scan, io.Writer) error }`; the iterator pages 500 findings at a time from SQLite. **HTML**: single self-contained file, `html/template` + embedded CSS, no JS dependencies, no external assets; sections: score card (0-100, grade, delta vs previous), "Fix these first" (top 10 by Risk with HowToFix), findings grouped by asset then risk, each with What/Why/Fix/Evidence (redacted, `<pre>` escaped), suppressed/accepted appendix, coverage appendix (engines run, versions, skipped and why), scan metadata (consent method, scope hash). **JSON**: `{schema_version:"1", scan, assets[], findings[]}` matching Section 3 structs; this is the stable contract. **SARIF 2.1.0**: own structs (no dependency), one `run` per engine with `tool.driver.rules[]` from `Rule`, `results[].locations` for file/URL, `partialFingerprints.scnr/v1`; validated in tests against the published schema file in `testdata`. **Markdown**: summary + table, for PR comments. **CSV**: flat findings for spreadsheet triage. Plain-English text is authored in the `Rule` (embedded YAML `rules/*.yaml` per engine) so engines never hardcode prose; adapter rules without our text fall back to the tool's description and are marked "description from <tool>".

### 5.10 doctor (`internal/doctor`)

Checks: config file valid, DB opens and migrations current, vuln DB age (KEV/EPSS, warn > 7 d), each adapter `Detect` (path, version vs MinVersion), raw-socket capability (informational: "nmap SYN scan unavailable without root; connect scan will be used"), outbound reachability to osv.dev (only if `--online`), disk space in store dir. Output is a table with `OK / MISSING / OLD` and, for missing tools, the install guidance string per platform (brew/apt/binary release URL) from a static table in `doctor/install.go`. `--install-guide` prints copy-pasteable commands but never runs them.

## 6. CLI command tree

```
scnr                                    # wizard (TTY only)
scnr scan [TARGET...] [flags]           # --profile quick|standard|deep  --type url|host|cidr|path|image|cloud
                                        # --engines a,b  --skip-engines a  --out DIR  --format html,json,sarif,md,csv
                                        # --scope scnr.yaml  --non-interactive  --online/--offline  --max-hosts N
                                        # --ports top100|top1000|all|LIST  --rate N  --concurrency N
                                        # --policy policy.yaml  --baseline baseline.yaml  --diff latest|SCAN-ID
                                        # --templates DIR  --allow-intrusive  --strict  --ack-authorized
scnr doctor [--install-guide] [--online]
scnr report SCAN-ID|latest [--format ...] [--out DIR]
scnr scan list | show SCAN-ID
scnr findings list [--scan ID] [--asset KEY] [--severity high] [--status open] [--limit 50 --offset 0]
scnr findings show FINGERPRINT
scnr findings diff SCAN-A SCAN-B
scnr findings export [--format json|csv|sarif]
scnr assets list | show KEY [--trend]
scnr accept FINGERPRINT|RULE-ID --reason TEXT --expires 90d [--asset KEY]
scnr accept list | revoke ID
scnr baseline create --from SCAN-ID
scnr scope init | check TARGET          # writes scnr.yaml skeleton / explains gate decision
scnr verify DOMAIN [--print-token] [--check]
scnr db update [--offline-bundle PATH] | status
scnr sbom TARGET [--format cyclonedx-json]
scnr templates list | validate PATH
scnr policy check SCAN-ID --policy policy.yaml
scnr schedule add --cron "0 2 * * 1" --name weekly -- scan 10.0.0.0/24 --profile standard
scnr schedule list | remove NAME
scnr daemon run
scnr config init | show
scnr version
```

Examples: `scnr scan https://app.example.com` (interactive consent, standard profile); `scnr scan . --format sarif --out out/ --policy .scnr/policy.yaml --non-interactive` (CI, exit 1 on policy fail); `scnr scan 10.0.0.0/24 --profile quick --ack-authorized --non-interactive` (private range, ack via flag, allowed); `scnr scan 203.0.113.10 --non-interactive` → exit 3 with "public target requires ownership verification: run `scnr verify example.com` or scan interactively".

## 7. Risk scoring

Per finding, `Risk` (0-100):

```
base = CVSS.Score*10 if CVSS present else {Critical:95, High:80, Medium:55, Low:25, Info:5}[Severity]
E (exploitability) = 1.00 if KEV or EPSS >= 0.10
                   = 0.85 if 0.01 <= EPSS < 0.10
                   = 0.70 if EPSS < 0.01
                   = 0.80 if no CVE / EPSS unknown
X (exposure)       = 1.00 if asset is public (internet-facing host/URL, public cloud resource)
                   = 0.85 if private network host
                   = 0.80 if local code/image/IaC (deployment context unknown)
C (confidence)     = 1.00 Confirmed | 0.90 Firm | 0.75 Tentative
Risk = clamp(round(base * E * X * C), 0, 100);  if KEV: Risk = max(Risk, 90)
Bucket: Critical >= 90, High 70-89, Medium 40-69, Low 10-39, Info < 10   (bucket drives ordering and policy; original Severity is kept and shown)
```

Posture score (0-100) per scan over open, non-accepted, non-suppressed findings, by bucket with diminishing deductions:

```
score = 100
  - critical: 25 for the first, 10 each after, cap 60
  - high:     10 for the first,  4 each after, cap 30
  - medium:    3 for the first,  1 each after, cap 15
  - low:       1 each, cap 5
  - info:      0
score = max(score, 0)
Grade: A 90-100, B 80-89, C 70-79, D 60-69, F < 60.  Any open KEV finding caps the grade at D.
Partial scans display the score with "(partial)" and the grade is not shown as a letter in policy output.
```

EPSS and KEV come from `vulndb` tables (Section 8); with no local DB, E = 0.80 and the report notes "exploit data unavailable; run `scnr db update`". All constants live in `risk/weights.go` and are printed by `scnr config show --risk` so the score is explainable.

## 8. Storage schema (SQLite, `internal/store`)

`~/.scnr/scnr.db` (override `SCNR_HOME`), `PRAGMA journal_mode=WAL; foreign_keys=ON; busy_timeout=5000`. One writer goroutine per process (`store.Writer` with a buffered channel) so engines never contend; the daemon takes an advisory lock file to prevent two processes writing. Migrations: embedded `migrations/NNNN_name.up.sql` / `.down.sql`, applied in a transaction, recorded in `schema_migrations(version, applied_at)`; `scnr db migrate --down 1` for rollback. Phase 1 schema:

```sql
CREATE TABLE assets (id TEXT PRIMARY KEY, key TEXT NOT NULL UNIQUE, type TEXT NOT NULL, name TEXT,
  labels TEXT NOT NULL DEFAULT '{}', public INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);

CREATE TABLE scans (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, profile TEXT NOT NULL,
  target_set_hash TEXT NOT NULL, scope_hash TEXT NOT NULL, consent_method TEXT NOT NULL, consent_by TEXT NOT NULL,
  partial INTEGER NOT NULL DEFAULT 0, score INTEGER, grade TEXT, exit_code INTEGER, meta TEXT NOT NULL DEFAULT '{}');
CREATE INDEX scans_target_set ON scans(target_set_hash, started_at);

CREATE TABLE scan_targets (scan_id TEXT NOT NULL REFERENCES scans(id), raw TEXT NOT NULL, type TEXT NOT NULL,
  value TEXT NOT NULL, public INTEGER NOT NULL);
CREATE TABLE scan_engines (scan_id TEXT NOT NULL REFERENCES scans(id), name TEXT NOT NULL, version TEXT,
  status TEXT NOT NULL, duration_ms INTEGER, error TEXT, PRIMARY KEY (scan_id, name));

CREATE TABLE findings (                      -- canonical, deduped by fingerprint
  fingerprint TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets(id), rule_id TEXT NOT NULL,
  engine TEXT NOT NULL, title TEXT NOT NULL, severity INTEGER NOT NULL, confidence INTEGER NOT NULL,
  what TEXT, why TEXT, fix TEXT, location TEXT, cves TEXT NOT NULL DEFAULT '[]', cwe TEXT,
  cvss_vector TEXT, cvss_score REAL, epss REAL, kev INTEGER NOT NULL DEFAULT 0, risk INTEGER NOT NULL,
  refs TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'open',
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
CREATE INDEX findings_asset_status ON findings(asset_id, status, risk DESC);
CREATE INDEX findings_rule ON findings(rule_id);

CREATE TABLE finding_occurrences (scan_id TEXT NOT NULL REFERENCES scans(id),
  fingerprint TEXT NOT NULL REFERENCES findings(fingerprint), seen_at TEXT NOT NULL, PRIMARY KEY (scan_id, fingerprint));
CREATE INDEX occ_fp ON finding_occurrences(fingerprint);

CREATE TABLE evidence (id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL REFERENCES findings(fingerprint),
  scan_id TEXT NOT NULL, kind TEXT NOT NULL, location TEXT, redacted TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX evidence_fp ON evidence(fingerprint);

CREATE TABLE suppressions (id TEXT PRIMARY KEY, fingerprint TEXT, rule_id TEXT, asset_key TEXT, reason TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT,
  CHECK (fingerprint IS NOT NULL OR rule_id IS NOT NULL));
CREATE INDEX supp_fp ON suppressions(fingerprint); CREATE INDEX supp_rule ON suppressions(rule_id, asset_key);

CREATE TABLE verifications (host TEXT PRIMARY KEY, method TEXT NOT NULL, verified_at TEXT NOT NULL, expires_at TEXT NOT NULL);

CREATE TABLE audit_log (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  scan_id TEXT, detail TEXT NOT NULL);      -- append-only: no UPDATE/DELETE statements exist in store for this table
CREATE INDEX audit_ts ON audit_log(ts);

CREATE TABLE kev (cve TEXT PRIMARY KEY, added TEXT NOT NULL, due TEXT, product TEXT);
CREATE TABLE epss (cve TEXT PRIMARY KEY, score REAL NOT NULL, percentile REAL NOT NULL);
CREATE TABLE vuln_cache (id TEXT PRIMARY KEY, body TEXT NOT NULL, fetched_at TEXT NOT NULL);
CREATE TABLE vulndb_meta (source TEXT PRIMARY KEY, updated_at TEXT NOT NULL, version TEXT);
```

Phase 4 adds `schedules(name PK, cron, args_json, last_run, next_run, enabled)` and `osv_affected(id, ecosystem, name, versions_json)` for offline matching. All queries use `?` placeholders via `database/sql`; there is no string-built SQL. JSON columns (`labels`, `cves`, `refs`, `meta`, `detail`) are `encoding/json`-marshalled; no `json_extract` filtering on them in hot paths. List commands and reporters always page (`LIMIT ? OFFSET ?`, default 50 for CLI, 500 for reporters).

Secret evidence: `redacted` and `hash` only. `--show-secrets` does not exist.

## 9. Safety and authorization design (`internal/safety`)

This section is a hard requirement; every network-touching code path goes through it and tests must be exhaustive.

**Authorization acknowledgment.** Every scan requires `authorization.acknowledged: true` in `scnr.yaml` (written by `scnr scope init` after an interactive confirmation that records OS user and time) or `--ack-authorized` on the command line. The text acknowledged: "I am authorised to scan these targets and accept responsibility for doing so." Missing → exit 3.

**Scope file.** `scnr.yaml`:

```yaml
authorization: { acknowledged: true, by: gerald, at: 2026-10-10T09:00:00Z }
scope:
  allow: [10.0.0.0/8, 192.168.1.0/24, app.example.com, "https://staging.example.com"]
  deny:  [10.0.0.1, "*.prod.example.com"]
limits: { rate_per_sec: 200, per_host_concurrency: 32, http_rps_per_host: 10, max_hosts: 4096 }
```

Deny always wins. `allow` entries: CIDR, IP, hostname, wildcard hostname (`*.x`), URL prefix. Hostnames are matched both by name and by their resolved IPs.

**Gate decision per target (`safety.Gate.Decide`)**, in order:
1. Cloud target → requires acknowledgment + `sts`-style identity confirmation; skip network rules.
2. Path target → acknowledgment only.
3. Resolve all addresses. Any address in `deny` → **refuse** (`E_SCOPE_DENIED`).
4. All addresses private (RFC1918, 127/8, ::1, 169.254/16, fe80::/10, fc00::/7, 100.64/10) → **allow** (consent method `private-range`), subject to default private limits. Hosts in a CIDR are checked individually at dial time too (step 7).
5. Public addresses: must be in `allow` **and** one of: (a) interactive TTY consent, where the plan (hosts, ports, requests, rate, duration) is displayed and the user types the target hostname/IP back; or (b) a non-expired `verifications` row for the hostname. Non-interactive without (b) → **refuse** with instructions (`E_OWNERSHIP_REQUIRED`).
6. CIDR size caps: private ≤ /16 (65 536), public ≤ /24, else refuse unless `--max-hosts` explicitly ≥ host count (audited).
7. Dial-time enforcement: `safety.NewHTTPClient` and `netscan`'s dialer both use a `DialContext` that resolves, checks every resulting IP against scope (deny, allow, public/private rules) *at connect time*, and refuses otherwise. This defeats DNS rebinding and redirects into internal ranges. `CheckRedirect` allows ≤ 5 hops, re-validates each hop, and turns an out-of-scope redirect into an `info` finding `web.redirect-out-of-scope` instead of following it.

**Ownership verification (`scnr verify`).** Token = base32(HMAC-SHA256(local secret in `~/.scnr/secret` with 0600, hostname))[:32]; `scnr verify example.com --print-token` prints `scnr-verify=<token>`; the user publishes it as DNS TXT at `_scnr-verify.example.com` or at `https://example.com/.well-known/scnr-verify.txt`; `scnr verify example.com --check` confirms via a resolver query (TXT) or a single GET with the safe client (file), stores `verifications` with 30-day expiry. Wildcard: a TXT at `_scnr-verify.example.com` also verifies subdomains (`publicsuffix` prevents verifying `co.uk`). Bare public IPs: verifiable only via the well-known file over HTTP(S) on that IP; otherwise interactive consent only.

**Rate and concurrency caps.** Defaults: private 500 conn/s, 64 per-host concurrency, HTTP 20 rps/host; public 100 conn/s, 16, 10 rps/host; global engine parallelism 4. User can lower freely; raising above 2x default requires `--i-understand-rate-limits` and is audited. Adapters receive equivalent flags (`nmap --max-rate --max-parallelism -T3`, `nuclei -rl -c`), and the runner refuses to launch an adapter whose flags it cannot bound.

**No-harm rules.** No exploitation modules exist in the codebase; the `Rule.Safety` type has exactly two values and the only intrusive behaviours are non-destructive (POST ≤ 4 KiB, form canaries). Nuclei runs with `-et dos,fuzz,intrusive,bruteforce,dast`; nmap runs without `--script` (no NSE) and never with `-sU`/`-O` unless `deep` and root (still read-only); semgrep/trivy/grype/prowler are read-only by nature. A repo-level `SAFETY.md` lists these invariants and a CI test (`safety_invariants_test.go`) greps the adapter arg builders for forbidden flags (`--script`, `-dast`, `-fuzz`, `brute`).

**Hostile inputs.** Templates: 1 MiB cap, strict YAML, RE2 regexes only (linear time), path allowlist `^/[A-Za-z0-9._~/-]*$`. Lockfiles and IaC: size caps, depth caps, no symlink following outside the root. Adapter output: streamed JSON/XML decoders with 256 MiB cap, field allowlists, control chars stripped, `html/template` escaping for HTML; `encoding/xml` for nmap with `Strict=true` and entity expansion disabled by default in Go. Env for child processes is minimal; arguments are `[]string` always; user-supplied values (targets, paths) are passed as separate argv entries and validated against the detection grammar first so `-` prefixed values cannot become flags (`--` separators used where tools support them).

**Secrets.** Redaction happens in the engine before `Evidence` exists; the redactor is also applied to every adapter string field and to log lines (`logx` has a redacting handler for known key patterns). Cloud credentials are never read by scnr itself for AWS native (SDK default chain) and only passed through env to prowler.

**Telemetry.** None. Outbound connections are only: targets in scope, `api.osv.dev` (when online), `www.cisa.gov` KEV JSON and `epss.cyentia.com` CSV (only during `db update`), and `--notify-url` if the user sets one. `scnr doctor --online` lists them.

**Audit.** Every `scan`, `accept`, `verify`, `db update`, `schedule` change, limit override and gate refusal writes an `audit_log` row (actor = OS user, detail JSON includes targets, scope hash, consent method, engine versions, exit code). `--audit-file path.jsonl` mirrors rows to a file.

## 10. Dependencies

| Module | Phase | Why it is needed and why stdlib cannot do it |
|---|---|---|
| `github.com/spf13/cobra` | 1 | Command tree, flags, completions; de facto standard, no reason to hand-roll |
| `github.com/charmbracelet/huh` (pulls `bubbletea`, `lipgloss`) | 1 | Wizard forms with validation and select widgets; `survey` is unmaintained |
| `modernc.org/sqlite` | 1 | Pure-Go SQLite, keeps `CGO_ENABLED=0` static binaries |
| `gopkg.in/yaml.v3` | 1 | Config, templates, rules, baseline, policy; strict `KnownFields` |
| `golang.org/x/sync` | 1 | `semaphore.Weighted`, `errgroup` for bounded concurrency |
| `golang.org/x/time/rate` | 1 | Token-bucket rate limiting of connections and HTTP |
| `golang.org/x/net` | 1 | `publicsuffix` for verification; `html` tokenizer for the Phase 4 crawler |
| `github.com/google/go-cmp` | 1 (test) | Readable struct diffs in tests |
| `github.com/package-url/packageurl-go` | 3 | PURL construction for SCA dedupe and SBOM |
| `github.com/CycloneDX/cyclonedx-go` | 3 | CycloneDX schema is large and versioned; not worth re-typing |
| `github.com/google/go-containerregistry` | 3 | Registry auth, manifests, layer streaming |
| `github.com/hashicorp/hcl/v2` | 3 | Terraform HCL parsing |
| `github.com/robfig/cron/v3` | 4 | Cron expression parsing for schedules |
| `github.com/aws/aws-sdk-go-v2` (+ `config`, `sts`, `iam`, `s3`, `ec2`, `rds`, `cloudtrail`, `kms` modules only) | 4 | Native AWS checks; modular to bound binary size |
| `github.com/Masterminds/semver/v3` | 4 | Offline OSV range matching for semver ecosystems |

Not added: a JSON-path or expression library (templates use RE2 only), a SARIF library (own structs), a UUID library (`crypto/rand` hex), testify (stdlib + go-cmp), logrus/zap (`log/slog`). All versions pinned in `go.mod`/`go.sum`; `govulncheck` runs in CI. Build tooling (not deps): `golangci-lint`, `goreleaser`, `govulncheck`.

## 11. Phased delivery

### Phase 1 — MVP vertical slice

Scope: `cmd/scnr`, `cli` (scan, doctor, report, scan list/show, findings list/show, scope init/check, verify, db update, config, version), `wizard`, `config`, `domain`, `target`, `safety` (full gate, HTTP client, redactor, verification), `engine` (interfaces, registry, runner, profiles), `netscan`, `secrets`, `sca` (go.mod, package-lock.json, requirements.txt; OSV online), `risk`, `vulndb` (KEV + EPSS), `store` (schema above), `report` (html, json), `audit`, `doctor`, `logx`. Adapters: interface and `Base` only (the nmap adapter lands in Phase 2 so Phase 1 is pure native and testable without tools).

Acceptance criteria:
1. `scnr` on a TTY launches the wizard; `scnr` with stdin not a TTY prints usage and exits 2.
2. `scnr scan 127.0.0.1 --ack-authorized --non-interactive --ports 8080,8443` against test listeners (one plain HTTP, one TLS with a self-signed cert) produces findings `net.open-port` x2, `net.tls.self-signed`, and writes `report.html` + `report.json` under `--out`.
3. `scnr scan ./testdata/repo --ack-authorized --non-interactive` produces one `secret.aws-access-key` finding whose `redacted` evidence is `AKIA...XX` form, a `hash` present, and the raw key appears nowhere in the DB file or reports (asserted by grep over both).
4. Same scan with a `package-lock.json` containing a known-vulnerable package (fixture + OSV response recorded via `httptest`) yields `sca.osv.<id>@<purl>` with HowToFix naming the fixed version; with `--offline` the engine is `skipped: offline`, `Partial=true`, exit 0 (exit 5 with `--strict`).
5. Risk and posture: unit tests pin the formulas in Section 7 (including KEV floor and grade cap); report shows score, grade, top-fixes list.
6. Safety gate table tests: private target allowed; public target non-interactive without verification → exit 3; public target in deny → exit 3 even if verified; CIDR /15 private → refused without `--max-hosts`; HTTP redirect from in-scope to `169.254.169.254` → not followed, `web.redirect-out-of-scope` emitted; DNS answer changing between resolve and dial → dial refused.
7. `scnr verify example.test --print-token` is deterministic per local secret; `--check` against a test resolver/HTTP server stores a 30-day `verifications` row.
8. `scnr db update` loads KEV and EPSS fixtures into tables; `scnr doctor` reports DB age, missing adapters with install guidance, and exits 0.
9. Every scan writes exactly one `audit_log` row with consent method and exit code; gate refusals write one too.
10. Memory: scanning a fixture producing 50 000 synthetic findings (fake engine in tests) keeps RSS under 300 MiB (findings are streamed to the store; asserted with `runtime.MemStats` in a test).
11. `go vet`, `golangci-lint`, `govulncheck` clean; `CGO_ENABLED=0 go build` produces a static binary on linux/amd64, linux/arm64, darwin/arm64.

Test strategy: table-driven unit tests per package; `httptest` servers for HTTP/TLS/OSV/well-known; in-process `net.Listen` for port scanning; a fake DNS resolver injected via `net.Resolver.Dial`; fuzz targets for `target.Detect`, lockfile parsers, secret rules; golden-file tests for HTML/JSON (JSON golden is the public schema); an e2e test building the binary and running criteria 2-4 under `-tags e2e`.

### Phase 2 — Web, adapters, outputs, vuln management core

Scope: `webscan` passive + template engine + ~100 embedded templates; `nmap` and `nuclei` adapters; SARIF/Markdown/CSV reporters; `findings diff`, `--diff`, status lifecycle (fixed), `accept`, `baseline`, `policy check` and exit codes; `templates list|validate`.

Acceptance: (1) template loader rejects >1 MiB, unknown fields, non-RE2 regex, bad IDs, `safety` values other than the two allowed; (2) nmap XML and nuclei JSONL fixtures (two versions each in `testdata/adapters/<tool>/<version>/`) parse to expected findings; adapter arg builders never emit forbidden flags (invariant test); (3) SARIF output validates against the 2.1.0 JSON schema in `testdata`; (4) two consecutive scans of a fixture where one finding is removed mark it `fixed` and `diff` prints 1 fixed/0 new; (5) `accept` requires reason and expiry, expired acceptances revert to open on next scan with an audit row; (6) policy `fail_on: high` returns exit 1 when a high exists, 0 when it is accepted; (7) a nuclei run against the test server with the adapter uses `-ni` and the exclusion tags (asserted by a fake `nuclei` binary that records argv).

### Phase 3 — Supply chain breadth and IaC

Scope: remaining lockfile parsers, PURL, `sbom`, `image` engine (apk/dpkg), `iac` engine (Dockerfile, K8s, Terraform), `codecheck`, `trivy`/`grype`/`semgrep` adapters, cross-tool SCA dedupe.

Acceptance: (1) each parser has a fixture + fuzz target; malformed inputs never panic; (2) `scnr sbom` output validates against the CycloneDX 1.5 schema; (3) image fixture (small alpine tar in `testdata`) yields OS packages and OSV findings via recorded responses; rpm image yields the informational handoff finding; (4) the same CVE from native SCA, trivy fixture and grype fixture collapses to one finding with three engines listed in evidence; (5) Terraform fixtures produce the documented rules with HCL line locations; (6) `codecheck` findings all carry `Confidence=Tentative` and the "verify in context" text.

### Phase 4 — Cloud, offline DB, scheduler, DAST active, plugins

Scope: native AWS checks + `prowler` adapter; OSV offline bundle (`db update --offline-bundle`, `osv_affected` table, semver matching); `schedule`/`daemon`; crawler + canary/open-redirect checks behind `--allow-intrusive`; exec plugin protocol (`scnr-plugin-<name>` on PATH, `--manifest` prints JSON `{name, version, supports:[types], safety:"safe"}`, then `run --target <json>` streams findings as JSONL on stdout, subject to the same hostile-input handling as adapters).

Acceptance: (1) AWS checks run against a stub endpoint (`aws-sdk-go-v2` custom `EndpointResolver`) and are provably read-only (an invariant test lists every SDK operation name used and asserts it matches `^(Get|List|Describe|Head)`); (2) prowler OCSF fixture parses; (3) offline SCA yields identical findings to online for the fixture set; (4) daemon executes a due schedule once, skips while a lock is held, refuses public targets without verification; (5) crawler respects depth/URL caps and scope at every hop; canary never appears in a non-GET request unless `--allow-intrusive`; (6) a sample plugin in `examples/` runs end to end and a malicious plugin emitting 1 GiB is cut off at the cap.

### Phase 5 — Server-mode path (design only, no code in this spec)

`store` gets an interface with a Postgres driver; `cli` becomes a thin client of an HTTP API with the same JSON schema; RBAC and multi-tenant scoping are added at the API layer; the daemon becomes the server's worker. Nothing in Phases 1-4 may depend on `*sql.DB` outside `internal/store` to keep this door open.

## 12. Risks, unhandled cases, open questions

### Risks and mitigations

- **False positives destroy trust with non-expert users.** Mitigation: `Confidence` on every finding, pattern-grade engines are always Tentative with "verify" wording, "Fix these first" list uses Risk which weights confidence, and the acceptance flow makes dismissing easy.
- **Native engines look thinner than the tools they stand in for.** Mitigation: the coverage appendix in every report states exactly what ran and what would run if `nmap`/`nuclei`/`trivy` were installed, with install commands; `doctor` nags.
- **External tool output format drift.** Mitigation: `MinVersion` per adapter, fixtures per tested version, parsers tolerant of unknown fields and strict on required ones, drift surfaces as an engine error not a silent empty result.
- **OSV API rate limits or outage during CI.** Mitigation: `vuln_cache`, batching, backoff; Phase 4 offline bundle; engine failure marks Partial rather than failing the scan.
- **SQLite single-writer and large scans.** Mitigation: one writer goroutine, WAL, batched inserts in transactions of 500; measured by criterion 1.10.
- **Legal misuse despite gates.** Mitigation: acknowledgment text recorded with user and time, ownership verification for public targets in automation, audit log, `SAFETY.md`, and no exploit code to misuse.
- **Binary size growth (AWS SDK, go-containerregistry).** Mitigation: measure per phase, budget 60 MiB total; consider `scnr-cloud` split binary if exceeded (decision deferred to Phase 4).

### Unhandled (deliberately)

UDP scanning in native engine (nmap adapter only, root, deep); SYN scans; IPv6 range sweeps (single IPv6 hosts are supported, CIDRs > /120 refused); authenticated web scanning; git history secret scanning; rpm package databases natively; Windows adapter discovery beyond `LookPath`; proxies/`HTTP_PROXY` for scanning traffic (honoured only for OSV/db updates); scanning through jump hosts; concurrent `scnr` processes writing the same DB (second process gets `busy_timeout` then a clear error, daemon uses a lock file).

### Performance notes

Hot paths: port scanning (bounded by `Limits`, connect-only, 2 s timeouts, no retries), file walking (single pass shared by secrets and codecheck, skips binaries and >5 MiB), finding writes (batched transactions). Expected queries per scan: O(findings/500) inserts plus one upsert per asset; reporters: one paged query per 500 findings plus one per scan for metadata. Indexes listed in Section 8 cover every `WHERE` in `store`. Measure with `--profile-cpu file` (pprof) and the RSS test; baseline target: /24 private quick scan < 90 s on a laptop, 10k-file repo secrets+SCA < 30 s.

### Open questions (recommended default in bold)

1. Go module path / repository org? **`github.com/gerald/scnr`** until a home is chosen; only `go.mod` and imports change.
2. License? **Apache-2.0** (matches trivy/grype; permits enterprise adoption; patent grant).
3. Should SCA contact osv.dev by default, or require `--online`? **Default on, with a one-time wizard disclosure and `--offline` to disable**; otherwise the MVP has no useful SCA.
4. Non-interactive scans of bare public IPs with no DNS name and no HTTP: refuse, or allow if the IP is in `allow`? **Refuse** (`E_OWNERSHIP_REQUIRED`); the allow list alone is not proof of ownership.
5. Store location for CI (ephemeral runners)? **`SCNR_HOME` env plus `--db path`; default `./.scnr/` when `CI=true`**, so history can be cached as an artefact if desired.

## Handoff

Implement with code-writer from this spec, Phase 1 first; each phase is a separate hand-off with the acceptance criteria above as the test list.

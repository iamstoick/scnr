# scnr Phase 4 — design addendum: cloud posture, active DAST, plugins, daemon, offline DB

Status: draft for review | Date: 2026-10-10 | Supersedes: Section 11 "Phase 4" of `scnr-platform.md` where the two differ | Size: L (five independently shippable sub-phases, 4a–4e)

## 0. Why an addendum

Phases 1–3 are built and went through three security reviews. The recurring defect classes were: (1) outbound traffic bypassing `safety.Dialer`, (2) external tools making their own network calls, (3) unbounded parsing of hostile input, (4) redaction gaps, (5) lifecycle (`MarkFixed`) integrity, (6) engines that can hang. Every Phase 4 feature touches at least three of these: cloud SDKs bring their own HTTP stack and credential chain; active DAST sends attacker-shaped input and handles secrets; plugins are hostile code by construction; the daemon runs with nobody watching; offline bundles are large untrusted archives. This document tightens the Section 5.7 / 5.4 / 5.8 / 11 sketches into decisions, invariants and the tests that enforce them. It changes no Phase 1–3 behaviour except where a seam is extended (named per file in each sub-phase).

### Goal

A user who owns an AWS account, a web application, a fleet of machines or an air-gapped CI runner can (a) get a plain-English posture report for the AWS account using read-only credentials, (b) let scnr probe their web application a little harder than passive checks, with explicit, audited opt-in and no possibility of damage, (c) run scans on a schedule unattended, (d) extend scnr with third-party checks without granting those checks the network or the filesystem, and (e) do SCA with no internet access from a signed bundle. All of it inside the SAFETY.md invariants, which gain items 16–20 below.

### Shared conventions used by every sub-phase

- **Dialer rule.** Any outbound TCP connection scnr itself opens goes through `safety.Dialer.DialContext` (`internal/safety/dial.go`) or a `*http.Client` built by `safety.NewHTTPClient`, or through the new `safety.NewEndpointClient` (4b) whose transport is the same `limitedTransport` with a host allowlist in place of the target scope. A test (`TestNoRawDialers`, `internal/safety`) walks every non-test Go file under `internal/` and fails on `net.Dial`, `net.DialTimeout`, `(&net.Dialer{}).Dial`, `http.DefaultClient`, `http.Get/Post/Head`, `http.DefaultTransport` or a composite literal `http.Transport{` outside `internal/safety`, `internal/vulndb` (db update, already allowlisted) and `internal/engine/sca/osv.go` (allowlisted today; moves onto `NewEndpointClient` in 4a).
- **Hostile input rule.** Every byte from a cloud API, a crawled page, a plugin, a bundle or a tool is decoded with a field allowlist (`adapter.StreamArray`/`DecodeElement`, `internal/adapter/parse.go`), size-capped before decode, control-stripped (`safety.StripControl`) and redacted (`safety.Redactor.Clean`) before it becomes a `domain.Evidence`, a `Finding` string, a log line or an audit detail.
- **Hang rule.** Every engine honours `Options.Profile.EngineTimeout` and the Runner's `AbandonGrace` (`internal/engine/runner.go`). Child processes are started with `Setpgid` and the whole process group is killed on timeout (extension to `adapter.Base.Exec`, 4e, used by prowler in 4b as well).
- **Lifecycle rule.** `store.MarkFixed` (`internal/store/vulnmgmt.go`) only marks findings whose engine completed `ok`. New engines must report `skipped`/`failed` honestly: a cloud engine that hit its API budget, a crawler that hit its URL cap, a plugin cut off at the output cap all return `ok` only if the *coverage* was complete; otherwise they emit a `*-truncated` finding **and** return `engine.PartialError{Reason}` (new, `internal/engine/engine.go`), which the Runner records as `status = "partial: <reason>"`. `okEngines` (`internal/cli/scan.go`) excludes partial runs, so truncated coverage never marks findings fixed. Regression test: `TestMarkFixedIgnoresPartialEngines` in `internal/cli`.
- **Audit rule.** Every new user-facing action gets an `audit.Action*` constant (`internal/audit/audit.go`) and exactly one row; gate refusals keep using `ActionGateRefused`.

## 1. Sub-phase plan (ordered by risk/value; each ships alone)

| Sub-phase | Contents | Size | Why this order |
|---|---|---|---|
| **4a** | Offline OSV bundle: signed format, `db bundle build|verify`, `db update --offline-bundle`, `osv_affected`, offline SCA matching | M | Smallest new attack surface (one signed archive parser), unblocks air-gapped CI, and introduces `safety.NewEndpointClient`, which 4b–4e reuse. |
| **4b** | Cloud posture: AWS native (STS gate, read-only middleware, ~25 checks), prowler adapter (AWS; Azure/GCP behind allowlists) | L | Highest user value of the phase; risk is bounded by the read-only middleware and the endpoint client from 4a. |
| **4c** | Scheduler and daemon: `schedules` table, `schedule add|list|remove|show`, `daemon run`, lock, notify webhook | M | Multiplies whatever exists; ships before 4d so unattended mode never has intrusive checks it was not designed for. |
| **4d** | Active DAST: crawler, reflection/open-redirect/error-disclosure probes, `--allow-intrusive` mechanics, authenticated scanning via `--auth-file` | M | Attacker-shaped traffic; needs 4c's non-interactive rules settled first. |
| **4e** | Plugins: exec protocol, manifest + checksum + ed25519 signature, lock file, broker, sandbox wrappers | L | Highest uncertainty of value and the largest trust problem; last so it can adopt every seam the others hardened. |

Each sub-phase has its own acceptance list; SAFETY.md items 16–20 are added as each lands.

---

## 2. Sub-phase 4a — Offline vulnerability bundles

### 2.1 Threats

1. A tampered or substituted bundle plants or hides vulnerability data (false "no findings" is the dangerous direction).
2. Decompression/tar bombs, absolute or `..` entry names, huge JSON lines, a million tiny entries.
3. A bundle that half-loads leaves `osv_affected` in a mixed state across two snapshots.
4. Bundle building fetches from a new endpoint (OSV's GCS bucket) — another outbound host that must be declared and go through the dialer.
5. Version-range matching bugs cause silent misses (offline results differ from online for the same inputs).

### 2.2 Design

**Format.** `scnr-osv-<yyyymmdd>.tar.gz` with a fixed entry set:

```
manifest.json          {"schema_version":1,"created_at":RFC3339,"builder":"scnr <ver>","source":"osv.dev",
                        "ecosystems":[...],"files":[{"name":"affected/npm.jsonl","sha256":hex,"bytes":n,"records":n}, ...],
                        "kev":{"name":"kev.json","sha256":...} (optional), "epss":{"name":"epss.csv","sha256":...} (optional)}
manifest.sig           base64(ed25519 signature over the exact manifest.json bytes), one line
affected/<eco>.jsonl   one record per (vuln, package): {"id","aliases":[],"ecosystem","name","versions":[],"ranges":[{"type":"SEMVER|ECOSYSTEM","events":[{"introduced":..},{"fixed":..}]}],
                        "summary"(≤200),"severity":[{"type","score"}],"refs":[...≤10],"cwe":[...],"modified"}
kev.json, epss.csv     same shapes `vulndb.ParseKEV`/`ParseEPSS` already accept (`internal/vulndb/vulndb.go`)
```

No zstd (consistent with SAFETY item 13), no nested archives, entry names must match `^(manifest\.json|manifest\.sig|kev\.json|epss\.csv|affected/[a-z0-9.-]{1,32}\.jsonl)$`; anything else (symlinks, hardlinks, directories, PAX globals aside) is a hard error, not a skip — a bundle is not a scanned artefact, it is a trust decision.

**Keys.** `scnr db keygen` writes `<home>/bundle-signing.key` (0600, ed25519 seed, `crypto/ed25519`) and prints the public key. Trusted public keys live in `scnr.yaml` under `vulndb.trusted_keys: ["ed25519:<base64>"]` (new `config.VulnDB` struct). There is no project-embedded key in 4a (open question 2): the model is "an online machine you control builds and signs; air-gapped machines trust that key".

**Build.** `scnr db bundle build --out DIR --ecosystems npm,Go,PyPI,... [--sign-key PATH]` downloads `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip` per ecosystem through `safety.NewEndpointClient(hosts: osv-vulnerabilities.storage.googleapis.com)`, streams the zip (`archive/zip` over a temp file; per-entry 16 MiB cap matching `osvMaxBodyBytes`, total 2 GiB), normalises each OSV record into the affected line shape with the same field allowlist as `sca.Vuln` (`internal/engine/sca/osv.go`), writes files, computes hashes, writes manifest, signs. `doctor.ListsOutbound` gains the GCS host "(only during `db bundle build`)". Unsigned bundles can be built (`--sign-key` omitted) but cannot be loaded unless `--allow-unsigned` is passed interactively (refused with `--non-interactive`/daemon) and audited.

**Verify and load.** `scnr db update --offline-bundle PATH`:
1. Open, gunzip through a `countingReader` capped at 2 GiB decompressed (same technique as `image/archive.go`), tar-walk.
2. `manifest.json` must be the first entry and ≤ 1 MiB; `manifest.sig` second. Verify signature against `vulndb.trusted_keys` **before any other entry is read**. Failure → `E_BUNDLE_UNTRUSTED`, nothing touched, audited.
3. Every subsequent entry must be listed in the manifest with matching `bytes`; stream it through a `sha256` tee into a staging table `osv_affected_staging` (same schema, created in the load transaction), line cap 1 MiB (`nuclei.readLine` pattern, `internal/adapter/nuclei/nuclei.go`), record cap = manifest `records` (+0 tolerance), per-line field allowlist decode, `StripControl` + redactor on `summary`/`refs`.
4. After the last entry: compare each file's digest to the manifest; any mismatch → rollback. Otherwise, in the same transaction: `DELETE FROM osv_affected; INSERT ... SELECT FROM staging; DROP staging;` and `vulndb_meta(source='osv-offline', version=created_at)`. KEV/EPSS inside the bundle go through `store.ReplaceKEV/ReplaceEPSS` in the same transaction.
5. Audit `ActionDBUpdate` with `{"bundle": sha256(file), "signer": key fingerprint, "ecosystems", "records"}`.

**Schema** (migration `0003_osv_offline.up.sql` / `.down.sql`):

```sql
CREATE TABLE osv_affected (id TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
  versions_json TEXT NOT NULL DEFAULT '[]', ranges_json TEXT NOT NULL DEFAULT '[]', body TEXT NOT NULL,
  PRIMARY KEY (ecosystem, name, id));
CREATE INDEX osv_affected_pkg ON osv_affected(ecosystem, name);
```

`body` is the normalised record (so `GetVulns` offline needs no second table). Down migration drops the table; nothing else depends on it.

**Matching.** New interface in `internal/engine/sca/osv.go`:

```go
// Lookup is what the sca engine needs from a vulnerability source.
type Lookup interface {
    QueryBatch(ctx context.Context, pkgs []Package) ([][]string, error)
    GetVulns(ctx context.Context, ids []string) (map[string]*Vuln, error)
}
```

`OSVClient` already satisfies it. `OfflineClient{Store}` implements it with one `SELECT ... WHERE ecosystem=? AND name=?` per distinct package (batched 500 per `IN` using `store.chunks`), then `affects(pkg.Version, record)`: exact match against `versions[]` first; if the record has a `SEMVER` range and the ecosystem is in `semverEcosystems = {npm, Go, crates.io, Packagist, Hex, Pub}`, evaluate introduced/fixed with `golang.org/x/mod/semver` (already an indirect dependency; versions are canonicalised with a `v` prefix, invalid versions → not affected and counted as `sca.version-unparsed`, Info). `ECOSYSTEM` ranges for PyPI/RubyGems/Maven/Debian/Alpine are **not** evaluated (no PEP 440/Gem/dpkg comparator in 4a); those ecosystems rely on `versions[]`, which OSV populates for them. The coverage appendix states this.

`sca.Engine.Lookup` (`internal/engine/sca/sca.go`) chooses: `o.Online` → `OSVClient`; else if `osv_affected` has rows → `OfflineClient` and the engine run is `ok`; else `SkipError{"offline"}` as today. `Engine.OSV *OSVClient` becomes `Engine.Online Lookup; Engine.Offline Lookup`.

### 2.3 Interfaces

```go
// internal/vulndb/bundle.go
type Manifest struct { SchemaVersion int; CreatedAt time.Time; Builder, Source string; Ecosystems []string; Files []FileEntry; KEV, EPSS *FileEntry }
type FileEntry struct { Name, SHA256 string; Bytes, Records int64 }
type BundleReader struct { Keys []ed25519.PublicKey; MaxDecompressed int64; Store *store.Store; Redactor *safety.Redactor }
func (r *BundleReader) Load(ctx context.Context, path string, allowUnsigned bool) (LoadResult, error)
func Sign(seed []byte, manifest []byte) []byte
func ParseTrustedKey(s string) (ed25519.PublicKey, error)     // "ed25519:<base64>"
// internal/vulndb/build.go
type Builder struct { HTTP *http.Client /* endpoint client */; Out string; Ecosystems []string; SignSeed []byte; Log *slog.Logger }
func (b *Builder) Build(ctx context.Context) (Manifest, error)
// internal/engine/sca/offline.go
type OfflineClient struct { Store OfflineStore }   // OfflineStore is the store subset: AffectedFor(ctx, eco, name) ([]AffectedRecord, error)
```

### 2.4 Invariants and the tests that enforce them

| # | Invariant | Test |
|---|---|---|
| A1 | No bundle byte beyond `manifest.json`/`manifest.sig` is parsed before the signature verifies. | `TestBundleUntrustedStopsAtManifest`: a bundle with a bad signature and a malformed third entry fails with `E_BUNDLE_UNTRUSTED` (not a parse error) and the tar reader's byte counter is < manifest+sig size. |
| A2 | Partial loads never change `osv_affected`. | `TestBundleDigestMismatchRollsBack`: load a good bundle, then one whose last file's digest is wrong; row count and `vulndb_meta` unchanged. |
| A3 | Entry-name grammar and caps are hard errors. | Table test over: symlink entry, `../x`, `affected/../kev.json`, 65th entry, 1 MiB+1 line, decompressed > cap (gzip bomb fixture of zeros), records count off by one. |
| A4 | Offline results equal online results for the fixture set. | `TestOfflineMatchesOnline` (acceptance 3 of the platform spec): same lockfile fixtures through `httptest` OSV and through a bundle built from the same recorded records; identical fingerprint sets. |
| A5 | Builder contacts only the GCS host. | `TestBuilderEndpointAllowlist`: builder with the endpoint client refuses a redirect to another host (`RedirectOutOfScopeError`). |
| A6 | Unsigned load is impossible non-interactively. | `TestUnsignedBundleRefusedNonInteractive` in `internal/cli`: exit 3, audit row `gate_refused`. |

### 2.5 Acceptance criteria

1. `scnr db keygen` creates a 0600 key; `scnr db bundle build --ecosystems npm --sign-key K` against a recorded GCS fixture writes a bundle whose `scnr db bundle verify` passes and prints ecosystems, record counts, signer fingerprint.
2. `scnr db update --offline-bundle B` loads it; `scnr db status` shows `osv-offline` rows and age; `scnr doctor` warns when older than 30 days.
3. `scnr scan ./testdata/repo --offline --ack-authorized --non-interactive` after the load yields the same `sca.osv.*` findings as the online fixture run and the sca engine is `ok` (not skipped).
4. Invariants A1–A6 pass; `go test -fuzz=FuzzBundleRecord` runs clean for 60 s in CI on the affected-line decoder.
5. `TestNoRawDialers` is introduced in this sub-phase and passes (osv.go moves onto `NewEndpointClient`).

### 2.6 Dependencies

None new. `golang.org/x/mod/semver` is promoted from indirect to direct. Rejected: `github.com/Masterminds/semver/v3` (the platform spec's choice) — `x/mod/semver` already ships, is strict, and the ecosystems that need loose parsing (PyPI, Maven) are version-list matched anyway.

### 2.7 Out of scope (4a)

PEP 440 / Gem / dpkg / apk version comparators; project-published bundles and an embedded project key; delta bundles; bundle download over the network (users move the file); `vuln_cache` import from a bundle.

---

## 3. Sub-phase 4b — Cloud posture (AWS native, prowler adapter)

### 3.1 Threats

1. Credentials: scnr reads something it should not (`credential_process` runs arbitrary commands; IMDS is `BuiltinDeny`; SSO caches), logs or stores a credential, or stores an STS token in audit detail.
2. Scanning the wrong account (profile points elsewhere, env var leaks a client's keys) — authorisation must bind to the account ID actually in use.
3. A mutating API call slips in (a `Put*` that "fixes" a bucket, `GenerateCredentialReport` which creates an artefact, `Simulate*`).
4. API throttling → engine hangs or the account's other automation gets throttled.
5. Unbounded pagination (an account with 400k EC2 instances) and unbounded response bodies.
6. Resource data leaks into reports: tags, EC2 user data (often contains secrets), Lambda env, bucket policies with principals, SG descriptions.
7. SDK traffic bypasses `safety.Dialer`: custom endpoints, VPC endpoints resolving to private space, proxy settings, SDK telemetry/metrics (there is none in aws-sdk-go-v2, but the default retryer and IMDS region lookup do make calls).
8. Prowler: fixers, Security Hub/S3 upload of results, Slack, Shodan lookups, browser-based auth, its own network stack for everything.
9. Binary size and dependency surface of the SDK.

### 3.2 Decision: aws-sdk-go-v2 (modular), not hand-rolled SigV4

SigV4 itself is ~300 lines. The cost of hand-rolling is everything after the signature: seven services' request/response shapes (IAM/S3/EC2 are query/XML, STS is query/XML, RDS is query/XML, CloudTrail and KMS are JSON 1.1), pagination tokens that differ per service, error envelopes, retry classification, the credential sources users actually have (profiles with `role_arn`, web identity in CI, SSO). Each of those is hostile-input parsing we would own with no reference implementation, exactly defect class (3). The SDK gives typed decoders, bounded retries and a middleware stack we can use to *enforce* read-only and metering in one place. Mitigations for the SDK's own risks (credential chain breadth, endpoint control, size) are below and tested. Measured cost (4b review, darwin/arm64, `CGO_ENABLED=0`): ~44 MiB stripped (~61 MiB unstripped) over the 4a baseline — the pre-build +12 MiB estimate was wrong by 4x. Decision: the size gate applies to the **stripped** binary only (`go build -ldflags="-s -w"`); unstripped dev builds are exempt. The gate asserts `< 72 MiB` total on darwin/arm64 and linux/amd64 (4b stripped total: ~62 MiB, ~10 MiB headroom). If the budget is blown, the fallback is a `scnr-cloud` split binary, not SigV4.

Modules: `aws-sdk-go-v2` core, `config`, `credentials`, `service/sts`, `service/iam`, `service/s3`, `service/ec2`, `service/rds`, `service/cloudtrail`, `service/kms`, and transitively `smithy-go`. `feature/ec2/imds` is only linked when instance credentials are enabled (build is single; the provider is constructed only behind the flag). No `service/sso*` unless open question 1 resolves "yes".

### 3.3 Design

**Target and scope.** `aws://` (default profile/env) or `aws://<profile>`; profile names validated `^[A-Za-z0-9_.-]{1,64}$` in `planCredentials` (`internal/engine/cloud/aws/creds.go`) at identity time, with `adapter.FlagSafeValue` as a second check at the prowler argv boundary. A named profile bypasses the environment-key steps of the chain (below), so the native engine and prowler's `-p` agree on one profile. New `scnr.yaml` section (`config.Cloud`, strict YAML):

```yaml
cloud:
  aws:
    accounts: ["123456789012"]        # required for non-interactive; 12 digits each
    regions: ["eu-west-1", "us-east-1"] # optional; default = account's enabled regions, capped at 20
    instance_credentials: false        # IMDS/ECS container creds; default off
  azure: { subscriptions: [] }         # prowler-only
  gcp:   { projects: [] }              # prowler-only
```

**Gate.** `safety.Gate.Decide` (`internal/safety/gate.go`) for `TargetCloud` currently returns `ConsentLocal` immediately. It gains a `CloudIdentity CloudIdentityFunc` hook:

```go
// CloudIdentityFunc confirms who the credentials are and returns the account/subscription/project id.
type CloudIdentityFunc func(ctx context.Context, t domain.Target) (CloudIdentity, error)
type CloudIdentity struct { Provider, Account, Principal, Source string } // Source: "env" | "profile:<name>" | "web-identity" | "instance"
```

Decision order for cloud: acknowledgment → `CloudIdentity` (one `sts:GetCallerIdentity`) → if `Account` ∈ `cloud.aws.accounts` → allow (`ConsentMethod = domain.ConsentCloudAllowlist`, new constant); else if interactive → show "`You are about to scan AWS account 1234… as arn:… (credentials from profile X). Type the account ID to continue`" (reuse `App.consentPrompt` with the account as the expected echo) → `ConsentInteractive`; else refuse `E_CLOUD_ACCOUNT_NOT_ALLOWED`. The decision pins `Account`; every API client created afterwards is built from the same resolved credentials object (not re-resolved), and the engine re-checks `GetCallerIdentity` once more at the end of the run and marks the engine `failed: identity changed` if the account differs (credential rotation mid-run to another account is a real misconfiguration). Asset key `aws:<account-id>` (`domain.Target.AssetKey` already does this for `aws://`; it must use the confirmed account, so `Target.Value` is rewritten to `aws://<account-id>` after the gate and the profile moves to `Labels["profile"]`).

**Credential sources** (`internal/engine/cloud/aws/creds.go`). `config.LoadDefaultConfig` is **not** called. The chain is built explicitly from `credentials` providers in this order, stopping at the first that yields keys:
1. Environment static/session keys (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`).
2. `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN` (CI, IRSA) via `stscreds.NewWebIdentityRoleProvider`.
3. Shared config/credentials files for the named profile, loaded with `config.LoadSharedConfigProfile` and inspected: static keys allowed; `role_arn` + `source_profile`/`credential_source=Environment` allowed (assume-role through our STS client, chain depth ≤ 2); `credential_process` → refuse `E_CLOUD_CREDENTIAL_SOURCE` ("scnr does not run credential helpers; export credentials to the environment or use a role_arn profile"); `sso_*` → refuse in 4b unless open question 1 says otherwise; `credential_source = Ec2InstanceMetadata|EcsContainer` → only when `cloud.aws.instance_credentials: true`.
4. Instance/container credentials — only when `cloud.aws.instance_credentials: true`; the IMDS client is created with the endpoint client whose allowlist admits exactly `169.254.169.254` (and `169.254.170.2`/`AWS_CONTAINER_CREDENTIALS_FULL_URI` host when set), overriding `BuiltinDeny` for that one client only. This is the single exception to item 3 and is audited (`limit_override` with `{"instance_credentials": true}`).

Credentials are held in the SDK's `aws.CredentialsCache` for the run and are never written anywhere: the `logx` redactor already masks `AKIA…`/`ASIA…`; `Clean` is applied to every error string from the SDK before it is logged or stored (SDK errors can embed request details). The audit row records `Source` and `Principal` ARN, never key IDs. `scnr doctor` shows which source *would* be used without resolving credentials (it reads the files, calls nothing).

**Read-only by construction.** Every service client is created through one constructor, `aws.newClient[T](cfg, opts...)`, which appends two middlewares:

```go
// ReadOnlyGuard refuses any operation whose name is not on the allowlist. It sits in the
// Initialize step so no request is ever serialised, signed or sent.
var readOnlyOp = regexp.MustCompile(`^(Get|List|Describe|Head|Lookup)[A-Z]`)
var readOnlyDeny = map[string]bool{"GenerateCredentialReport": true, "GetSessionToken": true, "GetFederationToken": true}
type ReadOnlyGuard struct{}
func (ReadOnlyGuard) HandleInitialize(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
    op := awsmiddleware.GetOperationName(ctx)
    if !readOnlyOp.MatchString(op) || readOnlyDeny[op] { return middleware.InitializeOutput{}, middleware.Metadata{}, &RefusedOperationError{Op: op} }
    return next.HandleInitialize(ctx, in)
}
```

and `Meter{limiter, budget}` in the Finalize step: waits on a per-region `rate.Limiter` (10 req/s, burst 10; `deep` 20) and decrements a scan-wide call budget (standard 5,000, deep 20,000); budget exhausted → `BudgetExceededError`, the engine emits `cloud.aws.inventory-truncated` and returns `engine.PartialError`. The SDK retryer is `retry.NewStandard` with `MaxAttempts: 5`, `MaxBackoff: 20s`, rate-limited by the same limiter (retries count against the budget). `AssumeRole` is the one non-`Get/List/Describe` operation needed; it is issued by the credential provider, not through `newClient`, and the provider's STS client is built with `ReadOnlyGuard` replaced by an allowlist of exactly `{AssumeRole, AssumeRoleWithWebIdentity, GetCallerIdentity}`. Both guards are the only two places operation names are permitted.

**Pagination.** Every paginator loop is wrapped by `cloud.Pages(ctx, pager, maxPages)` with `maxPages = 100` and `maxItems = 10,000` per inventory list; hitting either yields `cloud.aws.inventory-truncated` once per list with the counts and `PartialError`. Response bodies: the SDK's HTTP client is our endpoint client whose `MaxResponseHeaderBytes` is 64 KiB and whose transport wraps bodies in `io.LimitReader(16 MiB)`.

**Transport.** `safety.NewEndpointClient(o EndpointOptions)` (new, `internal/safety/endpoint.go`) returns an `*http.Client` using the existing `limitedTransport` with a `Dialer` whose `Scope` is built from `allow = o.Hosts` (hostname and wildcard entries, e.g. `*.amazonaws.com`) and `deny = BuiltinDeny`, plus an `EndpointPolicy{RefusePrivate bool}` check in `CheckURL`: cloud endpoints must resolve to public space (PrivateLink/VPC endpoints are refused in 4b: `E_ENDPOINT_PRIVATE`, with the hint to use the public endpoint; open question 3). `Proxy` is `nil`: HTTP proxies are not used for cloud API traffic (a proxy host would fail the endpoint allowlist anyway; SAFETY.md item 16 records this as closed). The SDK is given `aws.Config{HTTPClient: endpointClient, EndpointResolverV2: nil (default AWS resolver), BaseEndpoint: nil}`; `AWS_ENDPOINT_URL*` env vars are **ignored** (the SDK reads them in `LoadDefaultConfig`, which we do not call). Tests inject `Engine.BaseEndpoint` and an `EndpointOptions.Hosts` of `127.0.0.1`; `cli` never sets either (no flag exists), asserted by `TestCLIDoesNotExposeEndpointOverride`.

**Checks** (`internal/engine/cloud/aws/checks_*.go`, rules in `rules/*.yaml` with what/why/fix text; ~25 as listed in platform §5.7). Each check is `func(ctx, *clients, region string, emit) error` and may only read allowlisted fields into findings: ARN/ID/name, booleans, dates, port ranges, CIDRs, key rotation status, policy *flags* (e.g. "allows `s3:GetObject` to `*`") never the policy document text. Explicitly never copied: tags (keys or values), EC2 user data, Lambda environment, RDS master username, bucket policy/ACL JSON, SG descriptions, IAM inline policy documents, CloudTrail S3 bucket names outside the ARN. `Evidence.Location = ARN`; `Evidence.Redacted` is a one-line structured summary built from those fields and passed through `Redactor.Clean` anyway. Regional checks run per region with `errgroup` limited to 4 regions in parallel; per-check timeout 2 min; the engine honours `EngineTimeout` (standard 10 min).

**IAM policy for the scanner.** Documented in `docs/cloud-aws.md`: `arn:aws:iam::aws:policy/SecurityAudit` is sufficient; a minimal explicit policy listing the exact operations the allowlist test prints is generated by `scnr config show --aws-policy` (the operation list is derived from the same AST walk as test B2 so docs cannot drift).

**Prowler adapter** (`internal/adapter/prowler/`). Argv (AWS):

```
prowler aws -M json-ocsf -o <scratch> -F prowler -z -b --no-color [-p <profile>] [-f <regions...>] [--filter-region ...]
```

Flags with their reason: `-M json-ocsf` single machine format; `-o`/`-F` output into scratch under a fixed name; `-z` ignore exit 3 (findings present); `-b` no banner; `--no-color`. Azure: `prowler azure -M json-ocsf -o … -z -b --no-color (--az-cli-auth | --sp-env-auth | --managed-identity-auth) --subscription-ids <from scope>`; GCP: `prowler gcp … --project-ids <from scope> [--credentials-file <abs path from scnr.yaml tools.gcp_credentials_file>]`. Azure/GCP run only when the corresponding scope list is non-empty (prowler is told the exact subscriptions/projects; there is no native identity confirmation for them — residual, stated in SAFETY item 16). Added to `adapter.Forbidden`: `--fixer`, `-S`, `--security-hub`, `--send-sh-only-fails`, `-B`, `--output-bucket`, `--output-bucket-no-assume`, `--slack`, `--shodan`, `--browser-auth`, `--quick-inventory`? (no: inventory is read-only; not forbidden), `-M csv,html` (not forbidden, just not used), `--config-file` from user input (not accepted). Env pass-through (`Base.ExtraEnv`): `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`, `AWS_DEFAULT_REGION`, `AWS_REGION`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN`, `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_SUBSCRIPTION_ID`, `GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_CONFIG`. `Base.SetEnv`: `PROWLER_NO_UPDATE_CHECK=1`? — not a documented prowler knob; instead doctor states plainly "prowler contacts the cloud provider APIs directly and may check PyPI for updates; whether a current release does so has not been verified against a live binary" (same honesty pattern as SAFETY item 10's nuclei/trivy residuals). Prowler runs after the native gate confirmed the account, with the same profile, so it cannot scan a different account than the one authorised unless `AWS_PROFILE` and `-p` disagree — the adapter always passes `-p <profile>` when a profile was named and sets none of the `AWS_*` vars itself.

Parse: OCSF output is a top-level JSON **array**; `adapter.StreamArray` expects an object, so `parse.go` gains `StreamTopLevelArray(r, fn)` (same skip/count semantics). Field allowlist: `finding_info.uid`, `finding_info.title`, `severity_id` (0–6 → Info/Low/Medium/High/Critical; 6 "Fatal" → Critical), `status_code` (`FAIL` only; `PASS`/`MANUAL` skipped and counted into coverage), `resources[0].uid` (ARN-shaped, `^arn:[a-z-]+:[a-z0-9-]*:[a-z0-9-]*:\d{0,12}:.{1,512}$`, else `provider:<type>/<name>` validated `^[A-Za-z0-9:/._@-]{1,512}$`), `resources[0].region`, `remediation.desc` (≤ 1,000, cleaned), `remediation.references[]` (`adapter.URLRefs`), `cloud.account.uid` (must equal the gate-confirmed account for AWS, else the element is dropped and counted — a prowler run that reports another account is a configuration error, surfaced as `prowler:account-mismatch`, High, Confirmed). `RuleID = prowler:<check-id>` with the check id validated `^[a-z0-9_]{3,100}$`. Dedupe with native checks: a `cloud_dedupe.yaml` map of ~25 `prowler:<check-id> → cloud.aws.<rule>` pairs for the native rule set so both engines produce one fingerprint (same pattern as `sca.osv.<id>@<purl>`).

### 3.4 Invariants and tests

| # | Invariant | Test |
|---|---|---|
| B1 | Every SDK operation issued matches the read-only allowlist at runtime. | `TestReadOnlyGuardRefuses`: a client with `BaseEndpoint = httptest` is asked to call a mutating operation (`PutBucketPolicy`, `DeleteUser`, `GenerateCredentialReport`); the handler records zero requests and the error is `*RefusedOperationError`. |
| B2 | Every SDK operation named in source is read-only. | `TestAWSOperationsAreReadOnly`: AST walk over `internal/engine/cloud/aws/**/*.go`; every selector `*.<Op>(` on an SDK service client and every `<Op>Input{` literal must match `readOnlyOp` and not `readOnlyDeny`; the STS provider file is allowed exactly `AssumeRole*`/`GetCallerIdentity`. Prints the list (feeds the IAM policy doc). |
| B3 | Account binding. | `TestCloudGateAccountAllowlist`: stub STS returns account A; scope lists B → `E_CLOUD_ACCOUNT_NOT_ALLOWED` non-interactively, prompt interactively; identity change mid-run → engine `failed`. |
| B4 | No credential helper execution, no IMDS by default. | `TestCredentialSourcesRefused`: profile with `credential_process` → `E_CLOUD_CREDENTIAL_SOURCE`; `credential_source = Ec2InstanceMetadata` without the config flag → refused; no HTTP request to 169.254.169.254 is attempted (dialer refusal recorded). |
| B5 | API traffic only to allowlisted hosts, public space only. | `TestEndpointClientAllowlist`: endpoint client refuses `evil.amazonaws.com.attacker.net`, a redirect to `169.254.169.254`, and a host resolving to RFC1918 (`E_ENDPOINT_PRIVATE`). |
| B6 | Budget and pagination caps stop the engine and mark it partial. | `TestInventoryTruncated`: stub returns 101 pages → one `cloud.aws.inventory-truncated`, `PartialError`, Runner status `partial:`; `TestMarkFixedIgnoresPartialEngines` covers the lifecycle side. |
| B7 | No tags/user data/env/policy documents in evidence. | `TestNoForbiddenFieldsInEvidence`: stub responses carry `Tags`, `UserData`, `Policy` documents, `Environment` with a canary string; the canary appears nowhere in findings, DB or report. Plus an AST test that no `.Tags`, `.UserData`, `.PolicyDocument`, `.Environment` selector appears in `checks_*.go`. |
| B8 | Credentials never logged or stored. | `TestNoCredentialLeak`: run with fake keys `AKIAFAKE…`/40-char secret/`FQoGZX…` token; grep DB file, reports, audit JSONL, captured stderr at `-v` — zero hits of any of the three values. |
| B9 | Prowler argv is bounded and read-only. | Extend `TestArgBuildersNeverEmitForbiddenFlags` and `TestCheckForbidden` (`internal/adapter/safety_invariants_test.go`) with the prowler adapter and the new `Forbidden` entries; fake binary via `adaptertest.Install` records argv. |
| B10 | Prowler results for another account are dropped. | `TestProwlerAccountMismatch` with an OCSF fixture whose `cloud.account.uid` differs. |
| B11 | Binary size budget (stripped). | CI job: `CGO_ENABLED=0 go build -ldflags="-s -w"` sizes for linux/amd64 and darwin/arm64 ≤ 72 MiB. Unstripped dev builds are exempt (4b review: unstripped is ~86 MiB, stripped ~62 MiB). |

### 3.5 Acceptance criteria

1. `scnr scan aws://audit --ack-authorized --non-interactive` with stub endpoints and `cloud.aws.accounts` containing the stub account produces findings for every native rule from the fixture set, asset `aws:<account>`, locations are ARNs, consent method `cloud-allowlist`, one audit row with `source`/`principal` and no key material.
2. The same without the allowlist exits 3 (`E_CLOUD_ACCOUNT_NOT_ALLOWED`) non-interactively and prompts with the account ID interactively.
3. B1–B11 pass. `scnr config show --aws-policy` prints a JSON IAM policy whose action list equals B2's output.
4. Prowler fixtures (two versions under `testdata/adapters/prowler/<ver>/`) parse; the shared rules dedupe with native findings; the fake prowler binary receives exactly the documented argv.
5. `scnr doctor` reports credential source, account allowlist state, prowler presence, and the two cloud outbound host classes.

### 3.6 Dependencies

`github.com/aws/aws-sdk-go-v2` (+ `config`, `credentials`, `service/{sts,iam,s3,ec2,rds,cloudtrail,kms}`, `smithy-go` transitively). Justified in 3.2. `feature/ec2/imds` only reachable behind config. Nothing else; OCSF parsing is `encoding/json` with allowlists.

### 3.7 Out of scope (4b)

Azure/GCP native checks and native identity confirmation; AWS Organizations fan-out (multiple accounts per scan); Lambda, EKS, ECR, Secrets Manager checks; PrivateLink/VPC endpoints; `AWS_ENDPOINT_URL`; credential helpers; remediation of any kind; CSPM "graph" features.

---

## 4. Sub-phase 4c — Scheduler and daemon

### 4.1 Threats

1. Unattended scans against targets nobody re-authorised (verification expired, scope file edited, DNS now points elsewhere).
2. Two daemons or a daemon plus an interactive scan corrupting state or doubling load on targets.
3. Stored schedule args becoming a persistence channel for secrets (auth headers, keys) or for flags that need a human (`--ack-authorized`, `--i-understand-rate-limits` escalation).
4. Credential lifetime: the daemon holds cloud credentials for days.
5. Notify webhook as SSRF (`--notify-url http://169.254.169.254/…`) or as a leak channel (findings bodies).
6. Missed runs replaying in a burst after downtime; overlapping runs of the same schedule.
7. Hangs: a stuck engine stalls the loop forever.

### 4.2 Design

**Storage.** Migration `0004_schedules`:

```sql
CREATE TABLE schedules (name TEXT PRIMARY KEY, cron TEXT NOT NULL, args_json TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, last_run TEXT, last_scan_id TEXT, last_status TEXT, next_run TEXT NOT NULL);
```

Down drops it. `scans.meta` gains `{"schedule": name}` for scans the daemon ran (no schema change; `meta` is JSON).

**Commands.** `scnr schedule add --name weekly --cron "0 2 * * 1" -- scan 10.0.0.0/24 --profile standard`:
- `name` `^[a-z0-9][a-z0-9-]{0,63}$`; cron parsed with `robfig/cron/v3` `Parser` (standard 5-field + `@daily|@weekly|@monthly|@hourly`; minimum interval 1 h: a schedule whose next two fires are < 1 h apart is refused — scanning is not a health check).
- Args after `--` must begin with `scan`; they are dry-parsed with a fresh `scanCmd()` flagset (`internal/cli/scan.go`) so unknown flags fail now. Refused in schedule args: `--ack-authorized` (acknowledgment must be the standing `scnr.yaml` record with `by`/`at`), `--header`/`--cookie` with literal values (4d; only `--auth-file PATH` is allowed), `--non-interactive` (implied), targets of type URL with credentials (already refused by the detector). `--allow-intrusive` is allowed only once 4d exists and is re-checked at run time (below). Stored as a JSON array, shown verbatim by `schedule show`.
- `schedule list|show|remove|enable|disable`; every change audits `ActionSchedule` with the full args.

**Daemon.** `scnr daemon run [--once] [--notify-url URL] [--out DIR]`:
- Lock: `<home>/daemon.lock` opened `O_CREATE|O_RDWR`, `syscall.Flock(LOCK_EX|LOCK_NB)` (`internal/sched/lock_unix.go`; Windows build returns `ErrUnsupported` and `daemon run` exits 2 — consistent with "Unix-first"). Second daemon → exit 2 "already running (pid N)". The lock is held for the process lifetime; the pid is written for diagnostics only.
- Loop: compute `next_run` for every enabled schedule from `now` at start (persisted), sleep until the earliest, run **one scan at a time** (no `--parallel`; a daemon-wide `semaphore(1)`), recompute, repeat. A schedule whose stored `next_run` is in the past at startup runs **once** (catch-up one, not N); overlapping fire of the same schedule while its scan is running is skipped and audited (`ActionScheduleSkipped`, reason `overlap`).
- Each run constructs a `wizard.ScanRequest` from `args_json` with `NonInteractive = true` and `App.IsTTY = false`, so `gate.Consent` is nil: public targets need a non-expired `verifications` row (`safety.Verifier.IsVerified`), private ranges pass, cloud needs the account allowlist (4b). Nothing in daemon mode can prompt; this is already the gate's behaviour — the daemon adds no bypass and `TestDaemonHasNoConsentFunc` asserts the gate it builds has `Consent == nil`.
- Per-run timeout = profile `EngineTimeout` × engines + 10 min, enforced with a context; the Runner's abandon logic handles wedged engines; a run that exceeds the outer deadline is recorded `last_status = "timeout"` and the loop continues.
- Scope file is re-read on every run (`App.loadConfig`), so edits apply without restart; a broken file → run skipped, audited, daemon keeps going.
- Credentials: nothing is cached between runs. Cloud credential chains are rebuilt per run (shared files re-read; env is process-fixed, documented: "rotate by restarting the daemon or use a role_arn profile"). `--auth-file` (4d) is re-read per run and must be 0600 and owned by the daemon's uid.
- Signals: SIGINT/SIGTERM cancel the in-flight scan context (recorded exit 2, partial), persist `next_run`, release the lock, exit 0.
- Output: reports to `--out/<scan-id>/` exactly as `RunScan` does; stdout gets one line per run; stderr the usual progress.

**Notify.** `--notify-url` must parse as `https://` (or `http://` only to loopback). Body is `{schema_version:"1", schedule, scan_id, started_at, finished_at, profile, targets:[raw], score, grade, counts, partial, exit_code, report_paths}` — no findings, no evidence. Sent with a client from `safety.NewEndpointClient(Hosts: [notify host], AllowPrivate: true, Redirects: 0)`: SSRF to metadata is blocked by `BuiltinDeny`, redirects are never followed (`http.ErrUseLastResponse`), response body discarded after 64 KiB, 30 s timeout, 3 attempts with backoff, failures audited not fatal. The notify host is user-configured and may be private (an internal webhook relay).

### 4.3 Interfaces

```go
// internal/sched/sched.go
type Schedule struct { Name, Cron string; Args []string; Enabled bool; CreatedBy string; CreatedAt, NextRun time.Time; LastRun *time.Time; LastScanID, LastStatus string }
func ParseCron(expr string) (cron.Schedule, error)          // robfig parser, min interval check
func ValidateArgs(args []string) error                       // dry-parse via cli flagset; refuses the list above
type Daemon struct { App *cli.App; Store *store.Store; Lock Locker; Notify *Notifier; Now func() time.Time; Once bool }
func (d *Daemon) Run(ctx context.Context) error
type Locker interface { TryLock(path string) (release func() error, err error) }
// internal/sched/notify.go
type Notifier struct { URL *url.URL; HTTP *http.Client; Log *slog.Logger }
func (n *Notifier) Send(ctx context.Context, s Summary) error
// internal/store/sched.go
func (s *Store) PutSchedule / GetSchedule / ListSchedules / DeleteSchedule / MarkScheduleRun(ctx, name, scanID, status string, next time.Time) error
```

### 4.4 Invariants and tests

| # | Invariant | Test |
|---|---|---|
| C1 | Only one daemon per home. | `TestDaemonLock`: second `Daemon.Run` returns `ErrLocked` while the first holds the flock; released on cancel. |
| C2 | No interactive path in daemon mode. | `TestDaemonHasNoConsentFunc`; `TestDaemonRefusesUnverifiedPublic` (platform acceptance 4): a schedule targeting a public host with no verification is skipped with `gate_refused` audit, exit path non-fatal. |
| C3 | Forbidden schedule args refused at add time and at run time. | `TestScheduleArgsValidation`: `--ack-authorized`, `--header X: y`, `--non-interactive`, unknown flag → error; the same list injected directly into `args_json` is refused at run time too. |
| C4 | One catch-up, no bursts; overlaps skipped. | `TestDaemonCatchUpOnce` with a fake clock jumped 3 weeks: exactly one run; `TestDaemonOverlapSkipped`. |
| C5 | Notify cannot reach metadata or follow redirects, and carries no findings. | `TestNotifyBlocked` (`169.254.169.254`, redirect to private); `TestNotifyBodySchema` golden. |
| C6 | Credentials not cached across runs. | `TestDaemonRebuildsCredentials`: a shared credentials file changed between two runs changes the `Source`/`Principal` recorded in the second scan's audit row. |
| C7 | Minimum interval. | `ParseCron("* * * * *")` → error. |

### 4.5 Acceptance criteria

1. `schedule add/list/show/remove/enable/disable` work and audit; `show` prints the stored argv verbatim.
2. `scnr daemon run --once` with a due private-range schedule against the test listeners runs exactly one scan, writes reports, records `last_scan_id`, sends the notify body to an `httptest` endpoint.
3. C1–C7 pass; `TestNoRawDialers` still passes with `internal/sched` included.
4. `scnr doctor` reports daemon lock state and schedules due in the next 24 h.

### 4.6 Dependencies

`github.com/robfig/cron/v3` — only its `Parser`/`Schedule` are used (no scheduler loop, no transitive dependencies, pure Go). Rejected: hand-rolled 5-field parser — the DOM/DOW "OR" semantics and `L`/`W`-style extensions users paste from crontabs are a known bug farm; the package is 1,500 lines and widely exercised.

### 4.7 Out of scope (4c)

Parallel scans in one daemon; Windows daemon; systemd/launchd unit generation (documented as copy-paste text in `docs/daemon.md`, not generated); schedule-level scope overrides; retention/pruning of old scans; a web dashboard.

---

## 5. Sub-phase 4d — Active DAST

### 5.1 What "active" means here, and what stays forbidden

Active = scnr chooses request *parameters* (not just fixed paths) and inspects how the application reflects or reacts to them. Every active request is still: GET or HEAD; idempotent by HTTP semantics; carrying a short inert marker from a fixed alphabet; to a same-origin URL discovered by the crawler or supplied as the target; within scope and rate limits at dial time. Forbidden, enforced by tests not policy: payload execution of any kind, SQL/OS/LDAP/XPath/template injection *payloads* (we send a marker and quotes, never a statement), time-based or boolean-based blind techniques, denial-of-service shapes (large bodies, slow requests, many connections), brute force or credential guessing, `POST/PUT/PATCH/DELETE` to anything the crawler found (forms with `method=post` are inventoried, never submitted — even with `--allow-intrusive`; Phase 5 may revisit), file upload, header injection beyond the two canary headers below, following out-of-scope redirects, JavaScript execution.

### 5.2 Threats

1. A "safe" probe still mutates state: a GET that deletes (`/delete?id=`), logout links, "mark all read" endpoints.
2. Crawler escapes scope (subdomains, redirects, `<base href>`, protocol-relative URLs) or explodes (calendar pages, infinite `?page=N`).
3. Payload creep: someone adds a `' OR 1=1` probe "for coverage".
4. Auth secrets (cookies, bearer tokens) end up in plan text, argv, audit, evidence, logs, DB.
5. Authenticated session + GET-mutating endpoints = real damage; and the crawler logging the user out mid-scan.
6. Nuclei's `dast`/`intrusive` tags being switched on because the flag name matches.
7. Reflection detection false positives (marker echoed inside a JSON string is not XSS).

### 5.3 Design

**Opt-in mechanics.** Intrusive checks run only when all of the following hold, evaluated per target in a new `safety.IntrusiveGate` (`internal/safety/intrusive.go`) called from `RunScan` after `gate.Decide`:
1. `--allow-intrusive` was passed (`wizard.ScanRequest.AllowIntrusive`; the wizard asks a dedicated question whose text names the probe classes and request budget).
2. The target matches `scope.intrusive_allow` (new list in `scnr.yaml`, same entry grammar as `scope.allow`, parsed by `safety.NewScope` into a third list `intrusive`); empty list → nothing is intrusive. Deny still wins.
3. The target is private (consent method `private-range`), **or** public with a non-expired ownership verification (`dns-txt`/`well-known`). Interactive consent alone is not sufficient for intrusive checks on public targets — the user is told why and pointed at `scnr verify`.
4. Non-interactive/daemon mode adds nothing and removes nothing: rule 3 already requires verification for public targets.
Outcome is recorded on the scan (`scans.meta.intrusive = {targets:[…], probes:n}`) and audited with `ActionIntrusive`; the HTML/JSON report shows an "Active checks ran" banner with the request count.

When the gate says no, the `webscan` engine runs exactly as in Phase 3 (templates with `safety: safe`, passive checks). When yes, `webscan.Engine.Templates` includes `safety: intrusive` templates (POST ≤ 4 KiB, already validated in `template.go`) and the new `dast` sub-engine runs. The `Rule.Safety` two-value invariant is unchanged.

**Crawler** (`internal/engine/webscan/crawl.go`, `x/net/html` tokenizer):
- Seeds: target URL plus the passive paths. Same-origin only (scheme, host, port equal to the target after normalisation); every candidate also passes `urlScopeFilter` (`webscan.go`) so URL-prefix allow entries bound it; `<base href>` is honoured only if same-origin; protocol-relative and `javascript:`/`data:`/`mailto:` dropped.
- Limits (constants, `deep` doubles the first three): depth 3, 200 URLs, 50 forms, 500 distinct (URL path, param name) pairs, HTML bodies ≤ 1 MiB (`maxBodyBytes`), only `text/html` parsed, 4 parallel fetches (`requestParallel`), per-host rps from `Limits` as today. Hitting a cap → `web.crawl-truncated` (Info) and `PartialError`.
- Dedupe key: path + sorted parameter *names* (values ignored), so `?page=1..N` is one node; numeric path segments collapse (`/items/123` → `/items/{n}`) for the depth/URL budget only, not for probing.
- Destructive-word deny list applied to the full URL and to link text: `logout|signout|sign-out|log-out|delete|remove|destroy|purge|reset|disable|revoke|unsubscribe|cancel|approve|reject|publish|archive|wipe|format|shutdown|reboot` (case-insensitive, word boundary) — such URLs are inventoried (`web.state-changing-get` Info finding: "a GET link appears to change state; verify it requires POST/CSRF token") and never fetched or probed. With `--auth-file`, the deny list is mandatory and cannot be shrunk.
- `robots.txt` `Disallow` for `*`/`scnr` is honoured by the crawler (templates are unaffected — they probe fixed paths by design); open question 4.
- Forms: `method=get` forms are treated as URL+param discoveries; `method=post` forms are recorded as `web.form-inventory` evidence (action, field names only — never field values or hidden tokens) and not submitted.

**Probes** (`internal/engine/webscan/probe.go`). One marker per (URL, param): `m := "scnr" + hex(6 random bytes)`; probe string classes:

```go
// Every active payload must match this. The test rejects any literal or constructed payload that does not.
var AllowedPayloadRe = regexp.MustCompile(`^scnr[0-9a-f]{12}(?:'"<)?$`)
```

- `web.reflected-input` (Medium, Firm): request `url?param=<m>'"<`; finding if the body contains `<m>'"<` unescaped **and** the match position is in an HTML text/attribute context (not inside a `<script>` string literal or a JSON response — content type `text/html` required, surrounding bytes inspected). Marker-only reflection (escaped quotes) → `web.reflected-input-escaped` (Info).
- `web.open-redirect` (Medium, Confirmed): existing `canaryOrigin` (`https://scnr-canary.invalid`) placed in parameters whose names match `(?i)^(url|next|redirect|return|returnurl|return_to|goto|dest|destination|continue|target|redir|r|u|back|callback)$` and in any parameter whose current value is URL-shaped; finding if the response is 3xx with `Location` host `scnr-canary.invalid`. Never followed (the client's `CheckRedirect` refuses it already as out of scope; the probe reads the `Location` header from the refused redirect via `RedirectOutOfScopeError`).
- `web.error-disclosure` (Low, Tentative): the same `'"<` probe; finding if the response status is 500 or the body matches a fixed RE2 set of database/framework error signatures (`SQLSTATE`, `ORA-\d{5}`, `You have an error in your SQL syntax`, `pg_query\(`, `Unclosed quotation mark`, `Traceback \(most recent call last\)`, `at java\.`, `Warning: .* on line \d+`). No statement is ever sent; a single quote in a GET parameter is the entire "injection".
- `web.cors-reflect-origin`: `Origin: https://scnr-canary.invalid` header (already sent passively today) — unchanged; and `web.host-header-reflect`: nothing — Host override is excluded (it is the one header class that can route requests elsewhere).
- Budget: ≤ 1,000 active requests per target (`deep` 3,000), counted separately from crawl fetches; exhausted → `web.probe-truncated` + `PartialError`.
- Body cap for probe responses 256 KiB; evidence is the request line with the marker and a ≤ 256-byte window around the match, through `Redactor.TextEvidence`.

**Authenticated scanning.** `--auth-file PATH` (YAML, strict): `{headers: {Authorization: "Bearer …", X-Api-Key: …}, cookies: {session: …}, mysql: {user: …, password: …}}`; file must be 0600 and owned by the current uid (`safety.CheckPrivateFile`, extracted from the `outfile.go` helpers if applicable, else new); `--header`/`--cookie` literals on the command line exist for interactive use only and are refused in schedules (4c). There are deliberately no `--db-user`/`--db-password` flags: database passwords must never appear on a command line. The mysql login is released only for the exact host:port being probed (`AuthMaterial.DBCredentials`, the database equivalent of the origin check below). Values are loaded into `engine.Options.Auth *safety.AuthMaterial` (new; `String()` returns `"<redacted>"`, `MarshalJSON` is an error so it can never be serialised by accident). Application: `limitedTransport.RoundTrip` (`dial.go`) adds the headers/cookies **only** when `req.URL` host:port equals the authorised origin recorded in `AuthMaterial.Origin`; redirects to another in-scope host do not carry them. Redaction: `Redactor` gains the patterns `(?i)^(cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*.+$` (line-anchored, multiline) and the exact auth values are added to a per-run `Redactor.Literals` list (new; exact-match masking, so even a non-pattern-shaped token is masked everywhere: plan, evidence, logs, audit, errors). The plan shows `authenticated: yes (2 headers, 1 cookie)`; the audit row records `auth: true` and `sha256(values)` only. Logout protection: with auth material present, the destructive-word list is enforced and `Set-Cookie` responses that clear the session cookie are noted as `web.session-invalidated` (Info) and the probe phase stops (coverage partial) rather than continuing unauthenticated.

**Nuclei interaction.** `--allow-intrusive` changes nothing in the nuclei adapter. `ExcludedTags = "dos,fuzz,intrusive,bruteforce,dast"` stays as is: nuclei's `intrusive` covers default-credential and similar checks, which are brute-force-adjacent and outside our definition; `-dast` stays in `adapter.Forbidden`. `TestNucleiArgsIgnoreAllowIntrusive` asserts byte-identical argv with and without the option.

### 5.4 Interfaces

```go
// internal/safety/intrusive.go
type IntrusiveGate struct { Scope *Scope; Verified VerifiedFunc }
func (g *IntrusiveGate) Decide(ctx context.Context, d *Decision, allowFlag bool) (ok bool, reason string, err error)
// internal/safety/auth.go
type AuthMaterial struct { Origin string; headers http.Header; cookies []*http.Cookie }   // unexported fields; Apply(req) copies only for Origin
func LoadAuthFile(path string) (*AuthMaterial, error)                                      // 0600 + owner check, strict YAML, ≤ 64 KiB
func (a *AuthMaterial) String() string { return "<redacted auth material>" }
func (a *AuthMaterial) MarshalJSON() ([]byte, error) { return nil, errors.New("auth material is not serialisable") }
// internal/safety/redact.go
func (r *Redactor) WithLiterals(vals ...string) *Redactor   // exact-match masking added to Redact
// internal/engine/webscan/crawl.go, probe.go
type Crawler struct { Client *http.Client; Scope func(string) bool; Limits CrawlLimits; Deny *regexp.Regexp; Robots *robots }
func (c *Crawler) Crawl(ctx context.Context, seed *url.URL, visit func(Page) error) (CrawlStats, error)
type Prober struct { Client *http.Client; Budget int; Rules engine.RuleSet; Red *safety.Redactor }
func (p *Prober) Probe(ctx context.Context, pages []Page, emit engine.EmitFunc) (ProbeStats, error)
// internal/engine/engine.go
type PartialError struct{ Reason string }   // Runner → status "partial: <reason>"; excluded from okEngines
```

`engine.Options` gains `Intrusive bool` and `Auth *safety.AuthMaterial`; `wizard.ScanRequest` gains `AllowIntrusive bool`, `AuthFile string`, `Headers, Cookies []string`.

### 5.5 Invariants and tests

| # | Invariant | Test |
|---|---|---|
| D1 | Every active payload matches `AllowedPayloadRe`. | `TestPayloadAlphabet`: AST walk over `internal/engine/webscan/probe.go` string literals that are passed to `url.Values.Set`/query building, plus a runtime hook recording every outbound query value during a probe run against `httptest`; all match. |
| D2 | Active requests are GET/HEAD only; POST only from intrusive templates ≤ 4 KiB. | `TestActiveMethods`: `httptest` server records methods and body sizes over a full intrusive run. |
| D3 | Intrusive never runs without flag + `intrusive_allow` + (private or verified). | `TestIntrusiveGateTable`: 8-row table including "public, interactive consent, no verification → refused with reason". |
| D4 | Crawler stays on origin and within scope at every hop; caps hold. | `TestCrawlerScope` (links to subdomain, other port, `<base href>` elsewhere, redirect to `169.254.169.254`, protocol-relative); `TestCrawlerCaps` (calendar page with 10,000 links → 200 URLs, `web.crawl-truncated`, `PartialError`). |
| D5 | Destructive-word URLs are never fetched. | `TestDestructiveLinksNotFetched`: server fails the test if `/logout` or `/items/1/delete` is requested. |
| D6 | Auth material never leaves the authorised origin and never appears anywhere. | `TestAuthOriginOnly` (in-scope second host receives no `Authorization`); `TestAuthNoLeak` (grep DB, reports, audit JSONL, plan text, `-v` logs for the token literal). |
| D7 | Nuclei argv is unchanged by `--allow-intrusive`. | `TestNucleiArgsIgnoreAllowIntrusive`. |
| D8 | Reflection finding requires HTML context. | Table: reflection inside JSON body → no `web.reflected-input`; inside `<script>` string → no; in attribute → yes. |
| D9 | Partial coverage never marks findings fixed. | `TestMarkFixedIgnoresPartialEngines` extended with a truncated crawl. |

### 5.6 Acceptance criteria

1. `scnr scan http://127.0.0.1:PORT --allow-intrusive --ack-authorized --non-interactive` with `intrusive_allow: [127.0.0.1]` against a fixture app (reflective param, open redirect, SQL error page, `/logout` link, POST form, 300-link index) produces `web.reflected-input`, `web.open-redirect`, `web.error-disclosure`, `web.state-changing-get`, `web.form-inventory`, `web.crawl-truncated`; the engine is `partial: crawl cap`; `/logout` was never requested; total requests ≤ budget.
2. Same command without `--allow-intrusive`, or without the `intrusive_allow` entry, runs only Phase 3 behaviour (asserted by request log) and the report has no "Active checks" banner.
3. A public fixture host (fake resolver → public IP, `httptest` listener reached through a pinned address) with interactive consent but no verification → intrusive refused with the `scnr verify` hint; with a verification row → runs.
4. `--auth-file` with a 0644 file is refused; with 0600 the fixture's `/account` page (requires the cookie) is crawled, the token appears nowhere (D6), and the plan prints `authenticated: yes`.
5. D1–D9 pass; `FuzzCrawlerHTML` (hostile HTML into the link extractor) runs clean 60 s.

### 5.7 Dependencies

None new (`golang.org/x/net/html` is already present).

### 5.8 Out of scope (4d)

POST form submission of any kind; login-flow automation (recorded sequences, OAuth); JS-rendered SPA crawling; blind/time-based techniques; XXE/SSRF probes (they require the target to call out); WebSocket; API spec (OpenAPI) driven probing; per-parameter type inference beyond "URL-shaped".

### 5.9 Implementation notes (as built)

- The canary origin (`https://scnr-canary.invalid`) is exempt from
  `AllowedPayloadRe`: the alphabet governs prober-generated marker
  payloads, and the canary is the single fixed non-marker value (placed,
  never followed). D1's runtime hook asserts marker-or-canary.
- Numeric-collapse (`/items/123` → `/items/{n}`) is a second
  crawl-frontier dedupe: collapsed repeats are not fetched. Probing
  always targets real page URLs. Any other reading leaves fetching
  unbounded, which contradicts the URL cap.
- "Passive paths" seeds are the template paths that returned 2xx in the
  passive phase (proved to exist), not every template path.
- `robots.txt` binds discovery and extra (2xx template-path) seeds;
  only the explicitly authorised primary seed is fetched
  unconditionally. The destructive-word list screens every discovered
  link and every extra seed at fetch time, while the prober re-screens
  every page (seeds included) and never probes destructive URLs.
- Probe requests keep the page's other parameters (fidelity; fewer
  error-disclosure false positives). Evidence request lines show the
  probed parameter only, and open-redirect evidence quotes the target
  host only, so echoed discovery values never reach evidence.
- Finding locations are value-free (`origin + path + ?param`) so the
  random marker cannot churn fingerprints across scans.
- `IntrusiveGate` re-checks verification live for public targets rather
  than trusting the decision's consent-method string.
- `scans.meta.intrusive` is written at insert (`{targets, probes: 0}`)
  and updated with the final probe count after the engines complete.
  Telemetry flows through an `engine.Options.Stats` callback.
- The destructive-link inventory is capped at 500 entries (fetching is
  unaffected — everything destructive is skipped regardless).
- No embedded `safety: intrusive` templates ship; intrusive templates
  come from `--templates` only.
- Follow-ups for a later pass: spaced/underscored destructive variants
  (`Log out`, `sign_out`) are not in the §5.3 word list (spec-literal);
  redirect follows of probe requests are hop-bounded but not
  budget-counted.

---

## 6. Sub-phase 4e — Plugins

### 6.1 Model decision

Out-of-process executables speaking JSON over stdio, discovered **only** from `<home>/plugins/<name>/<version>/` and only when listed in `<home>/plugins.lock` with a matching binary checksum. No in-process Go `plugin` package (platform-limited, same address space, no revocation), no PATH scanning for `scnr-plugin-*` (PATH hijack, no pinning — this replaces the §11 sketch), no network from the plugin process (the broker below is the only path). Plugins are hostile code: the protocol and the host treat them exactly like an adapter whose binary we did not write, which is what `adapter.Base` already models.

### 6.2 Threats

1. Supply chain: a plugin binary is swapped after install, a malicious plugin is installed by a typo, or an update changes capabilities silently.
2. The plugin reads files outside the target, phones home, mines, or reads `~/.scnr/secret`, the DB, the auth file.
3. Output: a billion findings, 1 GiB lines, control characters, HTML/SQL injection text, fake `Status: fixed`, fake `KEV: true`, rule IDs that collide with native rules to poison dedupe/lifecycle.
4. Hang / fork bomb / zombie children.
5. Sandboxing that exists on paper: macOS and Linux have different primitives and neither is available without caveats.
6. The broker becomes an SSRF proxy for the plugin.

### 6.3 Design

**Layout and lock.**

```
<home>/plugins/<name>/<version>/scnr-plugin-<name>     0700 binary
<home>/plugins/<name>/<version>/manifest.json           0600
<home>/plugins/<name>/<version>/manifest.sig            0600 (optional unless require_signature)
<home>/plugins.lock                                     0600 YAML:
  plugins:
    - name: license-check
      version: 1.2.0
      sha256: <hex of binary>
      manifest_sha256: <hex>
      publisher_key: "ed25519:<base64>"   # "" when installed with --allow-unsigned (interactive only)
      capabilities: {supports: [path], network: none, filesystem: target-readonly}
      installed_at: RFC3339
      installed_by: gerald
```

`scnr.yaml` gains `plugins: { require_signature: true, trusted_keys: ["ed25519:…"], sandbox: required|best-effort }` (defaults: `true`, `[]`, `required`).

**Manifest** (≤ 64 KiB, strict decode, field allowlist):

```json
{"protocol":1,"name":"license-check","version":"1.2.0","description":"…","homepage":"https://…",
 "supports":["path"],"safety":"safe","capabilities":{"network":"none|broker","filesystem":"target-readonly"},
 "rules":[{"id":"stale-license","title":"…","severity":"low","what":"…","why":"…","fix":"…","cwe":"CWE-…","references":["https://…"]}]}
```

`name` `^[a-z0-9][a-z0-9-]{1,31}$`; `version` strict semver (`x/mod/semver` with `v` prefix); `safety` must be `safe` (intrusive plugins are refused in 4e — there is no way to bound what a plugin does with intrusive permission); `supports` ⊆ `{path,url,host,image}`; `rules` ≤ 200, each validated by `engine.validateRule` (`internal/engine/rules.go`) with engine `plugin:<name>`, rule IDs become `plugin.<name>.<id>` — the namespace guarantees no collision with native or adapter rules.

**Install/update/remove.** `scnr plugin install PATH` where PATH is a local directory or `.tar.gz` (≤ 64 MiB, entry grammar `^(manifest\.json|manifest\.sig|scnr-plugin-[a-z0-9-]+)$`, no symlinks; the same tar hardening as 4a). Steps: parse manifest → verify `manifest.sig` against `plugins.trusted_keys` (ed25519 over the manifest bytes; the manifest must contain `"binary_sha256"`, so the signature covers the binary) — missing/invalid signature → refused unless `require_signature: false` **and** interactive **and** the user types the printed sha256 prefix back (`--allow-unsigned`); non-interactive install requires a trusted signature, no exceptions → copy into place with the modes above → write lock entry → audit `ActionPluginInstall` with name, version, hashes, key, how trust was established. Update = install of a new version; the old version directory is kept until `plugin remove NAME@VERSION`; a version downgrade prompts. `scnr plugin list|show|verify|remove`; `verify` re-hashes every installed binary against the lock and reports drift (also run by `doctor`). URL installs do not exist in 4e (the user downloads with their own tool; this keeps a fetch path out of the plugin code).

**Load.** At registry build (`App.engineRegistry`, `internal/cli/scan.go`), for each lock entry: re-hash the binary (`sha256`, streamed) — mismatch → plugin skipped with `plugin.integrity-failed` in the coverage appendix and an audit row, never run; manifest re-parsed and compared to lock `manifest_sha256`; then registered as engine `plugin:<name>` implementing `engine.Engine` via an `adapter.Base` with a **fixed path** (new `Base.Path string`; when set, `Detect` skips `LookPath` and uses it; `Detect` still runs `manifest` as the version probe).

**Protocol.** `scnr-plugin-x manifest` → manifest JSON on stdout (≤ 64 KiB, 10 s). `scnr-plugin-x run` → request JSON on **stdin** (never argv, so target paths with odd characters are not an argv problem and nothing is visible in `ps`):

```json
{"protocol":1,"target":{"type":"path","value":"/abs/target"},"scratch":"/tmp/scnr-xxx/plugin-license-check","profile":"standard",
 "deadline":"RFC3339","broker":"/tmp/scnr-xxx/plugin-license-check/broker.sock"}
```

Findings as JSONL on stdout, one object per line, allowlisted fields only: `rule` (must be a manifest rule id), `location` (≤ 1,024, relative under the target for `path` targets — `adapter.RelLocation`; URL on the target origin for `url`), `confidence` (`tentative|firm|confirmed`), `evidence` (≤ 10 × ≤ 4 KiB, `kind`, `location`, `text`), `cves` (validated `adapter.CVE`), `references` (`adapter.URLRefs`). Everything else is dropped. Line cap 1 MiB (dropped and counted), total stdout cap 256 MiB (`adapter.MaxStdoutBytes`, kill), findings cap 50,000 → `plugin.output-truncated` + `PartialError`. Severity, title, prose come from the manifest rule (via `domain.Rule.Apply`), never from the finding line, so a plugin cannot escalate per finding. `Engine`, `Status`, `ScanID`, `Risk`, `KEV`, `EPSS`, `Fingerprint` are set by scnr. Stderr: 8 KiB tail (existing). Exit code non-zero → engine `failed` with the cleaned tail. Status/progress lines are stderr only.

**Process controls** (`adapter.Base.Exec` extension, benefits prowler/nmap/nuclei too): `SysProcAttr{Setpgid: true}` and kill of the process group on timeout/cap; `cmd.Dir = scratch`; env = `PATH`, `HOME=<scratch>` (not the real home: plugins must not see `~/.scnr`), `TMPDIR=<scratch>`; stdin closed after the request; `ulimit`-style caps via `prlimit`-equivalent are not portable — `RLIMIT_NOFILE`/`RLIMIT_NPROC` are set through the sandbox wrapper where available.

**Sandbox wrappers** (`internal/plugin/sandbox_{linux,darwin,other}.go`), applied by prefixing argv:
- Linux: `bwrap --unshare-all --die-with-parent --new-session --ro-bind <target> <target> --bind <scratch> <scratch> --ro-bind /usr /usr --ro-bind /lib /lib (--ro-bind /lib64 …) --proc /proc --dev /dev --tmpfs /tmp --chdir <scratch> -- <binary> run`; `--unshare-net` is implied by `--unshare-all`; the broker socket lives in `<scratch>` so it is reachable. `bwrap` must be on PATH (doctor reports; most distros package it).
- macOS: `sandbox-exec -p "<profile>" <binary> run` with a profile: `(version 1) (deny default) (allow process-exec (literal "<binary>")) (allow file-read* (subpath "<target>") (subpath "<scratch>") (subpath "/usr/lib") (subpath "/System/Library")) (allow file-write* (subpath "<scratch>")) (allow network-outbound (remote unix-socket (path-literal "<scratch>/broker.sock")))` — no other network. `sandbox-exec` is deprecated by Apple but present; SAFETY item 19 records the residual.
- `plugins.sandbox: required` (default): no wrapper available → plugins are `skipped: sandbox unavailable` (doctor explains). `best-effort`: run with process controls only, audited per run with `sandbox: none`.

**Network broker** (`internal/plugin/broker.go`). Only for plugins whose manifest and lock say `network: broker`, and only for `url`/`host` targets. A Unix socket in scratch; line-delimited JSON requests `{"id":1,"method":"GET|HEAD","url":"…","headers":{…}}` (≤ 16 KiB per request; headers allowlist `Accept`, `Accept-Language`, `User-Agent` suffix; never `Host`, `Authorization`, `Cookie`); scnr performs the request with the **scan's** `Options.HTTP` client (scope-checked, pinned, rate-limited, redirect-validated — the plugin inherits exactly the scan's authorisation and nothing more, and never the auth material) and returns `{"id":1,"status":…,"headers":{…},"body_b64":…}` with body ≤ 1 MiB; ≤ 500 requests per plugin run; out-of-scope URL → `{"error":"E_SCOPE_NOT_ALLOWED"}`. There is no raw TCP, DNS or UDP broker.

### 6.4 Interfaces

```go
// internal/plugin/plugin.go
type Manifest struct { Protocol int; Name, Version, Description, Homepage string; Supports []domain.TargetType; Safety string; Capabilities Caps; Rules []domain.Rule; BinarySHA256 string }
type Caps struct { Network string /* none|broker */; Filesystem string /* target-readonly */ }
type LockEntry struct { Name, Version, SHA256, ManifestSHA256, PublisherKey string; Capabilities Caps; InstalledAt time.Time; InstalledBy string }
func Install(ctx context.Context, home, src string, o InstallOptions) (LockEntry, error)   // trust, verify, copy, lock, audit via callback
func LoadLock(home string) ([]LockEntry, error)
func Verify(home string, e LockEntry) error                                                   // re-hash binary and manifest
// internal/plugin/engine.go
type Engine struct { adapter.Base; Entry LockEntry; Manifest Manifest; Sandbox Sandbox; Broker *Broker }  // implements engine.Engine, adapter.Adapter
func (e *Engine) Args(t domain.Target, o engine.Options) ([]string, error)  // ["run"]; request goes to stdin
func (e *Engine) Parse(r io.Reader, emit func(domain.Finding) error) error
// internal/plugin/sandbox.go
type Sandbox interface { Wrap(binary string, target, scratch string, net bool) (argv []string, err error); Name() string }
// internal/plugin/broker.go
type Broker struct { Client *http.Client; Scope func(*url.URL) error; MaxRequests int; MaxBody int64 }
func (b *Broker) Serve(ctx context.Context, sockPath string) error
// internal/adapter/adapter.go (extensions)
type Base struct { ...; Path string /* fixed binary path; skips LookPath */; Stdin io.Reader; Setpgid bool }
```

### 6.5 Invariants and tests

| # | Invariant | Test |
|---|---|---|
| E1 | A plugin runs only if its binary and manifest hash match the lock. | `TestPluginIntegrity`: modify one byte of the binary after install → `skipped`, `plugin.integrity-failed`, audit row; no process spawned (fake binary writes a sentinel file if executed). |
| E2 | Unsigned install is impossible non-interactively; interactive requires typing the hash prefix. | `TestPluginInstallTrust` table. |
| E3 | Plugin output cannot set anything outside the allowlist. | `TestPluginOutputAllowlist`: lines carrying `severity`, `status`, `kev`, `risk`, `engine`, a non-manifest `rule`, an absolute `location` → fields ignored or line dropped and counted; the stored finding's severity equals the manifest rule's. |
| E4 | Caps and hangs. | `TestPluginGiBOutput` (platform acceptance 6: 1 GiB writer killed at 256 MiB, process group gone); `TestPluginHangKilled` (sleeps past deadline; children in the group killed; Runner `failed`). |
| E5 | No network except the broker, and the broker enforces scope. | `TestBrokerScope`: plugin requests `http://169.254.169.254/` and an out-of-scope host → `E_SCOPE_*`; in-scope request succeeds through the scan client (asserted via the `httptest` server). `TestSandboxDeniesNetwork` (skipped unless `bwrap`/`sandbox-exec` present; fake plugin tries a direct dial and must fail). |
| E6 | Plugins never see the real home or auth material. | `TestPluginEnv`: fake plugin dumps env and attempts to read `<home>/secret` and the DB → `HOME` is scratch, reads fail under sandbox (test gated on wrapper availability), and no `Authorization` header reaches the broker from the plugin side. |
| E7 | Rule namespace. | Manifest rule `sca.osv.x` → registered as `plugin.<name>.sca.osv.x`; `TestPluginRuleNamespace`. |
| E8 | Sandbox required by default. | `TestSandboxRequiredSkips`: with no wrapper found and default config, plugin status `skipped: sandbox unavailable`. |

### 6.6 Acceptance criteria

1. `examples/plugins/license-check/` (Go, built in tests) installs with a test key, appears in `plugin list`, runs on `scnr scan ./testdata/repo` producing `plugin.license-check.*` findings with manifest prose, and shows in the coverage appendix with version and sandbox name.
2. E1–E8 pass on Linux CI (bwrap installed) and macOS CI (sandbox-exec); the network-denial tests are skipped, not failed, where wrappers are absent.
3. `scnr doctor` lists installed plugins, integrity status, sandbox availability and `plugins.sandbox` mode.
4. `TestNoRawDialers`, `TestNoForbiddenFlagLiteralsInAdapterSources` (now including `internal/plugin`) pass.

### 6.7 Dependencies

None new. ed25519 and SHA-256 are stdlib; sandboxes are OS binaries detected at runtime, never vendored.

### 6.8 Out of scope (4e)

Intrusive plugins; plugins for cloud targets (would need credential forwarding); URL/registry installs and auto-update; Windows sandboxing; a plugin SDK beyond the documented protocol and the example; in-process plugins; WASM runtime (revisit in Phase 5 if the exec model proves too heavy).

---

## 7. SAFETY.md additions (one item per sub-phase, added as each lands)

16. **Cloud credentials are read-only, explicit and account-bound.** Credential sources are env, web identity, shared-file static or `role_arn` profiles, and (only when configured) instance credentials; `credential_process` is never run. `sts:GetCallerIdentity` runs before any check and the account must be in `cloud.aws.accounts` or confirmed interactively by typing it. Every SDK operation passes a read-only middleware (`^(Get|List|Describe|Head|Lookup)`, with `GenerateCredentialReport` denied) and the sources are AST-checked. API traffic goes through `safety.NewEndpointClient` (public AWS endpoints only); calls are rate-limited and budgeted; pagination is capped and truncation marks the engine partial. Tags, user data, environment variables and policy documents are never read into evidence. Prowler runs without fixers, uploads, Slack, Shodan or browser auth. *Residual:* Azure/GCP via prowler have no native identity confirmation; they run only against subscriptions/projects listed in the scope file.
17. **Offline bundles are signed before they are parsed.** Only `manifest.json`/`manifest.sig` are read until an ed25519 signature from `vulndb.trusted_keys` verifies; entries, sizes, line lengths and record counts are capped; a digest mismatch rolls back the whole load.
18. **The daemon can only do what a non-interactive scan can.** It has no consent function, one instance per home (flock), one scan at a time, re-reads the scope file per run, caches no credentials, refuses `--ack-authorized` and literal auth values in schedules, catches up at most one missed run, and notifies only the configured host with a summary that contains no findings.
19. **Active checks are inert, GET/HEAD, opt-in and never for unverified public targets.** Payloads match `^scnr[0-9a-f]{12}('"<)?$`; nothing is submitted by POST except ≤ 4 KiB intrusive templates; URLs with state-changing words are never fetched; `--allow-intrusive` requires `scope.intrusive_allow` and a private target or ownership verification; nuclei's argv is unchanged by the flag. Auth material is applied only to the authorised origin and masked everywhere as a literal.
20. **Plugins are untrusted executables.** Installed only from the lock file after signature or interactive hash confirmation, re-hashed before every run, executed with a fixed path, scratch `HOME`, process-group kill, 256 MiB/1 MiB/50,000-finding caps, output field allowlist with prose from the manifest, and a sandbox (`bwrap`/`sandbox-exec`) that is required by default. Network exists only through the broker, which uses the scan's own scope-checked client. *Residual:* `sandbox-exec` is deprecated on macOS; `best-effort` mode runs with process controls only and is audited.

## 8. Cross-cutting changes by file (seams extended; all read)

- `internal/safety/dial.go`: `NewEndpointClient` (reuses `limitedTransport`, `Dialer`); `limitedTransport.RoundTrip` applies `AuthMaterial` for the authorised origin only. `internal/safety/scope.go`: third list `intrusive`; `NewScope(allow, deny, intrusive)`. `internal/safety/gate.go`: `CloudIdentity` hook, `ConsentCloudAllowlist`; `internal/safety/redact.go`: cookie/header patterns, `WithLiterals`. New: `endpoint.go`, `intrusive.go`, `auth.go`.
- `internal/engine/engine.go`: `PartialError`; `Options.Intrusive`, `Options.Auth`. `internal/engine/runner.go`: map `PartialError` → `status "partial: …"`. `internal/cli/scan.go`: `okEngines` excludes partial; `IntrusiveGate` call; new flags; registry adds `cloud/aws`, `adapter/prowler`, `plugin` engines.
- `internal/adapter/adapter.go`: `Base.Path`, `Base.Stdin`, `Setpgid` + group kill; `Forbidden` additions; `parse.go`: `StreamTopLevelArray`. `safety_invariants_test.go`: include prowler and `internal/plugin`.
- `internal/store`: migrations `0003_osv_offline`, `0004_schedules`; `sched.go`; `AffectedFor`. `internal/engine/sca/{osv.go,sca.go,offline.go}`: `Lookup` interface. `internal/vulndb/{bundle.go,build.go}`. `internal/config/config.go`: `Cloud`, `VulnDB`, `Plugins`, `Scope.IntrusiveAllow`, `Tools.GCPCredentialsFile`. `internal/audit/audit.go`: `ActionSchedule`, `ActionScheduleSkipped`, `ActionIntrusive`, `ActionPluginInstall`, `ActionPluginRemove`, `ActionTrustKey`, `ActionDaemonStart`. `internal/doctor/doctor.go`: outbound lists, credential source, plugins, sandbox, daemon lock. `internal/engine/image/archive.go`: export the tar entry-name predicate as `ValidEntryName` for reuse by `vulndb` and `plugin` (one function; a cross-package test pins the rules).
- New packages: `internal/engine/cloud/aws`, `internal/adapter/prowler`, `internal/sched`, `internal/plugin`, `internal/engine/webscan/{crawl.go,probe.go}`.

## 9. Open questions (recommended default in bold)

1. AWS SSO as a credential source in 4b (`sso_*` profiles read `~/.aws/sso/cache` and call `portal.sso.<region>.amazonaws.com`)? **No in 4b** — refuse with a message pointing at `aws sso login` + `aws configure export-credentials --format env`, which puts short-lived keys in the environment; revisit if users ask. Keeps `service/sso*` out of the binary.
2. Who signs OSV bundles — self-built keys only, or also a project-published bundle with an embedded key? **Self-built only in 4a.** An embedded key is a release-infrastructure commitment (key custody, rotation) that this spec should not make.
3. PrivateLink/VPC endpoints for AWS API traffic (resolve to RFC1918)? **Refuse in 4b** (`E_ENDPOINT_PRIVATE`); add `cloud.aws.allow_private_endpoints: true` later if a real deployment needs it, audited like instance credentials.
4. Should the DAST crawler honour `robots.txt`? **Yes.** It is the owner's own statement about what automated clients should not touch; templates still probe their fixed paths, so sensitive-file exposure coverage is unaffected.
5. Default `plugins.sandbox` on macOS given `sandbox-exec` deprecation: `required` or `best-effort`? **`required`** on both platforms, with doctor explaining the deprecation; a plugin that cannot be sandboxed is skipped, never silently run unconfined.

## Handoff

Implement with code-writer from this spec, one sub-phase per hand-off in the order 4a → 4b → 4c → 4d → 4e; each sub-phase's invariant table is its test list and its SAFETY.md item lands in the same change.

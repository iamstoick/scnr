# scnr

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/4d85e729-70fa-479f-8949-7e423dc46a13" />


A defensive vulnerability discovery tool. It observes and reports; it never exploits.

`scnr` scans your code, dependencies, containers, infrastructure-as-code, networks, web apps, and AWS accounts, then gives you one plain-English report with a posture score — without ever running exploits, brute force, or anything that changes the target.

## The problem

Small teams and solo builders ship code to the cloud every day, but security tooling assumes you are an enterprise: expensive scanners, complex agents, dashboards that need a team to feed them, and "active" testers that can take down what they probe.

The result is that most projects get scanned never, or with a pile of disconnected tools whose outputs nobody reconciles. Meanwhile the attacks are automated and indiscriminate: leaked secrets on GitHub, unpatched npm/PyPI packages, public S3 buckets, SSH open to the world, databases without backups.

`scnr` exists to close that gap with a single static binary that:

- scans everything you own from one command: source tree, lockfiles, container images, Dockerfiles/Terraform/Kubernetes, hosts, networks, web apps, and AWS posture;
- is safe by construction — read-only checks, rate limits, scope allow/deny lists, dial-time DNS-rebinding protection, and secret redaction before anything is stored (see [SAFETY.md](SAFETY.md));
- refuses to scan what you have not proven you own (public targets need ownership verification or interactive consent);
- works offline and in CI, with signed offline vulnerability bundles and policy gating (exit non-zero when your policy fails);
- speaks open formats: HTML, JSON, SARIF (GitHub code scanning), Markdown, CSV, and CycloneDX SBOMs.

## Installation

### Prebuilt binary (recommended)

Download the latest release for your platform (single static binary, no runtime dependencies):

```sh
# macOS (Apple Silicon)
curl -L -o scnr https://github.com/iamstoick/scnr/releases/latest/download/scnr-darwin-arm64
# Linux (x86_64)
curl -L -o scnr https://github.com/iamstoick/scnr/releases/latest/download/scnr-linux-amd64

chmod +x scnr
./scnr version
```

Verify the download against the published checksums:

```sh
curl -L -o checksums.txt https://github.com/iamstoick/scnr/releases/latest/download/checksums.txt
shasum -a 256 -c checksums.txt
```

### From source

Prerequisites: Go 1.26+.

```sh
git clone https://github.com/iamstoick/scnr.git
cd scnr
go build -o scnr ./cmd/scnr
./scnr version
```

A stripped release-style build (much smaller, ~62 MiB with the AWS engine):

```sh
CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=0.1.0" -o scnr ./cmd/scnr
```

### Optional external tools

`scnr` has native engines for everything, and can also drive these tools when they are on your `PATH` (missing tools degrade to `skipped`, never silently):

| Tool | Used for |
|---|---|
| `nmap` | TCP port/service discovery |
| `nuclei` | HTTP template matching (safe templates only, no redirects) |
| `semgrep` | Static analysis with local rules or `p/default` |
| `trivy` | Vulnerabilities, misconfigurations, secrets in repos and images |
| `grype` | Image vulnerability matching |
| `prowler` | AWS checks alongside the native engine (no fixers/uploads) |

Check what `scnr` sees, with install guidance that never runs anything itself:

```sh
scnr doctor
scnr doctor --install-guide
scnr doctor --online   # also probe osv.dev and feed hosts
```

### First run

```sh
scnr scope init   # records your authorization acknowledgment in scnr.yaml
scnr scan         # no target? an interactive wizard walks you through it
```

## Usage

```
scnr scan [TARGET...]
```

Targets are auto-detected: `https://…` URLs, hostnames/IPs, CIDRs (`10.0.0.0/24`), local paths, `docker save` tarballs (`*.tar`, `*.tar.gz`, `*.tgz`), and `aws://` cloud accounts. Reports land in `./scnr-out/<scan-id>/` (HTML + JSON by default).

### Scan your code (secrets, SCA, IaC, code checks)

```sh
# Current directory, HTML + JSON report
scnr scan .

# A repo, CI-style: no prompts, JSON only, explicit ack
scnr scan ./myrepo --format json --out out/ --non-interactive --ack-authorized

# Only secrets and dependency CVEs, skip everything else
scnr scan ./myrepo --engines secrets,sca --ack-authorized --non-interactive

# Fully offline: no osv.dev contact (uses a loaded bundle, or skips SCA honestly)
scnr scan ./myrepo --offline --ack-authorized --non-interactive

# Fail the build if any engine was skipped or failed
scnr scan ./myrepo --strict --ack-authorized --non-interactive
```

### Scan a container image

```sh
# From a docker save tarball (auto-detected)
docker save myapp:latest -o myapp.tar
scnr scan myapp.tar --ack-authorized --non-interactive

# From an OCI layout directory (needs the type override)
scnr scan ./myimage-layout --type image --ack-authorized --non-interactive
```

Registry pulls are deliberately not supported — tools would fetch through their own network stacks. `docker save` first, then scan the file.

### Scan hosts and networks

```sh
# A host (private ranges just work after acknowledgment)
scnr scan 192.168.1.10 --ack-authorized --non-interactive

# A subnet, quick profile
scnr scan 10.0.0.0/24 --profile quick --ack-authorized --non-interactive

# Custom ports and gentler rate
scnr scan 10.0.0.5 --ports 22,80,8000-8100 --rate 50 --ack-authorized

# Audit a MySQL server (greeting/version always; enumeration with a login)
scnr scan 192.168.0.136 --type host --ports 3306 --auth-file ./auth.yaml --ack-authorized

# Raise above 2x defaults (audited, needs the explicit flag)
scnr scan 10.0.0.0/24 --rate 1000 --i-understand-rate-limits --ack-authorized

# Scan more hosts than the CIDR cap (audited)
scnr scan 10.0.0.0/20 --max-hosts 4096 --ack-authorized --non-interactive

# Skip one noisy adapter for this run
scnr scan 10.0.0.5 --skip-engines adapter:nuclei --ack-authorized
```

### Scan a web app

```sh
scnr scan https://app.example.com --ack-authorized

# With your own extra templates (validated: safe matchers only)
scnr scan https://app.example.com --templates ./my-templates --ack-authorized

# List and validate templates
scnr templates list
scnr templates validate ./my-templates
```

### Actively probe a web app (DAST)

Active checks crawl your app and send inert markers to find reflected
input, open redirects and error disclosure. Opt-in per target: add it to
`scope.intrusive_allow`, and public targets need ownership verification —
interactive consent alone is not enough.

```sh
# Private app (needs intrusive_allow: [10.0.0.0/8] in scnr.yaml)
scnr scan https://app.internal/ --allow-intrusive --ack-authorized

# Authenticated scan (auth.yaml is chmod 600, owned by you)
scnr scan https://app.internal/ --allow-intrusive --auth-file ./auth.yaml

# Explain the gate for a target before scanning
scnr scope check https://app.example/
```

### Prove you own a public target

Public addresses need proof: interactive consent (type the target back) or a 30-day ownership verification.

```sh
# 1. Get a token, publish it as DNS TXT _scnr-verify.example.com
#    or at https://example.com/.well-known/scnr-verify.txt
scnr verify example.com

# 2. Confirm it (recorded for 30 days)
scnr verify example.com --check

# 3. Now non-interactive scans are allowed
scnr scan https://example.com --ack-authorized --non-interactive
```

### Scan an AWS account

```sh
# Default credentials (env, shared config, or CI web identity)
scnr scan aws:// --ack-authorized --non-interactive

# A named profile
scnr scan aws://audit --ack-authorized --non-interactive
```

Before any check, `scnr` calls `sts:GetCallerIdentity`. The account must be listed in `scnr.yaml` (`cloud.aws.accounts`) or typed back interactively. Everything is read-only, rate-limited, and budgeted; ~25 checks cover IAM, S3, EC2, RDS, CloudTrail, and KMS. See [docs/cloud-aws.md](docs/cloud-aws.md), and get the minimal IAM policy with:

```sh
scnr config show --aws-policy
```

### Work with results

```sh
# Re-render an old scan in another format (html,json,md,csv,sarif)
scnr report latest --format sarif --out out/

# Query findings and assets from the local store
scnr findings list --help
scnr findings show <fingerprint>
scnr findings diff <scan-a> <scan-b>
scnr assets list

# Compare against the previous scan right after scanning
scnr scan . --diff latest --ack-authorized --non-interactive

# Suppress known findings going forward
scnr baseline create --from <scan-id>
scnr scan . --baseline baseline.yaml --ack-authorized

# Accept a single finding (fingerprint or rule id), list, revoke
scnr accept <fingerprint-or-rule-id>
scnr accept list
scnr accept revoke <id>
```

### Gate CI with policy-as-code

```sh
# Write a policy (max criticals, minimum score, ...), then:
scnr scan . --policy policy.yaml --ack-authorized --non-interactive  # exits 1 on violation
scnr policy check latest --policy policy.yaml
```

Exit codes: `0` ok · `1` policy violated · `2` usage error · `3` refused (auth/scope/ownership — nothing ran) · `4` all engines failed · `5` partial (`--strict`, or truncated coverage).

### Vulnerability data and offline bundles

```sh
scnr db update          # refresh KEV + EPSS feeds
scnr db status          # what is loaded and how old it is

# Air-gapped flow: on an online machine, build a signed bundle...
scnr db keygen
scnr db bundle build --out ./bundles --ecosystems npm,Go,PyPI,crates.io --sign-key ~/.scnr/bundle-signing.key
scnr db bundle verify ./bundles/scnr-osv-20260101.tar.gz

# ...then load it where there is no network
scnr db update --offline-bundle ./bundles/scnr-osv-20260101.tar.gz
scnr scan ./myrepo --offline --ack-authorized --non-interactive
```

### SBOMs and config

```sh
scnr sbom ./myrepo --out bom.json        # CycloneDX 1.5, lockfiles only, no network
scnr sbom myapp.tar --out bom.json       # from a docker save tarball
scnr config show                         # effective configuration
scnr config show --risk                  # scoring constants
scnr config init                         # write a fresh scnr.yaml
scnr scope check 10.0.0.5                # would this target be allowed?
scnr version
```

### Safety model in brief

- No exploits, brute force, or state-changing checks — ever.
- Every scan needs acknowledged authorization; public targets need ownership proof.
- Scope deny always wins; scope is re-checked at dial time with DNS-rebinding protection.
- Secrets are redacted before they reach evidence, logs, or reports.
- The audit log is append-only; external tools run with argument arrays, minimal environment, and output caps.

The full invariants live in [SAFETY.md](SAFETY.md) — enforced by code and tests, not by policy alone.

## How to help

This is a solo-maintainer project and every contribution matters.

- **Report bugs and false positives** with the target type, profile, and (redacted) output. A minimal reproducer is gold.
- **Send pull requests**: new safe web templates, new read-only AWS checks, new report details, docs, and tests. Please keep the safety bar — run `go test ./...` and read [SAFETY.md](SAFETY.md) first. Anything shaped like an exploit, brute-forcer, or state-changing check will be declined.
- **Improve the docs**: the best contribution for newcomers is fixing the README or `docs/` page that confused you.
- **Try it on your own projects** and share what you find — real-world feedback shapes the roadmap (scheduler/daemon, Azure/GCP, plugins).

If `scnr` saves you time or catches something nasty, consider buying the maintainer a coffee: [buymeacoffee.com/stoickthevast](https://buymeacoffee.com/stoickthevast)

## License

Apache License 2.0 — see [LICENSE](LICENSE).

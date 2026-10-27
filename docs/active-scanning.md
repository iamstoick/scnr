# Active checks (`--allow-intrusive`)

Passive scanning reads your site the way a browser first sees it: one GET
plus fixed-path template probes. Active checks go further — the crawler
discovers pages, parameters and forms, and the prober sends inert markers
to find reflected input, open redirects and error disclosure. They are
opt-in, inert by construction, and fenced by a dedicated gate.

## The gate

Active checks run for a URL or single-host target only when **all** of these hold
(CIDR ranges are refused — narrow to one `--type host` address):

1. You passed `--allow-intrusive`.
2. The target matches `scope.intrusive_allow` in `scnr.yaml` (same entry
   grammar as `scope.allow`; empty means nothing runs; `deny` still wins).
3. The target is private — or, for public targets, carries a non-expired
   ownership verification (`scnr verify`). Interactive consent alone is
   **not** enough for active checks on public targets.

`scnr scope check URL` shows the intrusive outcome alongside the gate
decision. When the flag is passed but the gate refuses a target, the scan
prints why, runs passively, and audits the refusal. The outcome lands on
the scan (`intrusive: {ran, targets, probes}`), in an `intrusive` audit
row, and as an "Active checks ran" banner in HTML/JSON reports.

## What runs

- **Crawler**: same-origin only (scheme, host, port), depth 3, 200 URLs,
  50 forms, 500 parameter pairs (`--profile deep` doubles the first three
  and triples the probe budget to 3000). Honors `robots.txt` for
  discovery, dedupes `?page=1..N` and `/items/123`-style series, and caps
  bodies at 1 MiB. Links that look state-changing (`logout`, `delete`,
  `publish`, … — full list in `SAFETY.md`) are inventoried as
  `web.state-changing-get` and never fetched. POST forms are inventoried
  (action + field names) and never submitted.
- **Probes** (≤ 1000 requests/target): one marker per parameter
  (`scnr` + 12 hex chars + `'"<` at most — never a statement, tag, or
  handler). `web.reflected-input` needs an HTML text/attribute context
  (JSON bodies, `<script>` strings and comments don't count);
  `web.open-redirect` places the fixed `scnr-canary.invalid` origin in
  redirect-shaped parameters and reads the refused redirect without
  following it; `web.error-disclosure` is a single quote in a GET
  parameter plus the server's own error text.
- **Budgets**: hitting any cap emits a `*-truncated` finding and marks
  the engine `partial`, so truncated runs never mark findings fixed.
- **MySQL CVE-2012-2122 probe** (host targets): when a greeting parses
  as MySQL 5.0–5.5, up to 300 wrong-password logins as `root` with a
  random password — success is only possible through the memcmp
  fail-open bug. No SQL is ever issued, and modern versions get zero
  login attempts. Reported as `net.mysql.cve-2012-2122` (critical).

Everything is GET or HEAD except `safety: intrusive` templates you supply
via `--templates` (POST, bodies ≤ 4 KiB, validated at load). Nuclei is
unaffected by the flag — its `dos,fuzz,intrusive,bruteforce,dast`
exclusions stay exactly as they are.

## Authenticated scanning

```yaml
# auth.yaml — chmod 600, owned by you
headers:
  Authorization: "Bearer …"
cookies:
  session: "…"
mysql:
  user: auditor
  password: "…"
```

```sh
scnr scan https://app.example/ --allow-intrusive --auth-file auth.yaml
scnr scan 192.168.0.136 --type host --ports 3306 --auth-file auth.yaml --ack-authorized
```

The file must be mode `0600`, owned by you, and not a symlink; `--header
"Name: value"` / `--cookie "name=value"` flags exist for interactive use
(schedules refuse them — scheduled authenticated scans use `--auth-file`,
which the daemon re-reads every run). Credentials go only to the target
origin (redirects elsewhere travel clean), values are masked everywhere
as literals, and the audit trail keeps only `auth: true` plus a hash. If
the server clears the session cookie mid-scan, probing stops with
`web.session-invalidated` instead of continuing anonymously.

## Examples

```sh
# Intrusive scan of a private app (needs intrusive_allow: [10.0.0.0/8])
scnr scan https://app.internal/ --allow-intrusive

# Verified public target with auth
scnr verify app.example && scnr scan https://app.example/ \
  --allow-intrusive --auth-file ./auth.yaml

# Nightly authenticated crawl (daemon re-reads the auth file per run)
scnr schedule add --name nightly --cron "0 2 * * *" -- \
  scan https://app.internal/ --allow-intrusive --auth-file /home/you/auth.yaml

# Explain the gate for a target before scanning
scnr scope check https://app.example/

# MySQL audit: greeting/version always; login enumeration with --auth-file
scnr scan 192.168.0.136 --type host --ports 3306 --auth-file ./auth.yaml --ack-authorized

# Add the CVE-2012-2122 probe (needs intrusive_allow, single host only)
scnr scan 192.168.0.136 --type host --ports 3306 --allow-intrusive --ack-authorized
```

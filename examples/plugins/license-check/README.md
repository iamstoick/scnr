# license-check — example scnr plugin

A minimal plugin: finds npm packages without a license field and roots
without a LICENSE file. It is also the protocol reference — copy this
directory to start your own plugin.

## The protocol

A plugin is a directory (or `.tar.gz`) with three files:

- `manifest.json` — name, version, capabilities, rules (this file, minus
  `binary_sha256`, which signing adds)
- `manifest.sig` — base64 ed25519 signature over the manifest bytes
- `scnr-plugin-<name>` — the executable

The binary takes one subcommand:

- `manifest` — print the manifest JSON (≤ 64 KiB, for debugging)
- `run` — read one JSON request from stdin, write JSONL findings to stdout

Request:

```json
{"protocol":1,"target":{"type":"path","value":"/abs/dir"},
 "scratch":"/tmp/.../plugin-license-check","profile":"standard",
 "deadline":"2026-10-12T12:00:00Z","broker":""}
```

`broker` is a Unix socket path when the manifest asks for
`network: broker` and the target is a URL or host, else `""`. Findings:

```json
{"rule":"unlicensed-package","location":"pkg/package.json",
 "confidence":"firm","cves":[],"references":[],
 "evidence":[{"kind":"package","location":"pkg/package.json","text":"…"}]}
```

Rules are namespaced to `plugin.<name>.<rule>`; `rule` must be declared
in the manifest. Unknown JSON fields are rejected. Limits: 50,000
findings, 1 MiB per line, 10 evidence items of 4 KiB each, 256 MiB total
stdout. The child runs with stdin closed after the request, cwd, HOME
and TMPDIR set to its scratch dir, stdout capped, stderr tailed, and —
on Linux/macOS — inside bwrap/sandbox-exec with the target read-only
and no network. It MUST exit 0 on success (findings or none); non-zero
fails the engine with a redacted stderr tail.

Findings locations: relative paths under the target for path scans
(absolute paths inside the target are relativised; anything else is
dropped), same-origin URLs for URL scans. KEV/EPSS/CVSS are computed by
scnr — anything the plugin claims there is ignored.

The broker (when present) speaks newline-delimited JSON over the Unix
socket: `{"id","method":"GET"|"HEAD","url","headers"}` with headers
limited to `Accept`, `Accept-Language` and a `User-Agent` suffix.
`Authorization`/`Cookie`/`Host` are rejected. Responses carry status,
headers (`Set-Cookie` stripped) and base64 body (≤ 1 MiB), or an error:
`E_BAD_REQUEST`, `E_FORBIDDEN_HEADER`, `E_SCOPE_NOT_ALLOWED`,
`E_FETCH_FAILED`, `E_BODY_TOO_LARGE`, `E_BUDGET_EXCEEDED` (500/run).

## Build, sign, install

```sh
cd examples/plugins/license-check

# 1. Build (any language; this one is stdlib-only Go)
go build -o scnr-plugin-license-check main.go

# 2. Create a signing key once (shared with offline bundles)
scnr db keygen --out ~/.scnr/plugin-sign.key
# add the printed ed25519:... line to scnr.yaml plugins.trusted_keys

# 3. Stamp binary_sha256 into the manifest and sign it
scnr plugin sign . --key ~/.scnr/plugin-sign.key

# 4. Install (verifies the signature against trusted_keys)
scnr plugin install .

# 5. Scan — it runs as engine plugin:license-check
scnr scan ./myrepo --ack-authorized
```

Run without a signature only for local development: set
`require_signature: false`, stamp the payload hash into the manifest by
hand (`shasum -a 256 scnr-plugin-license-check`), then `plugin install
--allow-unsigned` on a terminal (you type the manifest hash back to
confirm).

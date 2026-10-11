# Scheduled scans and the daemon

`scnr` can run scans on its own: store a scan once, and the daemon runs it
on a cron schedule under exactly the same safety rules as a manual scan —
non-interactively, one at a time, with the scope file re-read and
credentials rebuilt for every run.

## Schedules

```sh
# Every Monday at 02:00. Fires at most hourly; schedules never run
# more often than that, no matter what the cron says.
scnr schedule add --name weekly --cron "0 2 * * 1" -- scan 10.0.0.0/24 --profile standard

# Shorter forms: @hourly, @daily, @weekly, @monthly.
scnr schedule add --name web --cron "@daily" -- scan https://app.example.com

scnr schedule list
scnr schedule show weekly     # full stored argv, last run, next run
scnr schedule disable weekly  # kept, not run
scnr schedule enable weekly   # next run recomputed from now
scnr schedule remove weekly
```

What a schedule may and may not carry:

- The stored argv must start with `scan` and name at least one target.
- `--ack-authorized` is refused: authorization comes from the standing
  record (`scnr scope init`), never from a stored flag. Removing the
  acknowledgment later refuses subsequent runs.
- `--header`, `--cookie` and `--non-interactive` are refused
  (secret-bearing and redundant for unattended runs), as is any unknown
  flag and any target URL carrying credentials.
- The stored argv is re-validated before **every** run, so rows edited
  directly in the database get no free pass.

Public targets need what a manual scan needs: scope allow-listing and a
live ownership verification (or interactive confirmation, which the
daemon cannot do — unverified public targets are refused and skipped).

## The daemon

```sh
# Run due schedules now, once each, then exit (exit 0 even when a
# schedule refuses or fails; per-schedule status lands in last_status).
scnr daemon run --once

# Stay up: hold the home lock, sleep until the next fire, run one scan
# at a time. Prints one line per run on stdout, usual progress on stderr.
scnr daemon run --notify-url https://relay.internal/scnr

# Reports go to --out/<scan-id>/ unless the stored argv sets its own --out.
scnr daemon run --out /var/lib/scnr/reports
```

Behavior worth knowing:

- One daemon per home: a second `daemon run` exits 2 with the recorded
  pid. `scnr doctor` shows the lock state and schedules due in 24h.
- Each run gets a timeout (profile timeout × engines + 10 minutes) so a
  stuck engine cannot stall the loop; timeouts are recorded, not fatal.
- A fire missed while its own scan is still running is skipped and
  audited (`schedule_skipped`, reason `overlap`) — catch-up runs one,
  never N.
- SIGINT/SIGTERM cancel the in-flight scan, persist every row, release
  the lock, and exit 0.
- Every run is audited (`scan`, `gate_refused`, `schedule_skipped`);
  `scans.meta` records which schedule ran it.

## Notifications

`--notify-url` POSTs one JSON summary per completed scan: schedule name,
scan id, profile, targets, score, grade, counts, exit code and report
paths. Bodies never carry findings or evidence (the shape is pinned by
test). Delivery retries 3 times with backoff; failures are audited, not
fatal.

The URL must be `https://`, or `http://` to a loopback host for local
relays. The client is pinned to the single notify host, never follows
redirects, and is denied the metadata endpoints — and a token in the URL
never appears in errors, logs, or audit rows.

## Running it as a service

scnr 4c ships no installer or supervisor files; point your supervisor at
`scnr daemon run`. Two copy-paste starting points (adjust paths and user):

systemd (`/etc/systemd/system/scnr.service`):

```ini
[Unit]
Description=scnr scheduled scans
After=network-online.target

[Service]
Type=simple
User=scnr
Environment=SCNR_HOME=/var/lib/scnr
ExecStart=/usr/local/bin/scnr daemon run --notify-url https://relay.internal/scnr
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

launchd (`~/Library/LaunchAgents/com.example.scnr.plist`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key><string>com.example.scnr</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/scnr</string>
    <string>daemon</string>
    <string>run</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SCNR_HOME</key><string>/Users/scnr/.scnr</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
```

Keep `SCNR_HOME` (database, lock, audit trail) on a volume the service
user owns, and back it up like any other state: it holds your scan
history and schedule rows.

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

CREATE TABLE findings (
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
CREATE INDEX supp_fp ON suppressions(fingerprint);
CREATE INDEX supp_rule ON suppressions(rule_id, asset_key);

CREATE TABLE verifications (host TEXT PRIMARY KEY, method TEXT NOT NULL, verified_at TEXT NOT NULL, expires_at TEXT NOT NULL);

CREATE TABLE audit_log (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  scan_id TEXT, detail TEXT NOT NULL);
CREATE INDEX audit_ts ON audit_log(ts);

CREATE TABLE kev (cve TEXT PRIMARY KEY, added TEXT NOT NULL, due TEXT, product TEXT);
CREATE TABLE epss (cve TEXT PRIMARY KEY, score REAL NOT NULL, percentile REAL NOT NULL);
CREATE TABLE vuln_cache (id TEXT PRIMARY KEY, body TEXT NOT NULL, fetched_at TEXT NOT NULL);
CREATE TABLE vulndb_meta (source TEXT PRIMARY KEY, updated_at TEXT NOT NULL, version TEXT);

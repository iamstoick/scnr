-- Offline OSV data loaded from a signed bundle (Phase 4a). One row per
-- (vulnerability, package); body is the normalised record so the sca engine
-- needs no second table.
CREATE TABLE osv_affected (id TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
  versions_json TEXT NOT NULL DEFAULT '[]', ranges_json TEXT NOT NULL DEFAULT '[]', body TEXT NOT NULL,
  PRIMARY KEY (ecosystem, name, id));
CREATE INDEX osv_affected_pkg ON osv_affected(ecosystem, name);
CREATE INDEX osv_affected_id ON osv_affected(id);

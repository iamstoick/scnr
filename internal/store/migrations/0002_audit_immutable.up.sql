-- audit_log is append-only (SAFETY.md item 8). Enforce it in the database,
-- not only by convention in store.go: any UPDATE or DELETE aborts.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;

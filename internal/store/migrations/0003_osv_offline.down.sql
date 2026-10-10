DROP INDEX IF EXISTS osv_affected_id;
DROP INDEX IF EXISTS osv_affected_pkg;
DROP TABLE IF EXISTS osv_affected;
DELETE FROM vulndb_meta WHERE source = 'osv-offline';

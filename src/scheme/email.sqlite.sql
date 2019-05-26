DROP TABLE IF EXISTS gs_code;

CREATE TABLE gs_code (
  gsc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gsc_mod_name TEXT NOT NULL,
  gsc_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gsc_username TEXT NOT NULL,
  gsc_enabled INTEGER DEFAULT 1,
  gsc_code_hash TEXT,
  gsc_result INTEGER DEFAULT 0
);
CREATE INDEX i_gsc_username ON gs_code(gsc_username);

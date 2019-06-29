DROP TABLE IF EXISTS gss_code;

CREATE TABLE gs_code (
  gsc_id SERIAL PRIMARY KEY,
  gsc_mod_name VARCHAR(128) NOT NULL,
  gsc_issued_at TIMESTAMP NOT NULL DEFAULT NOW(),
  gsc_username VARCHAR(128) NOT NULL,
  gsc_enabled SMALLINT DEFAULT 1,
  gsc_code_hash VARCHAR(128),
  gsc_result SMALLINT DEFAULT 0
);
CREATE INDEX i_gsc_username ON gs_code(gsc_username);

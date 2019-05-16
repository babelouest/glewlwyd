DROP TABLE IF EXISTS gs_webauthn_credential;
DROP TABLE IF EXISTS gs_webauthn_user;

CREATE TABLE gs_webauthn_user (
  gswu_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gswu_username TEXT NOT NULL UNIQUE,
  gswu_user_id TEXT NOT NULL
);
CREATE INDEX i_gswu_username ON gs_webauthn_user(gswu_username);

CREATE TABLE gs_webauthn_credential (
  gswc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gswu_id INTEGER NOT NULL,
  gswc_session_hash TEXT NOT NULL,
  gswc_name TEXT,
  gswc_challenge_hash TEXT,
  gswc_credential_id TEXT,
  gswc_public_key BLOB DEFAULT NULL,
  gswc_created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gswc_last_seen TIMESTAMP,
  gswc_status INTEGER DEFAULT 0, -- 0 new, 1 registered, 2 error, 3 closed, 4 cancelled
  FOREIGN KEY(gswu_id) REFERENCES gs_webauthn_user(gswu_id) ON DELETE CASCADE
);
CREATE INDEX i_gswc_credential_id ON gs_webauthn_credential(gswc_credential_id);

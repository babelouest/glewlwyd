DROP TABLE IF EXISTS gs_webauthn_assertion;
DROP TABLE IF EXISTS gs_webauthn_credential;
DROP TABLE IF EXISTS gs_webauthn_user;

CREATE TABLE gs_webauthn_user (
  gswu_id SERIAL PRIMARY KEY,
  gswu_username VARCHAR(128) UNIQUE NOT NULL,
  gswu_user_id VARCHAR(128) NOT NULL
);
CREATE INDEX i_gswu_username ON gs_webauthn_user(gswu_username);

CREATE TABLE gs_webauthn_credential (
  gswc_id SERIAL PRIMARY KEY,
  gswu_id INTEGER NOT NULL,
  gswc_session_hash VARCHAR(128) NOT NULL,
  gswc_name VARCHAR(128),
  gswc_challenge_hash VARCHAR(128),
  gswc_credential_id VARCHAR(256),
  gswc_public_key TEXT DEFAULT NULL,
  gswc_created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  gswc_status SMALLINT DEFAULT 0, -- 0 new, 1 registered, 2 error, 3 closed, 4 cancelled
  FOREIGN KEY(gswu_id) REFERENCES gs_webauthn_user(gswu_id) ON DELETE CASCADE
);
CREATE INDEX i_gswc_public_key ON gs_webauthn_credential(gswc_public_key);
CREATE INDEX i_gswc_session_hash ON gs_webauthn_credential(gswc_session_hash);

CREATE TABLE gs_webauthn_assertion (
  gswa_id SERIAL PRIMARY KEY,
  gswu_id INTEGER NOT NULL,
  gswc_id INTEGER,
  gswa_session_hash VARCHAR(128) NOT NULL,
  gswa_challenge_hash VARCHAR(128),
  gswa_status SMALLINT DEFAULT 0, -- 0 new, 1 verified, 2 not verified, 3 error, 4 cancelled
  FOREIGN KEY(gswu_id) REFERENCES gs_webauthn_user(gswu_id) ON DELETE CASCADE,
  FOREIGN KEY(gswc_id) REFERENCES gs_webauthn_credential(gswc_id) ON DELETE CASCADE
);
CREATE INDEX i_gswa_session_hash ON gs_webauthn_assertion(gswa_session_hash);

DROP TABLE IF EXISTS gs_webauthn_assertion;
DROP TABLE IF EXISTS gs_webauthn_credential;
DROP TABLE IF EXISTS gs_webauthn_user;

CREATE TABLE gs_webauthn_user (
  gswu_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gswu_username VARCHAR(128) UNIQUE NOT NULL,
  gswu_user_id VARCHAR(128) NOT NULL
);
CREATE INDEX i_gswu_username ON gs_webauthn_user(gswu_username);

CREATE TABLE gs_webauthn_credential (
  gswc_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gswu_id INT(11) NOT NULL,
  gswc_session_hash VARCHAR(128) NOT NULL,
  gswc_name VARCHAR(128),
  gswc_challenge_hash VARCHAR(128),
  gswc_credential_id VARCHAR(256),
  gswc_certificate TEXT DEFAULT NULL,
  gswc_public_key TEXT DEFAULT NULL,
  gswc_counter INT(11) DEFAULT 0,
  gswc_created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gswc_status TINYINT(1) DEFAULT 0, -- 0 new, 1 registered, 2 error, 3 disabled, 4 removed
  FOREIGN KEY(gswu_id) REFERENCES gs_webauthn_user(gswu_id) ON DELETE CASCADE
);
CREATE INDEX i_gswc_credential_id ON gs_webauthn_credential(gswc_credential_id);
CREATE INDEX i_gswc_session_hash ON gs_webauthn_credential(gswc_session_hash);

CREATE TABLE gs_webauthn_assertion (
  gswa_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gswu_id INT(11) NOT NULL,
  gswc_id INT(11),
  gswa_session_hash VARCHAR(128) NOT NULL,
  gswa_challenge_hash VARCHAR(128),
  gswa_counter INT(11) DEFAULT 0,
  gswa_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gswa_status TINYINT(1) DEFAULT 0, -- 0 new, 1 verified, 2 not verified, 3 error
  gswa_mock TINYINT(1) DEFAULT 0,
  FOREIGN KEY(gswu_id) REFERENCES gs_webauthn_user(gswu_id) ON DELETE CASCADE,
  FOREIGN KEY(gswc_id) REFERENCES gs_webauthn_credential(gswc_id) ON DELETE CASCADE
);
CREATE INDEX i_gswa_session_hash ON gs_webauthn_assertion(gswa_session_hash);

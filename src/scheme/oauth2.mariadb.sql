DROP TABLE IF EXISTS gs_oauth2_session;

CREATE TABLE gs_oauth2_session (
  gsos_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gsos_mod_name VARCHAR(128) NOT NULL,
  gsos_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gsos_username VARCHAR(128) NOT NULL,
  gsos_enabled TINYINT(1) DEFAULT 1,
  gsos_session_export TEXT
);
CREATE INDEX i_gsos_username ON gs_oauth2_session(gsos_username);

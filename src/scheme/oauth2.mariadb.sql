DROP TABLE IF EXISTS gs_oauth2_session;
DROP TABLE IF EXISTS gs_oauth2_registration;

CREATE TABLE gs_oauth2_registration (
  gsor_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gsor_mod_name VARCHAR(128) NOT NULL,
  gsor_provider VARCHAR(128) NOT NULL,
  gsor_created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gsor_username VARCHAR(128) NOT NULL,
  gsor_userinfo_sub VARCHAR(128),
  gsor_enabled TINYINT(1) DEFAULT 1
);
CREATE INDEX i_gsor_username ON gs_oauth2_registration(gsor_username);

CREATE TABLE gs_oauth2_session (
  gsos_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gsor_id INT(11),
  gsos_created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gsos_expires_at TIMESTAMP,
  gsos_state TEXT NOT NULL,
  gsos_session_export TEXT,
  gsos_status TINYINT(1) DEFAULT 0, -- 0: disabled, 1: registration, 2: authentication
  FOREIGN KEY(gsor_id) REFERENCES gs_oauth2_registration(gsor_id) ON DELETE CASCADE
);

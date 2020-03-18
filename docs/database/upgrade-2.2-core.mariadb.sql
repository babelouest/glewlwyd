-- Upgrade Glewlwyd 2.0.x or 2.1.x to 2.2.0

ALTER TABLE g_user_module_instance
ADD gumi_enabled TINYINT(1) DEFAULT 1;

ALTER TABLE g_user_auth_scheme_module_instance
ADD guasmi_enabled TINYINT(1) DEFAULT 1;

ALTER TABLE g_client_module_instance
ADD gcmi_enabled TINYINT(1) DEFAULT 1;

ALTER TABLE g_plugin_module_instance
ADD gpmi_enabled TINYINT(1) DEFAULT 1;

ALTER TABLE gpg_code
ADD gpgc_code_challenge VARCHAR(128);
CREATE INDEX i_gpgc_code_challenge ON gpg_code(gpgc_code_challenge);

ALTER TABLE gpg_access_token
ADD gpga_token_hash VARCHAR(512) NOT NULL DEFAULT '', 
ADD gpga_enabled TINYINT(1) DEFAULT 1;
CREATE INDEX i_gpga_token_hash ON gpg_access_token(gpga_token_hash);

ALTER TABLE gpo_code
ADD gpoc_code_challenge VARCHAR(128);
CREATE INDEX i_gpoc_code_challenge ON gpo_code(gpoc_code_challenge);

ALTER TABLE gpo_access_token
ADD gpoa_token_hash VARCHAR(512) NOT NULL DEFAULT '', 
ADD gpoa_enabled TINYINT(1) DEFAULT 1;
CREATE INDEX i_gpoa_token_hash ON gpo_access_token(gpoa_token_hash);

ALTER TABLE gpo_id_token
ADD gpoi_enabled TINYINT(1) DEFAULT 1;
CREATE INDEX i_gpoi_hash ON gpo_id_token(gpoi_hash);

-- store meta information on client registration
CREATE TABLE gpo_client_registration (
  gpocr_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpocr_plugin_name VARCHAR(256) NOT NULL,
  gpocr_cient_id VARCHAR(256) NOT NULL,
  gpocr_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoa_id INT(11),
  gpocr_issued_for VARCHAR(256), -- IP address or hostname
  gpocr_user_agent VARCHAR(256),
  FOREIGN KEY(gpoa_id) REFERENCES gpo_access_token(gpoa_id) ON DELETE CASCADE
);

CREATE TABLE gs_oauth2_registration (
  gsor_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gsor_mod_name VARCHAR(128) NOT NULL,
  gsor_provider VARCHAR(128) NOT NULL,
  gsor_created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gsor_username VARCHAR(128) NOT NULL,
  gsor_userinfo_sub VARCHAR(128)
);
CREATE INDEX i_gsor_username ON gs_oauth2_registration(gsor_username);

CREATE TABLE gs_oauth2_session (
  gsos_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gsor_id INT(11),
  gsos_created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gsos_expires_at TIMESTAMP,
  gsos_state TEXT NOT NULL,
  gsos_session_export TEXT,
  gsos_status TINYINT(1) DEFAULT 0, -- 0: registration, 1: authentication, 2: verified, 3: cancelled
  FOREIGN KEY(gsor_id) REFERENCES gs_oauth2_registration(gsor_id) ON DELETE CASCADE
);

-- store meta information about client request on token endpoint
CREATE TABLE gpo_client_token_request (
  gpoctr_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoctr_plugin_name VARCHAR(256) NOT NULL,
  gpoctr_cient_id VARCHAR(256) NOT NULL,
  gpoctr_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoctr_issued_for VARCHAR(256), -- IP address or hostname
  gpoctr_jti_hash VARCHAR(512)
);

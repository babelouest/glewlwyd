DROP TABLE IF EXISTS gpo_ciba_scope;
DROP TABLE IF EXISTS gpo_ciba_scheme;
DROP TABLE IF EXISTS gpo_ciba;
DROP TABLE IF EXISTS gpo_par_scope;
DROP TABLE IF EXISTS gpo_par;
DROP TABLE IF EXISTS gpo_rar;
DROP TABLE IF EXISTS gpo_dpop;
DROP TABLE IF EXISTS gpo_client_registration;
DROP TABLE IF EXISTS gpo_subject_identifier;
DROP TABLE IF EXISTS gpo_id_token;
DROP TABLE IF EXISTS gpo_access_token_scope;
DROP TABLE IF EXISTS gpo_access_token;
DROP TABLE IF EXISTS gpo_refresh_token_scope;
DROP TABLE IF EXISTS gpo_refresh_token;
DROP TABLE IF EXISTS gpo_code_scheme;
DROP TABLE IF EXISTS gpo_code_scope;
DROP TABLE IF EXISTS gpo_code;
DROP TABLE IF EXISTS gpo_client_token_request;
DROP TABLE IF EXISTS gpo_device_scheme;
DROP TABLE IF EXISTS gpo_device_authorization_scope;
DROP TABLE IF EXISTS gpo_device_authorization;

CREATE TABLE gpo_code (
  gpoc_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoc_plugin_name VARCHAR(256) NOT NULL,
  gpoc_authorization_type INT(2) NOT NULL,
  gpoc_username VARCHAR(256) NOT NULL,
  gpoc_client_id VARCHAR(256) NOT NULL,
  gpoc_redirect_uri VARCHAR(512) NOT NULL,
  gpoc_code_hash VARCHAR(512) NOT NULL,
  gpoc_nonce VARCHAR(512),
  gpoc_resource VARCHAR(512),
  gpoc_claims_request BLOB DEFAULT NULL,
  gpoc_authorization_details BLOB DEFAULT NULL,
  gpoc_s_hash VARCHAR(512),
  gpoc_sid VARCHAR(128),
  gpoc_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpoc_issued_for VARCHAR(256), -- IP address or hostname
  gpoc_user_agent VARCHAR(256),
  gpoc_code_challenge VARCHAR(128),
  gpoc_enabled TINYINT(1) DEFAULT 1
);
CREATE INDEX i_gpoc_code_hash ON gpo_code(gpoc_code_hash);
CREATE INDEX i_gpoc_code_challenge ON gpo_code(gpoc_code_challenge);

CREATE TABLE gpo_code_scope (
  gpocs_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoc_id INT(11),
  gpocs_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE
);

CREATE TABLE gpo_code_scheme (
  gpoch_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoc_id INT(11),
  gpoch_scheme_module VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE
);

CREATE TABLE gpo_refresh_token (
  gpor_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpor_plugin_name VARCHAR(256) NOT NULL,
  gpor_authorization_type INT(2) NOT NULL,
  gpoc_id INT(11) DEFAULT NULL,
  gpor_username VARCHAR(256) NOT NULL,
  gpor_client_id VARCHAR(256),
  gpor_resource VARCHAR(512),
  gpor_claims_request BLOB DEFAULT NULL,
  gpor_authorization_details BLOB DEFAULT NULL,
  gpor_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_duration INT(11),
  gpor_rolling_expiration TINYINT(1) DEFAULT 0,
  gpor_issued_for VARCHAR(256), -- IP address or hostname
  gpor_user_agent VARCHAR(256),
  gpor_token_hash VARCHAR(512) NOT NULL,
  gpor_jti VARCHAR(128),
  gpor_dpop_jkt VARCHAR(512),
  gpor_enabled TINYINT(1) DEFAULT 1,
  FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE
);
CREATE INDEX i_gpor_token_hash ON gpo_refresh_token(gpor_token_hash);
CREATE INDEX i_gpor_jti ON gpo_refresh_token(gpor_jti);

CREATE TABLE gpo_refresh_token_scope (
  gpors_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpor_id INT(11),
  gpors_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE
);

-- Access token table, to store meta information on access token sent
CREATE TABLE gpo_access_token (
  gpoa_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoa_plugin_name VARCHAR(256) NOT NULL,
  gpoa_authorization_type INT(2) NOT NULL,
  gpor_id INT(11) DEFAULT NULL,
  gpoa_username VARCHAR(256),
  gpoa_client_id VARCHAR(256),
  gpoa_resource VARCHAR(512),
  gpoa_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoa_issued_for VARCHAR(256), -- IP address or hostname
  gpoa_user_agent VARCHAR(256),
  gpoa_token_hash VARCHAR(512) NOT NULL,
  gpoa_jti VARCHAR(128),
  gpoa_authorization_details BLOB DEFAULT NULL,
  gpoa_enabled TINYINT(1) DEFAULT 1,
  FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE
);
CREATE INDEX i_gpoa_token_hash ON gpo_access_token(gpoa_token_hash);
CREATE INDEX i_gpoa_jti ON gpo_access_token(gpoa_jti);

CREATE TABLE gpo_access_token_scope (
  gpoas_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoa_id INT(11),
  gpoas_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpoa_id) REFERENCES gpo_access_token(gpoa_id) ON DELETE CASCADE
);

-- Id token table, to store meta information on id token sent
CREATE TABLE gpo_id_token (
  gpoi_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoc_id INT(11),
  gpor_id INT(11),
  gpoi_plugin_name VARCHAR(256) NOT NULL,
  gpoi_authorization_type INT(2) NOT NULL,
  gpoi_username VARCHAR(256),
  gpoi_client_id VARCHAR(256),
  gpoi_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoi_issued_for VARCHAR(256), -- IP address or hostname
  gpoi_user_agent VARCHAR(256),
  gpoi_hash VARCHAR(512),
  gpoi_sid VARCHAR(128),
  gpoi_enabled TINYINT(1) DEFAULT 1,
  FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE,
  FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE
);
CREATE INDEX i_gpoi_hash ON gpo_id_token(gpoi_hash);

-- subject identifier table to store subs and their relations to usernames, client_id and sector_identifier
CREATE TABLE gpo_subject_identifier (
  gposi_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gposi_plugin_name VARCHAR(256) NOT NULL,
  gposi_username VARCHAR(256) NOT NULL,
  gposi_client_id VARCHAR(256),
  gposi_sector_identifier_uri VARCHAR(256),
  gposi_sub VARCHAR(256) NOT NULL
);
CREATE INDEX i_gposi_sub ON gpo_subject_identifier(gposi_sub);

-- store meta information on client registration
CREATE TABLE gpo_client_registration (
  gpocr_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpocr_plugin_name VARCHAR(256) NOT NULL,
  gpocr_cient_id VARCHAR(256) NOT NULL,
  gpocr_management_at_hash VARCHAR(512),
  gpocr_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoa_id INT(11),
  gpocr_issued_for VARCHAR(256), -- IP address or hostname
  gpocr_user_agent VARCHAR(256),
  FOREIGN KEY(gpoa_id) REFERENCES gpo_access_token(gpoa_id) ON DELETE CASCADE
);
CREATE INDEX i_gpocr_management_at_hash ON gpo_client_registration(gpocr_management_at_hash);

-- store meta information about client request on token endpoint
CREATE TABLE gpo_client_token_request (
  gpoctr_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoctr_plugin_name VARCHAR(256) NOT NULL,
  gpoctr_cient_id VARCHAR(256) NOT NULL,
  gpoctr_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoctr_issued_for VARCHAR(256), -- IP address or hostname
  gpoctr_jti_hash VARCHAR(512)
);

-- store device authorization requests
CREATE TABLE gpo_device_authorization (
  gpoda_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoda_plugin_name VARCHAR(256) NOT NULL,
  gpoda_client_id VARCHAR(256) NOT NULL,
  gpoda_resource VARCHAR(512),
  gpoda_username VARCHAR(256),
  gpoda_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoda_expires_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoda_issued_for VARCHAR(256), -- IP address or hostname of the deice client
  gpoda_device_code_hash VARCHAR(512) NOT NULL,
  gpoda_user_code_hash VARCHAR(512) NOT NULL,
  gpoda_sid VARCHAR(128),
  gpoda_status TINYINT(1) DEFAULT 0, -- 0: created, 1: user verified, 2 device completed, 3 disabled
  gpoda_authorization_details BLOB DEFAULT NULL,
  gpoda_last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX i_gpoda_device_code_hash ON gpo_device_authorization(gpoda_device_code_hash);
CREATE INDEX i_gpoda_user_code_hash ON gpo_device_authorization(gpoda_user_code_hash);

CREATE TABLE gpo_device_authorization_scope (
  gpodas_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoda_id INT(11),
  gpodas_scope VARCHAR(128) NOT NULL,
  gpodas_allowed TINYINT(1) DEFAULT 0,
  FOREIGN KEY(gpoda_id) REFERENCES gpo_device_authorization(gpoda_id) ON DELETE CASCADE
);

CREATE TABLE gpo_device_scheme (
  gpodh_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoda_id INT(11),
  gpodh_scheme_module VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpoda_id) REFERENCES gpo_device_authorization(gpoda_id) ON DELETE CASCADE
);

CREATE TABLE gpo_dpop (
  gpod_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpod_plugin_name VARCHAR(256) NOT NULL,
  gpod_client_id VARCHAR(256) NOT NULL,
  gpod_jti_hash VARCHAR(512) NOT NULL,
  gpod_jkt VARCHAR(512) NOT NULL,
  gpod_htm VARCHAR(128) NOT NULL,
  gpod_htu VARCHAR(512) NOT NULL,
  gpod_iat TIMESTAMP NOT NULL,
  gpod_last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX i_gpod_jti_hash ON gpo_dpop(gpod_jti_hash);

CREATE TABLE gpo_rar (
  gporar_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gporar_plugin_name VARCHAR(256) NOT NULL,
  gporar_client_id VARCHAR(256) NOT NULL,
  gporar_type VARCHAR(256) NOT NULL,
  gporar_username VARCHAR(256),
  gporar_consent TINYINT(1) DEFAULT 0,
  gporar_enabled TINYINT(1) DEFAULT 1
);
CREATE INDEX i_gporar_client_id ON gpo_rar(gporar_client_id);
CREATE INDEX i_gporar_type ON gpo_rar(gporar_type);
CREATE INDEX i_gporar_username ON gpo_rar(gporar_username);

CREATE TABLE gpo_par (
  gpop_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpop_plugin_name VARCHAR(256) NOT NULL,
  gpop_response_type VARCHAR(128) NOT NULL,
  gpop_state BLOB,
  gpop_username VARCHAR(256),
  gpop_client_id VARCHAR(256) NOT NULL,
  gpop_redirect_uri VARCHAR(512) NOT NULL,
  gpop_request_uri_hash VARCHAR(512) NOT NULL,
  gpop_nonce VARCHAR(512),
  gpop_code_challenge VARCHAR(128),
  gpop_resource VARCHAR(512),
  gpop_claims_request BLOB DEFAULT NULL,
  gpop_authorization_details BLOB DEFAULT NULL,
  gpop_additional_parameters BLOB DEFAULT NULL,
  gpop_status TINYINT(1) DEFAULT 0, -- 0 created, 1 validated, 2 completed
  gpop_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpop_issued_for VARCHAR(256), -- IP address or hostname
  gpop_user_agent VARCHAR(256)
);
CREATE INDEX i_gpop_client_id ON gpo_par(gpop_client_id);
CREATE INDEX i_gpop_request_uri_hash ON gpo_par(gpop_request_uri_hash);
CREATE INDEX i_gpop_code_challenge ON gpo_par(gpop_code_challenge);

CREATE TABLE gpo_par_scope (
  gpops_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpop_id INT(11),
  gpops_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpop_id) REFERENCES gpo_par(gpop_id) ON DELETE CASCADE
);

CREATE TABLE gpo_ciba (
  gpob_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpob_plugin_name VARCHAR(256) NOT NULL,
  gpob_client_id VARCHAR(256) NOT NULL,
  gpob_x5t_s256 VARCHAR(64),
  gpob_username VARCHAR(256) NOT NULL,
  gpob_client_notification_token VARCHAR(1024),
  gpob_jti_hash VARCHAR(512),
  gpob_auth_req_id VARCHAR(128),
  gpob_user_req_id VARCHAR(128),
  gpob_binding_message VARCHAR(256),
  gpob_sid VARCHAR(128),
  gpob_status TINYINT(1) DEFAULT 0, -- 0: created, 1: accepted, 2: error, 3: closed
  gpob_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpob_issued_for VARCHAR(256), -- IP address or hostname
  gpob_user_agent VARCHAR(256),
  gpob_enabled TINYINT(1) DEFAULT 1
);
CREATE INDEX i_gpob_client_id ON gpo_ciba(gpob_client_id);
CREATE INDEX i_gpob_jti_hash ON gpo_ciba(gpob_jti_hash);
CREATE INDEX i_gpob_client_notification_token ON gpo_ciba(gpob_client_notification_token);
CREATE INDEX i_gpob_auth_req_id ON gpo_ciba(gpob_auth_req_id);
CREATE INDEX i_gpob_user_req_id ON gpo_ciba(gpob_user_req_id);

CREATE TABLE gpo_ciba_scope (
  gpocs_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpob_id INT(11),
  gpops_scope VARCHAR(128) NOT NULL,
  gpobs_granted TINYINT(1) DEFAULT 0,
  FOREIGN KEY(gpob_id) REFERENCES gpo_ciba(gpob_id) ON DELETE CASCADE
);

CREATE TABLE gpo_ciba_scheme (
  gpobh_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpob_id INT(11),
  gpobh_scheme_module VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpob_id) REFERENCES gpo_ciba(gpob_id) ON DELETE CASCADE
);

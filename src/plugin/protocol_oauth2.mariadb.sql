DROP TABLE IF EXISTS gpg_access_token_scope;
DROP TABLE IF EXISTS gpg_access_token;
DROP TABLE IF EXISTS gpg_refresh_token_scope;
DROP TABLE IF EXISTS gpg_refresh_token;
DROP TABLE IF EXISTS gpg_code_scope;
DROP TABLE IF EXISTS gpg_code;
DROP TABLE IF EXISTS gpg_device_authorization_scope;
DROP TABLE IF EXISTS gpg_device_authorization;

CREATE TABLE gpg_code (
  gpgc_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpgc_plugin_name VARCHAR(256) NOT NULL,
  gpgc_username VARCHAR(256) NOT NULL,
  gpgc_client_id VARCHAR(256) NOT NULL,
  gpgc_redirect_uri VARCHAR(512) NOT NULL,
  gpgc_code_hash VARCHAR(512) NOT NULL,
  gpgc_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgc_issued_for VARCHAR(256), -- IP address or hostname
  gpgc_user_agent VARCHAR(256),
  gpgc_code_challenge VARCHAR(128),
  gpgc_enabled TINYINT(1) DEFAULT 1
);
CREATE INDEX i_gpgc_code_hash ON gpg_code(gpgc_code_hash);
CREATE INDEX i_gpgc_code_challenge ON gpg_code(gpgc_code_challenge);

CREATE TABLE gpg_code_scope (
  gpgcs_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpgc_id INT(11),
  gpgcs_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpgc_id) REFERENCES gpg_code(gpgc_id) ON DELETE CASCADE
);

CREATE TABLE gpg_refresh_token (
  gpgr_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpgr_plugin_name VARCHAR(256) NOT NULL,
  gpgr_authorization_type INT(2) NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  gpgc_id INT(11) DEFAULT NULL,
  gpgr_username VARCHAR(256) NOT NULL,
  gpgr_client_id VARCHAR(256),
  gpgr_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgr_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgr_last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgr_duration INT(11),
  gpgr_rolling_expiration TINYINT(1) DEFAULT 0,
  gpgr_issued_for VARCHAR(256), -- IP address or hostname
  gpgr_user_agent VARCHAR(256),
  gpgr_token_hash VARCHAR(512) NOT NULL,
  gpgr_enabled TINYINT(1) DEFAULT 1,
  FOREIGN KEY(gpgc_id) REFERENCES gpg_code(gpgc_id) ON DELETE CASCADE
);
CREATE INDEX i_gpgr_token_hash ON gpg_refresh_token(gpgr_token_hash);

CREATE TABLE gpg_refresh_token_scope (
  gpgrs_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpgr_id INT(11),
  gpgrs_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpgr_id) REFERENCES gpg_refresh_token(gpgr_id) ON DELETE CASCADE
);

-- Access token table, to store meta information on access token sent
CREATE TABLE gpg_access_token (
  gpga_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpga_plugin_name VARCHAR(256) NOT NULL,
  gpga_authorization_type INT(2) NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  gpgr_id INT(11) DEFAULT NULL,
  gpga_username VARCHAR(256),
  gpga_client_id VARCHAR(256),
  gpga_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpga_issued_for VARCHAR(256), -- IP address or hostname
  gpga_user_agent VARCHAR(256),
  gpga_token_hash VARCHAR(512) NOT NULL,
  gpga_enabled TINYINT(1) DEFAULT 1,
  FOREIGN KEY(gpgr_id) REFERENCES gpg_refresh_token(gpgr_id) ON DELETE CASCADE
);
CREATE INDEX i_gpga_token_hash ON gpg_access_token(gpga_token_hash);

CREATE TABLE gpg_access_token_scope (
  gpgas_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpga_id INT(11),
  gpgas_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpga_id) REFERENCES gpg_access_token(gpga_id) ON DELETE CASCADE
);

-- store device authorization requests
CREATE TABLE gpg_device_authorization (
  gpgda_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpgda_plugin_name VARCHAR(256) NOT NULL,
  gpgda_client_id VARCHAR(256) NOT NULL,
  gpgda_username VARCHAR(256),
  gpgda_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpgda_expires_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpgda_issued_for VARCHAR(256), -- IP address or hostname of the deice client
  gpgda_device_code_hash VARCHAR(512) NOT NULL,
  gpgda_user_code_hash VARCHAR(512) NOT NULL,
  gpgda_status TINYINT(1) DEFAULT 0, -- 0: created, 1: user verified, 2 device completed, 3 disabled
  gpgda_last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX i_gpgda_device_code_hash ON gpg_device_authorization(gpgda_device_code_hash);
CREATE INDEX i_gpgda_user_code_hash ON gpg_device_authorization(gpgda_user_code_hash);

CREATE TABLE gpg_device_authorization_scope (
  gpgdas_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpgda_id INT(11),
  gpgdas_scope VARCHAR(128) NOT NULL,
  gpgdas_allowed TINYINT(1) DEFAULT 0,
  FOREIGN KEY(gpgda_id) REFERENCES gpg_device_authorization(gpgda_id) ON DELETE CASCADE
);

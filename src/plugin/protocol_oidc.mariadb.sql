DROP TABLE IF EXISTS gpo_subject_identifier;
DROP TABLE IF EXISTS gpo_id_token_scope;
DROP TABLE IF EXISTS gpo_id_token;
DROP TABLE IF EXISTS gpo_access_token_scope;
DROP TABLE IF EXISTS gpo_access_token;
DROP TABLE IF EXISTS gpo_refresh_token_scope;
DROP TABLE IF EXISTS gpo_refresh_token;
DROP TABLE IF EXISTS gpo_code_scheme;
DROP TABLE IF EXISTS gpo_code_scope;
DROP TABLE IF EXISTS gpo_code;

CREATE TABLE gpo_code (
  gpoc_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoc_plugin_name VARCHAR(256) NOT NULL,
  gpoc_authorization_type INT(2) NOT NULL,
  gpoc_username VARCHAR(256) NOT NULL,
  gpoc_client_id VARCHAR(256) NOT NULL,
  gpoc_redirect_uri VARCHAR(512) NOT NULL,
  gpoc_code_hash VARCHAR(512) NOT NULL,
  gpoc_nonce VARCHAR(512),
  gpoc_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpoc_issued_for VARCHAR(256), -- IP address or hostname
  gpoc_user_agent VARCHAR(256),
  gpoc_enabled TINYINT(1) DEFAULT 1
);
CREATE INDEX i_gpoc_code_hash ON gpo_code(gpoc_code_hash);

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
  gpor_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_duration INT(11),
  gpor_rolling_expiration TINYINT(1) DEFAULT 0,
  gpor_issued_for VARCHAR(256), -- IP address or hostname
  gpor_user_agent VARCHAR(256),
  gpor_token_hash VARCHAR(512) NOT NULL,
  gpor_enabled TINYINT(1) DEFAULT 1,
  FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE
);
CREATE INDEX i_gpor_token_hash ON gpo_refresh_token(gpor_token_hash);

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
  gpoa_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoa_issued_for VARCHAR(256), -- IP address or hostname
  gpoa_user_agent VARCHAR(256),
  FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE
);

CREATE TABLE gpo_access_token_scope (
  gpoas_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoa_id INT(11),
  gpoas_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpoa_id) REFERENCES gpo_access_token(gpoa_id) ON DELETE CASCADE
);

-- Id token table, to store meta information on id token sent
CREATE TABLE gpo_id_token (
  gpoi_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoi_plugin_name VARCHAR(256) NOT NULL,
  gpoi_authorization_type INT(2) NOT NULL,
  gpoi_username VARCHAR(256),
  gpoi_client_id VARCHAR(256),
  gpoi_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoi_issued_for VARCHAR(256), -- IP address or hostname
  gpoi_user_agent VARCHAR(256),
  gpoi_hash VARCHAR(512)
);

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

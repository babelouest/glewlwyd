DROP TABLE IF EXISTS gs_user_pkcs12;

ALTER TABLE gpr_session
ADD gprs_callback_url BLOB DEFAULT NULL;

CREATE TABLE gpr_update_email (
  gprue_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gprue_plugin_name VARCHAR(256) NOT NULL,
  gprue_username VARCHAR(256) NOT NULL,
  gprue_email VARCHAR(512),
  gprue_token_hash VARCHAR(512),
  gprue_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprue_issued_for VARCHAR(256), -- IP address or hostname
  gprue_user_agent VARCHAR(256),
  gprue_enabled TINYINT(1) DEFAULT 1
);
CREATE INDEX i_gprue_token_hash ON gpr_update_email(gprue_token_hash);

CREATE TABLE gpr_reset_credentials_session (
  gprrcs_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gprrcs_plugin_name VARCHAR(256) NOT NULL,
  gprrcs_username VARCHAR(256) NOT NULL,
  gprrcs_session_hash VARCHAR(512),
  gprrcs_callback_url BLOB DEFAULT NULL,
  gprrcs_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprrcs_issued_for VARCHAR(256), -- IP address or hostname
  gprrcs_user_agent VARCHAR(256),
  gprrcs_enabled TINYINT(1) DEFAULT 1
);
CREATE INDEX i_gprrcs_session_hash ON gpr_reset_credentials_session(gprrcs_session_hash);

CREATE TABLE gpr_reset_credentials_email (
  gprrct_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gprrct_plugin_name VARCHAR(256) NOT NULL,
  gprrct_username VARCHAR(256) NOT NULL,
  gprrct_token_hash VARCHAR(512),
  gprrct_callback_url BLOB DEFAULT NULL,
  gprrct_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprrct_issued_for VARCHAR(256), -- IP address or hostname
  gprrct_user_agent VARCHAR(256),
  gprrct_enabled TINYINT(1) DEFAULT 1
);
CREATE INDEX i_gprrct_token_hash ON gpr_reset_credentials_email(gprrct_token_hash);

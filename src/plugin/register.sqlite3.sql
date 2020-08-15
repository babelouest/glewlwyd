DROP TABLE IF EXISTS gpr_update_email;
DROP TABLE IF EXISTS gpr_reset_credentials_email;
DROP TABLE IF EXISTS gpr_reset_credentials_session;
DROP TABLE IF EXISTS gpr_session;

CREATE TABLE gpr_session (
  gprs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gprs_plugin_name TEXT NOT NULL,
  gprs_username TEXT NOT NULL,
  gprs_name TEXT,
  gprs_email TEXT,
  gprs_code_hash TEXT,
  gprs_password_set INTEGER DEFAULT 0,
  gprs_session_hash TEXT,
  gprs_token_hash TEXT,
  gprs_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprs_issued_for TEXT, -- IP address or hostname
  gprs_user_agent TEXT,
  gprs_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gprs_session_hash ON gpr_session(gprs_session_hash);
CREATE INDEX i_gprs_gprs_token_hash ON gpr_session(gprs_token_hash);
CREATE INDEX i_gprs_gprs_gprs_code_hash ON gpr_session(gprs_code_hash);

CREATE TABLE gpr_update_email (
  gprue_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gprue_plugin_name TEXT NOT NULL,
  gprue_username TEXT NOT NULL,
  gprue_email TEXT,
  gprue_token_hash TEXT,
  gprue_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprue_issued_for TEXT, -- IP address or hostname
  gprue_user_agent TEXT,
  gprue_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gprue_token_hash ON gpr_update_email(gprue_token_hash);

CREATE TABLE gpr_reset_credentials_session (
  gprrcs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gprrcs_plugin_name TEXT NOT NULL,
  gprrcs_username TEXT NOT NULL,
  gprrcs_session_hash TEXT,
  gprrcs_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprrcs_issued_for TEXT, -- IP address or hostname
  gprrcs_user_agent TEXT,
  gprrcs_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gprrcs_session_hash ON gpr_reset_credentials_session(gprrcs_session_hash);

CREATE TABLE gpr_reset_credentials_email (
  gprrct_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gprrct_plugin_name TEXT NOT NULL,
  gprrct_username TEXT NOT NULL,
  gprrct_token_hash TEXT,
  gprrct_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprrct_issued_for TEXT, -- IP address or hostname
  gprrct_user_agent TEXT,
  gprrct_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gprrct_token_hash ON gpr_reset_credentials_email(gprrct_token_hash);

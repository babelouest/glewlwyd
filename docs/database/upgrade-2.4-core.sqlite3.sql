DROP TABLE IF EXISTS gs_user_pkcs12;

ALTER TABLE gpr_session
ADD gprs_callback_url TEXT DEFAULT NULL;

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
  gprrcs_callback_url TEXT DEFAULT NULL,
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
  gprrct_callback_url TEXT DEFAULT NULL,
  gprrct_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprrct_issued_for TEXT, -- IP address or hostname
  gprrct_user_agent TEXT,
  gprrct_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gprrct_token_hash ON gpr_reset_credentials_email(gprrct_token_hash);

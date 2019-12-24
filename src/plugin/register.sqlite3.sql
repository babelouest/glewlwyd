DROP TABLE IF EXISTS gpr_session;

CREATE TABLE gpr_session (
  gprs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gprs_plugin_name TEXT NOT NULL,
  gprs_username TEXT NOT NULL,
  gprs_name TEXT,
  gprs_email TEXT,
  gprs_code TEXT,
  gprs_password_set INTEGER DEFAULT 0,
  gprs_session_hash TEXT,
  gprs_token_hash TEXT,
  gprs_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprs_issued_for TEXT, -- IP address or hostname
  gprs_user_agent TEXT,
  gprs_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gprs_session_hash ON gpr_session(gprs_session_hash);

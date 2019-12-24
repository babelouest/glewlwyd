DROP TABLE IF EXISTS gpr_session;

CREATE TABLE gpr_session (
  gprs_id SERIAL PRIMARY KEY,
  gprs_plugin_name VARCHAR(256) NOT NULL,
  gprs_username VARCHAR(256) NOT NULL,
  gprs_name VARCHAR(512),
  gprs_email VARCHAR(512),
  gprs_code_hash VARCHAR(512),
  gprs_password_set SMALLINT DEFAULT 0,
  gprs_session_hash VARCHAR(512),
  gprs_token_hash VARCHAR(512),
  gprs_expires_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprs_issued_for VARCHAR(256), -- IP address or hostname
  gprs_user_agent VARCHAR(256),
  gprs_enabled SMALLINT DEFAULT 1
);
CREATE INDEX i_gprs_session_hash ON gpr_session(gprs_session_hash);

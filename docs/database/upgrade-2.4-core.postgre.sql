DROP TABLE IF EXISTS gs_user_pkcs12;

ALTER TABLE gpr_session
ADD gprs_callback_url TEXT DEFAULT NULL;

CREATE TABLE gpr_update_email (
  gprue_id SERIAL PRIMARY KEY,
  gprue_plugin_name VARCHAR(256) NOT NULL,
  gprue_username VARCHAR(256) NOT NULL,
  gprue_email VARCHAR(512),
  gprue_token_hash VARCHAR(512),
  gprue_expires_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprue_issued_for VARCHAR(256), -- IP address or hostname
  gprue_user_agent VARCHAR(256),
  gprue_enabled SMALLINT DEFAULT 1
);
CREATE INDEX i_gprue_token_hash ON gpr_update_email(gprue_token_hash);

CREATE TABLE gpr_reset_credentials_session (
  gprrcs_id SERIAL PRIMARY KEY,
  gprrcs_plugin_name VARCHAR(256) NOT NULL,
  gprrcs_username VARCHAR(256) NOT NULL,
  gprrcs_session_hash VARCHAR(512),
  gprrcs_callback_url TEXT DEFAULT NULL,
  gprrcs_expires_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprrcs_issued_for VARCHAR(256), -- IP address or hostname
  gprrcs_user_agent VARCHAR(256),
  gprrcs_enabled SMALLINT DEFAULT 1
);
CREATE INDEX i_gprrcs_session_hash ON gpr_reset_credentials_session(gprrcs_session_hash);

CREATE TABLE gpr_reset_credentials_email (
  gprrct_id SERIAL PRIMARY KEY,
  gprrct_plugin_name VARCHAR(256) NOT NULL,
  gprrct_username VARCHAR(256) NOT NULL,
  gprrct_token_hash VARCHAR(512),
  gprrct_callback_url TEXT DEFAULT NULL,
  gprrct_expires_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprrct_issued_for VARCHAR(256), -- IP address or hostname
  gprrct_user_agent VARCHAR(256),
  gprrct_enabled SMALLINT DEFAULT 1
);
CREATE INDEX i_gprrct_token_hash ON gpr_reset_credentials_email(gprrct_token_hash);

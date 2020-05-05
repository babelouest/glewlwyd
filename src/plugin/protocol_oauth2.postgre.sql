DROP TABLE IF EXISTS gpg_access_token_scope;
DROP TABLE IF EXISTS gpg_access_token;
DROP TABLE IF EXISTS gpg_refresh_token_scope;
DROP TABLE IF EXISTS gpg_refresh_token;
DROP TABLE IF EXISTS gpg_code_scope;
DROP TABLE IF EXISTS gpg_code;
DROP TABLE IF EXISTS gpg_device_authorization_scope;
DROP TABLE IF EXISTS gpg_device_authorization;

CREATE TABLE gpg_code (
  gpgc_id SERIAL PRIMARY KEY,
  gpgc_plugin_name VARCHAR(256) NOT NULL,
  gpgc_username VARCHAR(256) NOT NULL,
  gpgc_client_id VARCHAR(256) NOT NULL,
  gpgc_redirect_uri VARCHAR(512) NOT NULL,
  gpgc_code_hash VARCHAR(512) NOT NULL,
  gpgc_expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gpgc_issued_for VARCHAR(256), -- IP address or hostname
  gpgc_user_agent VARCHAR(256),
  gpgc_code_challenge VARCHAR(128),
  gpgc_enabled SMALLINT DEFAULT 1
);
CREATE INDEX i_gpgc_code_hash ON gpg_code(gpgc_code_hash);
CREATE INDEX i_gpgc_code_challenge ON gpg_code(gpgc_code_challenge);

CREATE TABLE gpg_code_scope (
  gpgcs_id SERIAL PRIMARY KEY,
  gpgc_id INTEGER,
  gpgcs_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpgc_id) REFERENCES gpg_code(gpgc_id) ON DELETE CASCADE
);

CREATE TABLE gpg_refresh_token (
  gpgr_id SERIAL PRIMARY KEY,
  gpgr_plugin_name VARCHAR(256) NOT NULL,
  gpgr_authorization_type SMALLINT NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  gpgc_id INTEGER DEFAULT NULL,
  gpgr_username VARCHAR(256) NOT NULL,
  gpgr_client_id VARCHAR(256),
  gpgr_issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gpgr_expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gpgr_last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gpgr_duration INTEGER,
  gpgr_rolling_expiration SMALLINT DEFAULT 0,
  gpgr_issued_for VARCHAR(256), -- IP address or hostname
  gpgr_user_agent VARCHAR(256),
  gpgr_token_hash VARCHAR(512) NOT NULL,
  gpgr_enabled SMALLINT DEFAULT 1,
  FOREIGN KEY(gpgc_id) REFERENCES gpg_code(gpgc_id) ON DELETE CASCADE
);
CREATE INDEX i_gpgr_token_hash ON gpg_refresh_token(gpgr_token_hash);

CREATE TABLE gpg_refresh_token_scope (
  gpgrs_id SERIAL PRIMARY KEY,
  gpgr_id INTEGER,
  gpgrs_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpgr_id) REFERENCES gpg_refresh_token(gpgr_id) ON DELETE CASCADE
);

-- Access token table, to store meta information on access token sent
CREATE TABLE gpg_access_token (
  gpga_id SERIAL PRIMARY KEY,
  gpga_plugin_name VARCHAR(256) NOT NULL,
  gpga_authorization_type SMALLINT NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  gpgr_id INTEGER DEFAULT NULL,
  gpga_username VARCHAR(256),
  gpga_client_id VARCHAR(256),
  gpga_issued_at TIMESTAMPTZ DEFAULT NOW(),
  gpga_issued_for VARCHAR(256), -- IP address or hostname
  gpga_user_agent VARCHAR(256),
  gpga_token_hash VARCHAR(512) NOT NULL,
  gpga_enabled SMALLINT DEFAULT 1,
  FOREIGN KEY(gpgr_id) REFERENCES gpg_refresh_token(gpgr_id) ON DELETE CASCADE
);
CREATE INDEX i_gpga_token_hash ON gpg_access_token(gpga_token_hash);

CREATE TABLE gpg_access_token_scope (
  gpgas_id SERIAL PRIMARY KEY,
  gpga_id INTEGER,
  gpgas_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpga_id) REFERENCES gpg_access_token(gpga_id) ON DELETE CASCADE
);

-- store device authorization requests
CREATE TABLE gpg_device_authorization (
  gpgda_id SERIAL PRIMARY KEY,
  gpgda_plugin_name VARCHAR(256) NOT NULL,
  gpgda_client_id VARCHAR(256) NOT NULL,
  gpgda_username VARCHAR(256),
  gpgda_created_at TIMESTAMPTZ DEFAULT NOW(),
  gpgda_expires_at TIMESTAMPTZ DEFAULT NOW(),
  gpgda_issued_for VARCHAR(256), -- IP address or hostname of the deice client
  gpgda_device_code_hash VARCHAR(512) NOT NULL,
  gpgda_user_code_hash VARCHAR(512) NOT NULL,
  gpgda_status SMALLINT DEFAULT 0, -- 0: created, 1: user verified, 2 device completed, 3 disabled
  gpgda_last_check TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX i_gpgda_device_code_hash ON gpg_device_authorization(gpgda_device_code_hash);
CREATE INDEX i_gpgda_user_code_hash ON gpg_device_authorization(gpgda_user_code_hash);

CREATE TABLE gpg_device_authorization_scope (
  gpgdas_id SERIAL PRIMARY KEY,
  gpgda_id INTEGER,
  gpgdas_scope VARCHAR(128) NOT NULL,
  gpgdas_allowed SMALLINT DEFAULT 0,
  FOREIGN KEY(gpgda_id) REFERENCES gpg_device_authorization(gpgda_id) ON DELETE CASCADE
);

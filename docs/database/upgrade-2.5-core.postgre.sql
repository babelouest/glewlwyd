-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.4.0 2.5.0
-- Copyright 2020 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

ALTER TABLE g_user_module_instance
ADD gumi_multiple_passwords SMALLINT DEFAULT 0;

ALTER TABLE gpo_code
ADD gpoc_resource VARCHAR(512);

ALTER TABLE gpo_refresh_token
ADD gpor_resource VARCHAR(512);

ALTER TABLE gpo_access_token
ADD gpoa_resource VARCHAR(512);

ALTER TABLE gpo_device_authorization
ADD gpoda_resource VARCHAR(512);

CREATE TABLE gpo_dpop (
  gpod_id SERIAL PRIMARY KEY,
  gpod_plugin_name VARCHAR(256) NOT NULL,
  gpod_client_id VARCHAR(256) NOT NULL,
  gpod_jti_hash VARCHAR(512) NOT NULL,
  gpod_jkt VARCHAR(512) NOT NULL,
  gpod_htm VARCHAR(128) NOT NULL,
  gpod_htu VARCHAR(512) NOT NULL,
  gpod_iat TIMESTAMPTZ NOT NULL,
  gpod_last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX i_gpod_jti_hash ON gpo_dpop(gpod_jti_hash);

CREATE TABLE g_user_password (
  guw_id SERIAL PRIMARY KEY,
  gu_id SERIAL,
  guw_password VARCHAR(256),
  FOREIGN KEY(gu_id) REFERENCES g_user(gu_id) ON DELETE CASCADE
);

INSERT INTO g_user_password (gu_id, guw_password)
SELECT gu_id, gu_password FROM g_user;

ALTER TABLE g_user
DROP COLUMN gu_password;

ALTER TABLE gpo_code
ADD gpoc_authorization_details TEXT DEFAULT NULL;

ALTER TABLE gpo_refresh_token
ADD gpor_authorization_details TEXT DEFAULT NULL;

ALTER TABLE gpo_refresh_token
ADD gpor_dpop_jkt VARCHAR(512);

ALTER TABLE gpo_access_token
ADD gpoa_authorization_details TEXT DEFAULT NULL;

ALTER TABLE gpo_device_authorization
ADD gpoda_authorization_details TEXT DEFAULT NULL;

CREATE TABLE gpo_rar (
  gporar_id SERIAL PRIMARY KEY,
  gporar_plugin_name VARCHAR(256) NOT NULL,
  gporar_client_id VARCHAR(256) NOT NULL,
  gporar_type VARCHAR(256) NOT NULL,
  gporar_username VARCHAR(256),
  gporar_consent SMALLINT DEFAULT 0,
  gporar_enabled SMALLINT DEFAULT 1
);
CREATE INDEX i_gporar_client_id ON gpo_rar(gporar_client_id);
CREATE INDEX i_gporar_type ON gpo_rar(gporar_type);
CREATE INDEX i_gporar_username ON gpo_rar(gporar_username);

CREATE TABLE gpo_par (
  gpop_id SERIAL PRIMARY KEY,
  gpop_plugin_name VARCHAR(256) NOT NULL,
  gpop_response_type VARCHAR(128) NOT NULL,
  gpop_state TEXT,
  gpop_username VARCHAR(256),
  gpop_client_id VARCHAR(256) NOT NULL,
  gpop_redirect_uri VARCHAR(512) NOT NULL,
  gpop_request_uri_hash VARCHAR(512) NOT NULL,
  gpop_nonce VARCHAR(512),
  gpop_code_challenge VARCHAR(128),
  gpop_resource VARCHAR(512),
  gpop_claims_request TEXT DEFAULT NULL,
  gpop_authorization_details TEXT DEFAULT NULL,
  gpop_additional_parameters TEXT DEFAULT NULL,
  gpop_status SMALLINT DEFAULT 0, -- 0 created, 1 validated, 2 completed
  gpop_expires_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpop_issued_for VARCHAR(256), -- IP address or hostname
  gpop_user_agent VARCHAR(256)
);
CREATE INDEX i_gpop_request_uri_hash ON gpo_par(gpop_request_uri_hash);
CREATE INDEX i_gpop_code_challenge ON gpo_par(gpop_code_challenge);

CREATE TABLE gpo_par_scope (
  gpops_id SERIAL PRIMARY KEY,
  gpop_id INTEGER,
  gpops_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpop_id) REFERENCES gpo_par(gpop_id) ON DELETE CASCADE
);

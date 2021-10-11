-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.5.0 2.6.0
-- Copyright 2021 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

ALTER TABLE g_user_auth_scheme_module_instance
ADD guasmi_forbid_user_profile SMALLINT DEFAULT 0,
ADD guasmi_forbid_user_reset_credential SMALLINT DEFAULT 0;

CREATE TABLE g_user_middleware_module_instance (
  gummi_id SERIAL PRIMARY KEY,
  gummi_module VARCHAR(128) NOT NULL,
  gummi_order INTEGER NOT NULL,
  gummi_name VARCHAR(128) NOT NULL,
  gummi_display_name VARCHAR(256) DEFAULT '',
  gummi_parameters TEXT,
  gummi_enabled SMALLINT DEFAULT 1
);

CREATE INDEX i_gpop_client_id ON gpo_par(gpop_client_id);

CREATE TABLE gpo_ciba (
  gpob_id SERIAL PRIMARY KEY,
  gpob_plugin_name VARCHAR(256) NOT NULL,
  gpob_client_id VARCHAR(256) NOT NULL,
  gpob_x5t_s256 VARCHAR(64),
  gpob_username VARCHAR(256) NOT NULL,
  gpob_client_notification_token VARCHAR(1024),
  gpob_jti_hash VARCHAR(512),
  gpob_auth_req_id VARCHAR(128),
  gpob_user_req_id VARCHAR(128),
  gpob_binding_message VARCHAR(256),
  gpob_status SMALLINT DEFAULT 0, -- 0: created, 1: accepted, 2: error, 3: closed
  gpob_expires_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpob_issued_for VARCHAR(256), -- IP address or hostname
  gpob_user_agent VARCHAR(256),
  gpob_enabled SMALLINT DEFAULT 1
);
CREATE INDEX i_gpob_client_id ON gpo_ciba(gpob_client_id);
CREATE INDEX i_gpob_jti_hash ON gpo_ciba(gpob_jti_hash);
CREATE INDEX i_gpob_client_notification_token ON gpo_ciba(gpob_client_notification_token);
CREATE INDEX i_gpob_auth_req_id ON gpo_ciba(gpob_auth_req_id);
CREATE INDEX i_gpob_user_req_id ON gpo_ciba(gpob_user_req_id);

CREATE TABLE gpo_ciba_scope (
  gpocs_id SERIAL PRIMARY KEY,
  gpob_id INTEGER,
  gpops_scope VARCHAR(128) NOT NULL,
  gpobs_granted SMALLINT DEFAULT 0,
  FOREIGN KEY(gpob_id) REFERENCES gpo_ciba(gpob_id) ON DELETE CASCADE
);

CREATE TABLE gpo_ciba_scheme (
  gpobh_id SERIAL PRIMARY KEY,
  gpob_id INTEGER,
  gpobh_scheme_module VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpob_id) REFERENCES gpo_ciba(gpob_id) ON DELETE CASCADE
);

ALTER TABLE gpo_code
ADD gpoc_s_hash VARCHAR(512);

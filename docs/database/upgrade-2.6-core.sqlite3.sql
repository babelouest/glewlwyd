-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.5.0 2.6.0
-- Copyright 2021 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

ALTER TABLE g_user_auth_scheme_module_instance
ADD guasmi_forbid_user_profile INTEGER DEFAULT 0,
ADD guasmi_forbid_user_reset_credential INTEGER DEFAULT 0;

CREATE TABLE g_user_middleware_module_instance (
  gummi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gummi_module TEXT NOT NULL,
  gummi_order INTEGER NOT NULL,
  gummi_name TEXT NOT NULL,
  gummi_display_name TEXT DEFAULT '',
  gummi_parameters TEXT,
  gummi_enabled INTEGER DEFAULT 1
);

CREATE INDEX i_gpop_client_id ON gpo_par(gpop_client_id);

CREATE TABLE gpo_ciba (
  gpob_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpob_plugin_name TEXT NOT NULL,
  gpob_client_id TEXT NOT NULL,
  gpob_x5t_s256 TEXT,
  gpob_username TEXT NOT NULL,
  gpob_client_notification_token TEXT,
  gpob_jti_hash TEXT,
  gpob_auth_req_id TEXT,
  gpob_user_req_id TEXT,
  gpob_binding_message TEXT,
  gpob_status INTEGER DEFAULT 0, -- 0: created, 1: accepted, 2: error, 3: closed
  gpob_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpob_issued_for TEXT, -- IP address or hostname
  gpob_user_agent TEXT,
  gpob_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gpob_client_id ON gpo_ciba(gpob_client_id);
CREATE INDEX i_gpob_jti_hash ON gpo_ciba(gpob_jti_hash);
CREATE INDEX i_gpob_client_notification_token ON gpo_ciba(gpob_client_notification_token);
CREATE INDEX i_gpob_auth_req_id ON gpo_ciba(gpob_auth_req_id);
CREATE INDEX i_gpob_user_req_id ON gpo_ciba(gpob_user_req_id);

CREATE TABLE gpo_ciba_scope (
  gpocs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpob_id INTEGER,
  gpops_scope TEXT NOT NULL,
  gpobs_granted INTEGER DEFAULT 0,
  FOREIGN KEY(gpob_id) REFERENCES gpo_ciba(gpob_id) ON DELETE CASCADE
);

CREATE TABLE gpo_ciba_scheme (
  gpobh_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpob_id INTEGER,
  gpobh_scheme_module TEXT NOT NULL,
  FOREIGN KEY(gpob_id) REFERENCES gpo_ciba(gpob_id) ON DELETE CASCADE
);

ALTER TABLE gpo_code
ADD gpoc_s_hash TEXT;

ALTER TABLE gpo_id_token
ADD gpoc_id INTEGER,
ADD gpor_id INTEGER,
ADD gpoi_sid_hash TEXT,
ADD FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE,
ADD FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE;

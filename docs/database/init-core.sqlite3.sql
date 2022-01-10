-- ----------------------------------------------------- --
--                 SQlite3 Database                      --
-- Initialize Glewlwyd Database for the backend server   --
-- The administration client app                         --
-- Copyright 2020 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

DROP TABLE IF EXISTS g_misc_config;
DROP TABLE IF EXISTS g_api_key;
DROP TABLE IF EXISTS g_client_user_scope;
DROP TABLE IF EXISTS g_scope_group_auth_scheme_module_instance;
DROP TABLE IF EXISTS g_scope_group;
DROP TABLE IF EXISTS g_user_session_scheme;
DROP TABLE IF EXISTS g_scope;
DROP TABLE IF EXISTS g_plugin_module_instance;
DROP TABLE IF EXISTS g_user_module_instance;
DROP TABLE IF EXISTS g_user_middleware_module_instance;
DROP TABLE IF EXISTS g_user_auth_scheme_module_instance;
DROP TABLE IF EXISTS g_client_module_instance;
DROP TABLE IF EXISTS g_user_session;

CREATE TABLE g_user_module_instance (
  gumi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gumi_module TEXT NOT NULL,
  gumi_order INTEGER NOT NULL,
  gumi_name TEXT NOT NULL,
  gumi_display_name TEXT DEFAULT '',
  gumi_parameters TEXT,
  gumi_readonly INTEGER DEFAULT 0,
  gumi_multiple_passwords INTEGER DEFAULT 0,
  gumi_enabled INTEGER DEFAULT 1
);

CREATE TABLE g_user_middleware_module_instance (
  gummi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gummi_module TEXT NOT NULL,
  gummi_order INTEGER NOT NULL,
  gummi_name TEXT NOT NULL,
  gummi_display_name TEXT DEFAULT '',
  gummi_parameters TEXT,
  gummi_enabled INTEGER DEFAULT 1
);

CREATE TABLE g_user_auth_scheme_module_instance (
  guasmi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  guasmi_module TEXT NOT NULL,
  guasmi_expiration INTEGER NOT NULL DEFAULT 0,
  guasmi_max_use INTEGER DEFAULT 0, -- 0: unlimited
  guasmi_allow_user_register INTEGER DEFAULT 1,
  guasmi_name TEXT NOT NULL,
  guasmi_display_name TEXT DEFAULT '',
  guasmi_parameters TEXT,
  guasmi_enabled INTEGER DEFAULT 1
);

CREATE TABLE g_client_module_instance (
  gcmi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gcmi_module TEXT NOT NULL,
  gcmi_order INTEGER NOT NULL,
  gcmi_name TEXT NOT NULL,
  gcmi_display_name TEXT DEFAULT '',
  gcmi_parameters TEXT,
  gcmi_readonly INTEGER DEFAULT 0,
  gcmi_enabled INTEGER DEFAULT 1
);

CREATE TABLE g_plugin_module_instance (
  gpmi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpmi_module TEXT NOT NULL,
  gpmi_name TEXT NOT NULL,
  gpmi_display_name TEXT DEFAULT '',
  gpmi_parameters TEXT,
  gpmi_enabled INTEGER DEFAULT 1
);

CREATE TABLE g_user_session (
  gus_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gus_session_hash TEXT NOT NULL,
  gus_user_agent TEXT,
  gus_issued_for TEXT, -- IP address or hostname
  gus_username TEXT NOT NULL,
  gus_expiration TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gus_last_login TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gus_current INTEGER,
  gus_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_g_user_session_username ON g_user_session(gus_username);
CREATE INDEX i_g_user_session_last_login ON g_user_session(gus_last_login);
CREATE INDEX i_g_user_session_expiration ON g_user_session(gus_expiration);

CREATE TABLE g_user_session_scheme (
  guss_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gus_id INTEGER NOT NULL,
  guasmi_id INTEGER DEFAULT NULL, -- NULL means scheme 'password'
  guss_expiration TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  guss_last_login TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  guss_use_counter INTEGER DEFAULT 0,
  guss_enabled INTEGER DEFAULT 1,
  FOREIGN KEY(gus_id) REFERENCES g_user_session(gus_id) ON DELETE CASCADE,
  FOREIGN KEY(guasmi_id) REFERENCES g_user_auth_scheme_module_instance(guasmi_id) ON DELETE CASCADE
);
CREATE INDEX i_g_user_session_scheme_last_login ON g_user_session_scheme(guss_last_login);
CREATE INDEX i_g_user_session_scheme_expiration ON g_user_session_scheme(guss_expiration);

CREATE TABLE g_scope (
  gs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gs_name TEXT NOT NULL UNIQUE,
  gs_display_name TEXT DEFAULT '',
  gs_description TEXT,
  gs_password_required INTEGER DEFAULT 1,
  gs_password_max_age INTEGER DEFAULT 0,
  gs_enabled INTEGER DEFAULT 1
);

CREATE TABLE g_scope_group (
  gsg_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gs_id INTEGER,
  gsg_name TEXT NOT NULL,
  gsg_scheme_required INTEGER DEFAULT 1,
  FOREIGN KEY(gs_id) REFERENCES g_scope(gs_id) ON DELETE CASCADE
);

CREATE TABLE g_scope_group_auth_scheme_module_instance (
  gsgasmi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gsg_id INTEGER NOT NULL,
  guasmi_id INTEGER NOT NULL,
  FOREIGN KEY(gsg_id) REFERENCES g_scope_group(gsg_id) ON DELETE CASCADE,
  FOREIGN KEY(guasmi_id) REFERENCES g_user_auth_scheme_module_instance(guasmi_id) ON DELETE CASCADE
);

CREATE TABLE g_client_user_scope (
  gcus_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gs_id INTEGER NOT NULL,
  gcus_username TEXT NOT NULL,
  gcus_client_id TEXT NOT NULL,
  gcus_granted TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gcus_enabled INTEGER DEFAULT 1,
  FOREIGN KEY(gs_id) REFERENCES g_scope(gs_id) ON DELETE CASCADE
);
CREATE INDEX i_g_client_user_scope_username ON g_client_user_scope(gcus_username);
CREATE INDEX i_g_client_user_scope_client_id ON g_client_user_scope(gcus_client_id);

CREATE TABLE g_api_key (
  gak_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gak_token_hash TEXT NOT NULL,
  gak_counter INTEGER DEFAULT 0,
  gak_username TEXT NOT NULL,
  gak_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gak_issued_for TEXT, -- IP address or hostname
  gak_user_agent TEXT,
  gak_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gak_token_hash ON g_api_key(gak_token_hash);

CREATE TABLE g_misc_config (
  gmc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gmc_type TEXT NOT NULL,
  gmc_name TEXT,
  gmc_value TEXT
);
CREATE INDEX i_gmc_type ON g_misc_config(gmc_type);
CREATE INDEX i_gmc_name ON g_misc_config(gmc_name);

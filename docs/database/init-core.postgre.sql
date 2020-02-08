-- ----------------------------------------------------- --
--                PostgreSQL Database                    --
-- Initialize Glewlwyd Database for the backend server   --
-- The administration client app                         --
-- ----------------------------------------------------- --

DROP TABLE IF EXISTS g_client_user_scope;
DROP TABLE IF EXISTS g_scope_group_auth_scheme_module_instance;
DROP TABLE IF EXISTS g_scope_group;
DROP TABLE IF EXISTS g_user_session_scheme;
DROP TABLE IF EXISTS g_scope;
DROP TABLE IF EXISTS g_plugin_module_instance;
DROP TABLE IF EXISTS g_user_module_instance;
DROP TABLE IF EXISTS g_user_auth_scheme_module_instance;
DROP TABLE IF EXISTS g_client_module_instance;
DROP TABLE IF EXISTS g_user_session;

CREATE TABLE g_user_module_instance (
  gumi_id SERIAL PRIMARY KEY,
  gumi_module VARCHAR(128) NOT NULL,
  gumi_order INTEGER NOT NULL,
  gumi_name VARCHAR(128) NOT NULL,
  gumi_display_name VARCHAR(256) DEFAULT '',
  gumi_parameters TEXT,
  gumi_readonly SMALLINT DEFAULT 0,
  gumi_enabled SMALLINT DEFAULT 1
);

CREATE TABLE g_user_auth_scheme_module_instance (
  guasmi_id SERIAL PRIMARY KEY,
  guasmi_module VARCHAR(128) NOT NULL,
  guasmi_expiration INTEGER NOT NULL DEFAULT 0,
  guasmi_max_use INTEGER DEFAULT 0, -- 0: unlimited
  guasmi_allow_user_register SMALLINT DEFAULT 1,
  guasmi_name VARCHAR(128) NOT NULL,
  guasmi_display_name VARCHAR(256) DEFAULT '',
  guasmi_parameters TEXT,
  guasmi_enabled SMALLINT DEFAULT 1
);

CREATE TABLE g_client_module_instance (
  gcmi_id SERIAL PRIMARY KEY,
  gcmi_module VARCHAR(128) NOT NULL,
  gcmi_order INTEGER NOT NULL,
  gcmi_name VARCHAR(128) NOT NULL,
  gcmi_display_name VARCHAR(256) DEFAULT '',
  gcmi_parameters TEXT,
  gcmi_readonly SMALLINT DEFAULT 0,
  gcmi_enabled SMALLINT DEFAULT 1
);

CREATE TABLE g_plugin_module_instance (
  gpmi_id SERIAL PRIMARY KEY,
  gpmi_module VARCHAR(128) NOT NULL,
  gpmi_name VARCHAR(128) NOT NULL,
  gpmi_display_name VARCHAR(256) DEFAULT '',
  gpmi_parameters TEXT,
  gpmi_enabled SMALLINT DEFAULT 1
);

CREATE TABLE g_user_session (
  gus_id SERIAL PRIMARY KEY,
  gus_session_hash VARCHAR(128) NOT NULL,
  gus_user_agent VARCHAR(256),
  gus_issued_for VARCHAR(256), -- IP address or hostname
  gus_username VARCHAR(256) NOT NULL,
  gus_expiration TIMESTAMP NOT NULL DEFAULT NOW(),
  gus_last_login TIMESTAMP NOT NULL DEFAULT NOW(),
  gus_current SMALLINT,
  gus_enabled SMALLINT DEFAULT 1
);
CREATE INDEX i_g_user_session_username ON g_user_session(gus_username);
CREATE INDEX i_g_user_session_last_login ON g_user_session(gus_last_login);
CREATE INDEX i_g_user_session_expiration ON g_user_session(gus_expiration);

CREATE TABLE g_user_session_scheme (
  guss_id SERIAL PRIMARY KEY,
  gus_id INTEGER NOT NULL,
  guasmi_id INTEGER DEFAULT NULL, -- NULL means scheme 'password'
  guss_expiration TIMESTAMP NOT NULL DEFAULT NOW(),
  guss_last_login TIMESTAMP NOT NULL DEFAULT NOW(),
  guss_use_counter INTEGER DEFAULT 0,
  guss_enabled SMALLINT DEFAULT 1,
  FOREIGN KEY(gus_id) REFERENCES g_user_session(gus_id) ON DELETE CASCADE,
  FOREIGN KEY(guasmi_id) REFERENCES g_user_auth_scheme_module_instance(guasmi_id) ON DELETE CASCADE
);
CREATE INDEX i_g_user_session_scheme_last_login ON g_user_session_scheme(guss_last_login);
CREATE INDEX i_g_user_session_scheme_expiration ON g_user_session_scheme(guss_expiration);

CREATE TABLE g_scope (
  gs_id SERIAL PRIMARY KEY,
  gs_name VARCHAR(128) NOT NULL UNIQUE,
  gs_display_name VARCHAR(256) DEFAULT '',
  gs_description VARCHAR(512),
  gs_password_required SMALLINT DEFAULT 1,
  gs_password_max_age INTEGER DEFAULT 0,
  gs_enabled SMALLINT DEFAULT 1
);

CREATE TABLE g_scope_group (
  gsg_id SERIAL PRIMARY KEY,
  gs_id INTEGER,
  gsg_name VARCHAR(128) NOT NULL,
  FOREIGN KEY(gs_id) REFERENCES g_scope(gs_id) ON DELETE CASCADE
);

CREATE TABLE g_scope_group_auth_scheme_module_instance (
  gsgasmi_id SERIAL PRIMARY KEY,
  gsg_id INTEGER NOT NULL,
  guasmi_id INTEGER NOT NULL,
  FOREIGN KEY(gsg_id) REFERENCES g_scope_group(gsg_id) ON DELETE CASCADE,
  FOREIGN KEY(guasmi_id) REFERENCES g_user_auth_scheme_module_instance(guasmi_id) ON DELETE CASCADE
);

CREATE TABLE g_client_user_scope (
  gcus_id SERIAL PRIMARY KEY,
  gs_id INTEGER NOT NULL,
  gcus_username VARCHAR(256) NOT NULL,
  gcus_client_id VARCHAR(256) NOT NULL,
  gcus_granted TIMESTAMP NOT NULL DEFAULT NOW(),
  gcus_enabled SMALLINT DEFAULT 1,
  FOREIGN KEY(gs_id) REFERENCES g_scope(gs_id) ON DELETE CASCADE
);
CREATE INDEX i_g_client_user_scope_username ON g_client_user_scope(gcus_username);
CREATE INDEX i_g_client_user_scope_client_id ON g_client_user_scope(gcus_client_id);

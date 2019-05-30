-- ----------------------------------------------------- --
--                 SQlite3 Database                      --
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
DROP TABLE IF EXISTS gpg_access_token_scope;
DROP TABLE IF EXISTS gpg_access_token;
DROP TABLE IF EXISTS gpg_refresh_token_scope;
DROP TABLE IF EXISTS gpg_refresh_token;
DROP TABLE IF EXISTS gpg_code_scope;
DROP TABLE IF EXISTS gpg_code;
DROP TABLE IF EXISTS g_client_property;
DROP TABLE IF EXISTS g_client_scope_client;
DROP TABLE IF EXISTS g_client_scope;
DROP TABLE IF EXISTS g_client;
DROP TABLE IF EXISTS g_user_property;
DROP TABLE IF EXISTS g_user_scope_user;
DROP TABLE IF EXISTS g_user_scope;
DROP TABLE IF EXISTS g_user;

CREATE TABLE g_user_module_instance (
  gumi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gumi_module TEXT NOT NULL,
  gumi_order INTEGER NOT NULL,
  gumi_name TEXT NOT NULL,
  gumi_display_name TEXT DEFAULT '',
  gumi_parameters TEXT,
  gumi_readonly INTEGER DEFAULT 0
);

CREATE TABLE g_user_auth_scheme_module_instance (
  guasmi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  guasmi_module TEXT NOT NULL,
  guasmi_expiration INTEGER NOT NULL DEFAULT 0,
  guasmi_max_use INTEGER DEFAULT 0, -- 0: unlimited
  guasmi_allow_user_register INTEGER DEFAULT 0,
  guasmi_name TEXT NOT NULL,
  guasmi_display_name TEXT DEFAULT '',
  guasmi_parameters TEXT
);

CREATE TABLE g_client_module_instance (
  gcmi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gcmi_module TEXT NOT NULL,
  gcmi_order INTEGER NOT NULL,
  gcmi_name TEXT NOT NULL,
  gcmi_display_name TEXT DEFAULT '',
  gcmi_parameters TEXT,
  gcmi_readonly INTEGER DEFAULT 0
);

CREATE TABLE g_plugin_module_instance (
  gpmi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpmi_module TEXT NOT NULL,
  gpmi_name TEXT NOT NULL,
  gpmi_display_name TEXT DEFAULT '',
  gpmi_parameters TEXT
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
  gs_enabled INTEGER DEFAULT 1
);

CREATE TABLE g_scope_group (
  gsg_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gs_id INTEGER,
  gsg_name TEXT NOT NULL,
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

CREATE TABLE g_client (
  gc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gc_client_id TEXT NOT NULL UNIQUE,
  gc_name TEXT DEFAULT '',
  gc_description TEXT DEFAULT '',
  gc_confidential INTEGER DEFAULT 0,
  gc_password TEXT,
  gc_enabled INTEGER DEFAULT 1
);

CREATE TABLE g_client_scope (
  gcs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gcs_name TEXT NOT NULL UNIQUE
);

CREATE TABLE g_client_scope_client (
  gcsu_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gc_id INTEGER,
  gcs_id INTEGER,
  FOREIGN KEY(gc_id) REFERENCES g_client(gc_id) ON DELETE CASCADE,
  FOREIGN KEY(gcs_id) REFERENCES g_client_scope(gcs_id) ON DELETE CASCADE
);

CREATE TABLE g_client_property (
  gcp_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gc_id INTEGER,
  gcp_name TEXT NOT NULL,
  gcp_value TEXT DEFAULT NULL,
  FOREIGN KEY(gc_id) REFERENCES g_client(gc_id) ON DELETE CASCADE
);
CREATE INDEX i_g_client_property_name ON g_client_property(gcp_name);

CREATE TABLE g_user (
  gu_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gu_username TEXT NOT NULL UNIQUE,
  gu_name TEXT DEFAULT '',
  gu_email TEXT,
  gu_password TEXT,
  gu_enabled INTEGER DEFAULT 1
);

CREATE TABLE g_user_scope (
  gus_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gus_name TEXT NOT NULL UNIQUE
);

CREATE TABLE g_user_scope_user (
  gusu_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gu_id INTEGER,
  gus_id INTEGER,
  FOREIGN KEY(gu_id) REFERENCES g_user(gu_id) ON DELETE CASCADE,
  FOREIGN KEY(gus_id) REFERENCES g_user_scope(gus_id) ON DELETE CASCADE
);

CREATE TABLE g_user_property (
  gup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gu_id INTEGER,
  gup_name TEXT NOT NULL,
  gup_value TEXT DEFAULT NULL,
  FOREIGN KEY(gu_id) REFERENCES g_user(gu_id) ON DELETE CASCADE
);
CREATE INDEX i_g_user_property_name ON g_user_property(gup_name);

CREATE TABLE gpg_code (
  gpgc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpgc_username TEXT NOT NULL,
  gpgc_client_id TEXT NOT NULL,
  gpgc_redirect_uri TEXT NOT NULL,
  gpgc_code_hash TEXT NOT NULL,
  gpgc_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgc_issued_for TEXT, -- IP address or hostname
  gpgc_user_agent TEXT,
  gpgc_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gpgc_code_hash ON gpg_code(gpgc_code_hash);

CREATE TABLE gpg_code_scope (
  gpgcs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpgc_id INTEGER,
  gpgcs_scope TEXT NOT NULL,
  FOREIGN KEY(gpgc_id) REFERENCES gpg_code(gpgc_id) ON DELETE CASCADE
);

CREATE TABLE gpg_refresh_token (
  gpgr_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpgr_authorization_type INTEGER NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  gpgc_id INTEGER DEFAULT NULL,
  gpgr_username TEXT NOT NULL,
  gpgr_client_id TEXT,
  gpgr_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgr_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgr_last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgr_duration INTEGER,
  gpgr_rolling_expiration INTEGER DEFAULT 0,
  gpgr_issued_for TEXT, -- IP address or hostname
  gpgr_user_agent TEXT,
  gpgr_token_hash TEXT NOT NULL,
  gpgr_enabled INTEGER DEFAULT 1,
  FOREIGN KEY(gpgc_id) REFERENCES gpg_code(gpgc_id) ON DELETE CASCADE
);
CREATE INDEX i_gpgr_token_hash ON gpg_refresh_token(gpgr_token_hash);

CREATE TABLE gpg_refresh_token_scope (
  gpgrs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpgr_id INTEGER,
  gpgrs_scope TEXT NOT NULL,
  FOREIGN KEY(gpgr_id) REFERENCES gpg_refresh_token(gpgr_id) ON DELETE CASCADE
);

-- Access token table, to store meta information on access token sent
CREATE TABLE gpg_access_token (
  gpga_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpga_authorization_type INTEGER NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  gpgr_id INTEGER DEFAULT NULL,
  gpga_username TEXT,
  gpga_client_id TEXT,
  gpga_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpga_issued_for TEXT, -- IP address or hostname
  gpga_user_agent TEXT,
  FOREIGN KEY(gpgr_id) REFERENCES gpg_refresh_token(gpgr_id) ON DELETE CASCADE
);

CREATE TABLE gpg_access_token_scope (
  gpgas_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpga_id INT(11),
  gpgas_scope TEXT NOT NULL,
  FOREIGN KEY(gpga_id) REFERENCES gpg_access_token(gpga_id) ON DELETE CASCADE
);

INSERT INTO g_plugin_module_instance (gpmi_module, gpmi_name, gpmi_display_name, gpmi_parameters) VALUES ('oauth2-glewlwyd', 'glwd', 'OAuth2 Glewlwyd plugin', '{"url":"glwd","jwt-type":"sha","jwt-key-size":"256","key":"secret","access-token-duration":3600,"refresh-token-duration":1209600,"code-duration":600,"refresh-token-rolling":true,"auth-type-code-enabled":true,"auth-type-implicit-enabled":true,"auth-type-password-enabled":true,"auth-type-client-enabled":true,"auth-type-refresh-enabled":true,"scope":[{"name":"g_profile","refresh-token-rolling":true},{"name":"scope1","refresh-token-rolling":true},{"name":"scope2","refresh-token-rolling":false,"refresh-token-duration":7200}]}');
INSERT INTO g_scope (gs_name, gs_display_name, gs_description, gs_password_required) VALUES ('g_admin', 'Glewlwyd administration', 'Access to Glewlwyd''s administration API', 1);
INSERT INTO g_scope (gs_name, gs_display_name, gs_description, gs_password_required) VALUES ('g_profile', 'Glewlwyd profile', 'Access to the user''s profile API', 1);

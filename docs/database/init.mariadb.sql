-- ----------------------------------------------------- --
--              Mariadb/Mysql Database                   --
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
DROP TABLE IF EXISTS g_client_property;
DROP TABLE IF EXISTS g_client_scope_client;
DROP TABLE IF EXISTS g_client_scope;
DROP TABLE IF EXISTS g_client;
DROP TABLE IF EXISTS g_user_property;
DROP TABLE IF EXISTS g_user_scope_user;
DROP TABLE IF EXISTS g_user_scope;
DROP TABLE IF EXISTS g_user;
DROP TABLE IF EXISTS gpg_access_token_scope;
DROP TABLE IF EXISTS gpg_access_token;
DROP TABLE IF EXISTS gpg_refresh_token_scope;
DROP TABLE IF EXISTS gpg_refresh_token;
DROP TABLE IF EXISTS gpg_code_scope;
DROP TABLE IF EXISTS gpg_code;

CREATE TABLE g_user_module_instance (
  gumi_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gumi_module VARCHAR(128) NOT NULL,
  gumi_order INT(11) NOT NULL,
  gumi_name VARCHAR(128) NOT NULL,
  gumi_display_name VARCHAR(256) DEFAULT '',
  gumi_parameters MEDIUMBLOB,
  gumi_readonly TINYINT(1) DEFAULT 0
);

CREATE TABLE g_user_auth_scheme_module_instance (
  guasmi_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  guasmi_module VARCHAR(128) NOT NULL,
  guasmi_expiration INT(11) NOT NULL DEFAULT 0,
  guasmi_max_use INT(11) DEFAULT 0, -- 0: unlimited
  guasmi_name VARCHAR(128) NOT NULL,
  guasmi_display_name VARCHAR(256) DEFAULT '',
  guasmi_parameters MEDIUMBLOB
);

CREATE TABLE g_client_module_instance (
  gcmi_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gcmi_module VARCHAR(128) NOT NULL,
  gcmi_order INT(11) NOT NULL,
  gcmi_name VARCHAR(128) NOT NULL,
  gcmi_display_name VARCHAR(256) DEFAULT '',
  gcmi_parameters MEDIUMBLOB,
  gcmi_readonly TINYINT(1) DEFAULT 0
);

CREATE TABLE g_plugin_module_instance (
  gpmi_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpmi_module VARCHAR(128) NOT NULL,
  gpmi_name VARCHAR(128) NOT NULL,
  gpmi_display_name VARCHAR(256) DEFAULT '',
  gpmi_parameters MEDIUMBLOB
);

CREATE TABLE g_user_session (
  gus_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gus_session_hash VARCHAR(128) NOT NULL,
  gus_user_agent VARCHAR(256),
  gus_issued_for VARCHAR(256), -- IP address or hostname
  gus_username VARCHAR(256) NOT NULL,
  gus_expiration TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gus_last_login TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gus_current TINYINT(1),
  gus_enabled TINYINT(1) DEFAULT 1
);
CREATE INDEX i_g_user_session_username ON g_user_session(gus_username);
CREATE INDEX i_g_user_session_last_login ON g_user_session(gus_last_login);
CREATE INDEX i_g_user_session_expiration ON g_user_session(gus_expiration);

CREATE TABLE g_user_session_scheme (
  guss_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gus_id INT(11) NOT NULL,
  guasmi_id INT(11) DEFAULT NULL, -- NULL means scheme 'password'
  guss_expiration TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  guss_last_login TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  guss_use_counter INT(11) DEFAULT 0,
  guss_enabled TINYINT(1) DEFAULT 1,
  FOREIGN KEY(gus_id) REFERENCES g_user_session(gus_id) ON DELETE CASCADE,
  FOREIGN KEY(guasmi_id) REFERENCES g_user_auth_scheme_module_instance(guasmi_id) ON DELETE CASCADE
);
CREATE INDEX i_g_user_session_scheme_last_login ON g_user_session_scheme(guss_last_login);
CREATE INDEX i_g_user_session_scheme_expiration ON g_user_session_scheme(guss_expiration);

CREATE TABLE g_scope (
  gs_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gs_name VARCHAR(128) NOT NULL UNIQUE,
  gs_display_name VARCHAR(256) DEFAULT '',
  gs_description VARCHAR(512),
  gs_password_required TINYINT(1) DEFAULT 1,
  gs_enabled TINYINT(1) DEFAULT 1
);

CREATE TABLE g_scope_group (
  gsg_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gs_id INT(11),
  gsg_name VARCHAR(128) NOT NULL,
  FOREIGN KEY(gs_id) REFERENCES g_scope(gs_id) ON DELETE CASCADE
);

CREATE TABLE g_scope_group_auth_scheme_module_instance (
  gsgasmi_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gsg_id INT(11) NOT NULL,
  guasmi_id INT(11) NOT NULL,
  FOREIGN KEY(gsg_id) REFERENCES g_scope_group(gsg_id) ON DELETE CASCADE,
  FOREIGN KEY(guasmi_id) REFERENCES g_user_auth_scheme_module_instance(guasmi_id) ON DELETE CASCADE
);

CREATE TABLE g_client_user_scope (
  gcus_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gs_id INT(11) NOT NULL,
  gcus_username VARCHAR(256) NOT NULL,
  gcus_client_id VARCHAR(256) NOT NULL,
  gcus_granted TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gcus_enabled TINYINT(1) DEFAULT 1,
  FOREIGN KEY(gs_id) REFERENCES g_scope(gs_id) ON DELETE CASCADE
);
CREATE INDEX i_g_client_user_scope_username ON g_client_user_scope(gcus_username);
CREATE INDEX i_g_client_user_scope_client_id ON g_client_user_scope(gcus_client_id);

CREATE TABLE g_client (
  gc_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gc_client_id VARCHAR(128) NOT NULL UNIQUE,
  gc_name VARCHAR(256) DEFAULT '',
  gc_description VARCHAR(512) DEFAULT '',
  gc_confidential TINYINT(1) DEFAULT 0,
  gc_password VARCHAR(256),
  gc_enabled TINYINT(1) DEFAULT 1
);

CREATE TABLE g_client_scope (
  gcs_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gcs_name VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE g_client_scope_client (
  gcsu_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gc_id INT(11),
  gcs_id INT(11),
  FOREIGN KEY(gc_id) REFERENCES g_client(gc_id) ON DELETE CASCADE,
  FOREIGN KEY(gcs_id) REFERENCES g_client_scope(gcs_id) ON DELETE CASCADE
);

CREATE TABLE g_client_property (
  gcp_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gc_id INT(11),
  gcp_name VARCHAR(128) NOT NULL,
  gcp_value_tiny VARCHAR(512) DEFAULT NULL,
  gcp_value_small BLOB DEFAULT NULL,
  gcp_value_medium MEDIUMBLOB DEFAULT NULL,
  FOREIGN KEY(gc_id) REFERENCES g_client(gc_id) ON DELETE CASCADE
);
CREATE INDEX i_g_client_property_name ON g_client_property(gcp_name);

CREATE TABLE g_user (
  gu_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gu_username VARCHAR(128) NOT NULL UNIQUE,
  gu_name VARCHAR(256) DEFAULT '',
  gu_email VARCHAR(512),
  gu_password VARCHAR(256),
  gu_enabled TINYINT(1) DEFAULT 1
);

CREATE TABLE g_user_scope (
  gus_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gus_name VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE g_user_scope_user (
  gusu_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gu_id INT(11),
  gus_id INT(11),
  FOREIGN KEY(gu_id) REFERENCES g_user(gu_id) ON DELETE CASCADE,
  FOREIGN KEY(gus_id) REFERENCES g_user_scope(gus_id) ON DELETE CASCADE
);

CREATE TABLE g_user_property (
  gup_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gu_id INT(11),
  gup_name VARCHAR(128) NOT NULL,
  gup_value_tiny VARCHAR(512) DEFAULT NULL,
  gup_value_small BLOB DEFAULT NULL,
  gup_value_medium MEDIUMBLOB DEFAULT NULL,
  FOREIGN KEY(gu_id) REFERENCES g_user(gu_id) ON DELETE CASCADE
);
CREATE INDEX i_g_user_property_name ON g_user_property(gup_name);

CREATE TABLE gpg_code (
  gpgc_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpgc_username VARCHAR(256) NOT NULL,
  gpgc_client_id VARCHAR(256) NOT NULL,
  gpgc_redirect_uri VARCHAR(512) NOT NULL,
  gpgc_code_hash VARCHAR(512) NOT NULL,
  gpgc_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgc_issued_for VARCHAR(256), -- IP address or hostname
  gpgc_user_agent VARCHAR(256),
  gpgc_enabled TINYINT(1) DEFAULT 1
);
CREATE INDEX i_gpgc_code_hash ON gpg_code(gpgc_code_hash);

CREATE TABLE gpg_code_scope (
  gpgcs_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpgc_id INT(11),
  gpgcs_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpgc_id) REFERENCES gpg_code(gpgc_id) ON DELETE CASCADE
);

CREATE TABLE gpg_refresh_token (
  gpgr_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpgr_authorization_type INT(2) NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  gpgc_id INT(11) DEFAULT NULL,
  gpgr_username VARCHAR(256) NOT NULL,
  gpgr_client_id VARCHAR(256),
  gpgr_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgr_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgr_last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgr_duration INT(11),
  gpgr_rolling_expiration TINYINT(1) DEFAULT 0,
  gpgr_issued_for VARCHAR(256), -- IP address or hostname
  gpgr_user_agent VARCHAR(256),
  gpgr_token_hash VARCHAR(512) NOT NULL,
  gpgr_enabled TINYINT(1) DEFAULT 1,
  FOREIGN KEY(gpgc_id) REFERENCES gpg_code(gpgc_id) ON DELETE CASCADE
);
CREATE INDEX i_gpgr_token_hash ON gpg_refresh_token(gpgr_token_hash);

CREATE TABLE gpg_refresh_token_scope (
  gpgrs_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpgr_id INT(11),
  gpgrs_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpgr_id) REFERENCES gpg_refresh_token(gpgr_id) ON DELETE CASCADE
);

-- Access token table, to store meta information on access token sent
CREATE TABLE gpg_access_token (
  gpga_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpga_authorization_type INT(2) NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  gpgr_id INT(11) DEFAULT NULL,
  gpga_username VARCHAR(256),
  gpga_client_id VARCHAR(256),
  gpga_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpga_issued_for VARCHAR(256), -- IP address or hostname
  gpga_user_agent VARCHAR(256),
  FOREIGN KEY(gpgr_id) REFERENCES gpg_refresh_token(gpgr_id) ON DELETE CASCADE
);

CREATE TABLE gpg_access_token_scope (
  gpgas_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpga_id INT(11),
  gpgas_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpga_id) REFERENCES gpg_access_token(gpga_id) ON DELETE CASCADE
);

INSERT INTO g_plugin_module_instance (gpmi_module, gpmi_name, gpmi_display_name, gpmi_parameters) VALUES ('oauth2-glewlwyd', 'glwd', 'OAuth2 Glewlwyd plugin', '{"url":"glwd","jwt-type":"sha","jwt-key-size":"256","key":"secret","access-token-duration":3600,"refresh-token-duration":1209600,"code-duration":600,"refresh-token-rolling":true,"auth-type-code-enabled":true,"auth-type-implicit-enabled":true,"auth-type-password-enabled":true,"auth-type-client-enabled":true,"auth-type-refresh-enabled":true,"scope":[{"name":"g_profile","refresh-token-rolling":true},{"name":"scope1","refresh-token-rolling":true},{"name":"scope2","refresh-token-rolling":false,"refresh-token-duration":7200}]}');
INSERT INTO g_scope (gs_name, gs_display_name, gs_description, gs_password_required) VALUES ('g_admin', 'Glewlwyd administration', 'Access to Glewlwyd''s administration API', 1);
INSERT INTO g_scope (gs_name, gs_display_name, gs_description, gs_password_required) VALUES ('g_profile', 'Glewlwyd profile', 'Access to the user''s profile API', 1);

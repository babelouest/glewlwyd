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
  guasmi_allow_user_register TINYINT(1) DEFAULT 1,
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
  gs_password_max_age INT(11) DEFAULT 0,
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


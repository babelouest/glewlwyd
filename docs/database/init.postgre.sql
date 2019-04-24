-- ----------------------------------------------------- --
--                PostgreSQL Database                    --
-- Initialize Glewlwyd Database for the backend server   --
-- The administration client app                         --
-- ----------------------------------------------------- --

DROP TABLE IF EXISTS `g_client_user_scope`;
DROP TABLE IF EXISTS `g_scope_group_auth_scheme_module_instance`;
DROP TABLE IF EXISTS `g_scope_group`;
DROP TABLE IF EXISTS `g_user_session_scheme`;
DROP TABLE IF EXISTS `g_scope`;
DROP TABLE IF EXISTS `g_plugin_module_instance`;
DROP TABLE IF EXISTS `g_user_module_instance`;
DROP TABLE IF EXISTS `g_user_auth_scheme_module_instance`;
DROP TABLE IF EXISTS `g_client_module_instance`;
DROP TABLE IF EXISTS `g_user_session`;

CREATE TABLE `g_user_module_instance` (
  `gumi_id` SERIAL PRIMARY KEY,
  `gumi_module` VARCHAR(128) NOT NULL,
  `gumi_order` INT(11) NOT NULL,
  `gumi_name` VARCHAR(128) NOT NULL,
  `gumi_display_name` VARCHAR(256) DEFAULT '',
  `gumi_parameters` MEDIUMBLOB,
  `gumi_readonly` TINYINT(1) DEFAULT 0
);

CREATE TABLE `g_user_auth_scheme_module_instance` (
  `guasmi_id` SERIAL PRIMARY KEY,
  `guasmi_module` VARCHAR(128) NOT NULL,
  `guasmi_expiration` INT(11) NOT NULL DEFAULT 0,
  `guasmi_max_use` INT(11) DEFAULT 0, -- 0: unlimited
  `guasmi_name` VARCHAR(128) NOT NULL,
  `guasmi_display_name` VARCHAR(256) DEFAULT '',
  `guasmi_parameters` MEDIUMBLOB
);

CREATE TABLE `g_client_module_instance` (
  `gcmi_id` SERIAL PRIMARY KEY,
  `gcmi_module` VARCHAR(128) NOT NULL,
  `gcmi_order` INT(11) NOT NULL,
  `gcmi_name` VARCHAR(128) NOT NULL,
  `gcmi_display_name` VARCHAR(256) DEFAULT '',
  `gcmi_parameters` MEDIUMBLOB,
  `gcmi_readonly` TINYINT(1) DEFAULT 0
);

CREATE TABLE `g_plugin_module_instance` (
  `gpmi_id` SERIAL PRIMARY KEY,
  `gpmi_module` VARCHAR(128) NOT NULL,
  `gpmi_name` VARCHAR(128) NOT NULL,
  `gpmi_display_name` VARCHAR(256) DEFAULT '',
  `gpmi_parameters` MEDIUMBLOB
);

CREATE TABLE `g_user_session` (
  `gus_id` SERIAL PRIMARY KEY,
  `gus_session_hash` VARCHAR(128) NOT NULL,
  `gus_user_agent` VARCHAR(256),
  `gus_issued_for` VARCHAR(256), -- IP address or hostname
  `gus_username` VARCHAR(256) NOT NULL,
  `gus_expiration` TIMESTAMP NOT NULL DEFAULT NOW(),
  `gus_last_login` TIMESTAMP NOT NULL DEFAULT NOW(),
  `gus_current` TINYINT(1),
  `gus_enabled` TINYINT(1) DEFAULT 1
);
CREATE INDEX `i_g_user_session_username` ON `g_user_session`(`gus_username`);
CREATE INDEX `i_g_user_session_last_login` ON `g_user_session`(`gus_last_login`);
CREATE INDEX `i_g_user_session_expiration` ON `g_user_session`(`gus_expiration`);

CREATE TABLE `g_user_session_scheme` (
  `guss_id` SERIAL PRIMARY KEY,
  `gus_id` INT(11) NOT NULL,
  `guasmi_id` INT(11) DEFAULT NULL, -- NULL means scheme 'password'
  `guss_expiration` TIMESTAMP NOT NULL DEFAULT NOW(),
  `guss_last_login` TIMESTAMP NOT NULL DEFAULT NOW(),
  `guss_use_counter` INT(11) DEFAULT 0,
  `guss_enabled` TINYINT(1) DEFAULT 1,
  FOREIGN KEY(`gus_id`) REFERENCES `g_user_session`(`gus_id`) ON DELETE CASCADE,
  FOREIGN KEY(`guasmi_id`) REFERENCES `g_user_auth_scheme_module_instance`(`guasmi_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_user_session_scheme_last_login` ON `g_user_session_scheme`(`guss_last_login`);
CREATE INDEX `i_g_user_session_scheme_expiration` ON `g_user_session_scheme`(`guss_expiration`);

CREATE TABLE `g_scope` (
  `gs_id` SERIAL PRIMARY KEY,
  `gs_name` VARCHAR(128) NOT NULL UNIQUE,
  `gs_display_name` VARCHAR(256) DEFAULT '',
  `gs_description` VARCHAR(512),
  `gs_password_required` TINYINT(1) DEFAULT 1,
  `gs_enabled` TINYINT(1) DEFAULT 1
);

CREATE TABLE `g_scope_group` (
  `gsg_id` SERIAL PRIMARY KEY,
  `gs_id` INT(11),
  `gsg_name` VARCHAR(128) NOT NULL,
  FOREIGN KEY(`gs_id`) REFERENCES `g_scope`(`gs_id`) ON DELETE CASCADE
);

CREATE TABLE `g_scope_group_auth_scheme_module_instance` (
  `gsgasmi_id` SERIAL PRIMARY KEY,
  `gsg_id` INT(11) NOT NULL,
  `guasmi_id` INT(11) NOT NULL,
  FOREIGN KEY(`gsg_id`) REFERENCES `g_scope_group`(`gsg_id`) ON DELETE CASCADE,
  FOREIGN KEY(`guasmi_id`) REFERENCES `g_user_auth_scheme_module_instance`(`guasmi_id`) ON DELETE CASCADE
);

CREATE TABLE `g_client_user_scope` (
  `gcus_id` SERIAL PRIMARY KEY,
  `gs_id` INT(11) NOT NULL,
  `gcus_username` VARCHAR(256) NOT NULL,
  `gcus_client_id` VARCHAR(256) NOT NULL,
  `gcus_granted` TIMESTAMP NOT NULL DEFAULT NOW(),
  `gcus_enabled` TINYINT(1) DEFAULT 1,
  FOREIGN KEY(`gs_id`) REFERENCES `g_scope`(`gs_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_client_user_scope_username` ON `g_client_user_scope`(`gcus_username`);
CREATE INDEX `i_g_client_user_scope_client_id` ON `g_client_user_scope`(`gcus_client_id`);

INSERT INTO `g_user_module_instance` (`gumi_module`, `gumi_name`, `gumi_display_name`, `gumi_order`, `gumi_parameters`) VALUES ('mock', 'mock', 'Mock user module', 0, '{"username-prefix":"","password":"password"}');
INSERT INTO `g_user_auth_scheme_module_instance` (`guasmi_module`, `guasmi_name`, `guasmi_display_name`, `guasmi_expiration`, `guasmi_parameters`) VALUES ('mock', 'mock_scheme_42', 'Mock 42', 600, '{"mock-value":"42"}');
INSERT INTO `g_user_auth_scheme_module_instance` (`guasmi_module`, `guasmi_name`, `guasmi_display_name`, `guasmi_expiration`, `guasmi_parameters`, `guasmi_max_use`) VALUES ('mock', 'mock_scheme_88', 'Mock 88', 600, '{"mock-value":"88"}', 1);
INSERT INTO `g_user_auth_scheme_module_instance` (`guasmi_module`, `guasmi_name`, `guasmi_display_name`, `guasmi_expiration`, `guasmi_parameters`) VALUES ('mock', 'mock_scheme_95', 'Mock 95', 300, '{"mock-value":"95"}');
INSERT INTO `g_client_module_instance` (`gcmi_module`, `gcmi_name`, `gcmi_display_name`, `gcmi_order`, `gcmi_parameters`) VALUES ('mock', 'mock', 'Mock client module', 0, '{"username-prefix":"","password":"password"}');
INSERT INTO `g_plugin_module_instance` (`gpmi_module`, `gpmi_name`, `gpmi_display_name`, `gpmi_parameters`) VALUES ('oauth2-glewlwyd', 'glwd', 'OAuth2 Glewlwyd plugin', '{"url":"glwd","jwt-type":"sha","jwt-key-size":"256","key":"secret","access-token-duration":3600,"refresh-token-duration":1209600,"code-duration":600,"refresh-token-rolling":true,"auth-type-code-enabled":true,"auth-type-implicit-enabled":true,"auth-type-password-enabled":true,"auth-type-client-enabled":true,"auth-type-refresh-enabled":true,"scope":[{"name":"g_profile","refresh-token-rolling":true},{"name":"scope1","refresh-token-rolling":true},{"name":"scope2","refresh-token-rolling":false,"refresh-token-duration":7200}]}');
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`, `gs_password_required`) VALUES ('g_admin', 'Glewlwyd administration', 'Access to Glewlwyd''s administration API', 1);
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`, `gs_password_required`) VALUES ('g_profile', 'Glewlwyd profile', 'Access to the user''s profile API', 1);
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`, `gs_password_required`) VALUES ('scope1', 'Glewlwyd mock scope with password', 'Glewlwyd scope 1 scope description', 1);
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`, `gs_password_required`) VALUES ('scope2', 'Glewlwyd mock scope without password', 'Glewlwyd scope 2 scope description', 0);
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`, `gs_password_required`) VALUES ('scope3', 'Glewlwyd mock scope with password', 'Glewlwyd scope 3 scope description', 1);
INSERT INTO `g_scope_group` (`gs_id`, `gsg_name`) VALUES ((SELECT `gs_id` FROM `g_scope` WHERE `gs_name` = 'scope1'), 'mock_group_1');
INSERT INTO `g_scope_group` (`gs_id`, `gsg_name`) VALUES ((SELECT `gs_id` FROM `g_scope` WHERE `gs_name` = 'scope1'), 'mock_group_2');
INSERT INTO `g_scope_group` (`gs_id`, `gsg_name`) VALUES ((SELECT `gs_id` FROM `g_scope` WHERE `gs_name` = 'scope2'), 'mock_group_3');
INSERT INTO `g_scope_group` (`gs_id`, `gsg_name`) VALUES ((SELECT `gs_id` FROM `g_scope` WHERE `gs_name` = 'scope3'), 'mock_group_4');
INSERT INTO `g_scope_group_auth_scheme_module_instance` (`gsg_id`, `guasmi_id`) VALUES ((SELECT `gsg_id` FROM `g_scope_group` WHERE `gsg_name` = 'mock_group_1'), (SELECT `guasmi_id` FROM `g_user_auth_scheme_module_instance` WHERE `guasmi_name` = 'mock_scheme_42'));
INSERT INTO `g_scope_group_auth_scheme_module_instance` (`gsg_id`, `guasmi_id`) VALUES ((SELECT `gsg_id` FROM `g_scope_group` WHERE `gsg_name` = 'mock_group_1'), (SELECT `guasmi_id` FROM `g_user_auth_scheme_module_instance` WHERE `guasmi_name` = 'mock_scheme_88'));
INSERT INTO `g_scope_group_auth_scheme_module_instance` (`gsg_id`, `guasmi_id`) VALUES ((SELECT `gsg_id` FROM `g_scope_group` WHERE `gsg_name` = 'mock_group_2'), (SELECT `guasmi_id` FROM `g_user_auth_scheme_module_instance` WHERE `guasmi_name` = 'mock_scheme_95'));
INSERT INTO `g_scope_group_auth_scheme_module_instance` (`gsg_id`, `guasmi_id`) VALUES ((SELECT `gsg_id` FROM `g_scope_group` WHERE `gsg_name` = 'mock_group_3'), (SELECT `guasmi_id` FROM `g_user_auth_scheme_module_instance` WHERE `guasmi_name` = 'mock_scheme_95'));
INSERT INTO `g_scope_group_auth_scheme_module_instance` (`gsg_id`, `guasmi_id`) VALUES ((SELECT `gsg_id` FROM `g_scope_group` WHERE `gsg_name` = 'mock_group_4'), (SELECT `guasmi_id` FROM `g_user_auth_scheme_module_instance` WHERE `guasmi_name` = 'mock_scheme_88'));

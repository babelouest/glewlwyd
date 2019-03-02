-- ----------------------------------------------------- --
--              Mariadb/Mysql Database                   --
-- Initialize Glewlwyd Database for the backend server   --
-- The administration client app                         --
-- ----------------------------------------------------- --

DROP TABLE IF EXISTS `g_client_user_scope`;
DROP TABLE IF EXISTS `g_user_auth_scheme_group_scope`;
DROP TABLE IF EXISTS `g_user_auth_scheme_group_auth_scheme_module_instance`;
DROP TABLE IF EXISTS `g_user_auth_scheme_group`;
DROP TABLE IF EXISTS `g_user_session_scheme`;
DROP TABLE IF EXISTS `g_scope`;
DROP TABLE IF EXISTS `g_plugin_module_instance`;
DROP TABLE IF EXISTS `g_user_module_instance`;
DROP TABLE IF EXISTS `g_user_auth_scheme_module_instance`;
DROP TABLE IF EXISTS `g_client_module_instance`;
DROP TABLE IF EXISTS `g_user_session`;

CREATE TABLE `g_user_module_instance` (
  `gumi_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gumi_module` VARCHAR(128) NOT NULL,
  `gumi_order` INT(11) NOT NULL,
  `gumi_name` VARCHAR(128) NOT NULL,
  `gumi_display_name` VARCHAR(256) DEFAULT '',
  `gumi_parameters` TINYBLOB,
  `gumi_readonly` TINYINT(1) DEFAULT 0
);

CREATE TABLE `g_user_auth_scheme_module_instance` (
  `guasmi_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `guasmi_module` VARCHAR(128) NOT NULL,
  `guasmi_expiration` INT(11) NOT NULL DEFAULT 0,
  `guasmi_name` VARCHAR(128) NOT NULL,
  `guasmi_display_name` VARCHAR(256) DEFAULT '',
  `guasmi_parameters` TINYBLOB
);

CREATE TABLE `g_client_module_instance` (
  `gcmi_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gcmi_module` VARCHAR(128) NOT NULL,
  `gcmi_order` INT(11) NOT NULL,
  `gcmi_name` VARCHAR(128) NOT NULL,
  `gcmi_display_name` VARCHAR(256) DEFAULT '',
  `gcmi_parameters` TINYBLOB,
  `gcmi_readonly` TINYINT(1) DEFAULT 0
);

CREATE TABLE `g_plugin_module_instance` (
  `gpmi_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gpmi_module` VARCHAR(128) NOT NULL,
  `gpmi_name` VARCHAR(128) NOT NULL,
  `gpmi_display_name` VARCHAR(256) DEFAULT '',
  `gpmi_parameters` MEDIUMBLOB
);

CREATE TABLE `g_user_session` (
  `gus_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gus_uuid` VARCHAR(128) NOT NULL,
  `gus_user_agent` VARCHAR(256),
  `gus_username` VARCHAR(256) NOT NULL,
  `gus_expiration` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `gus_last_login` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `gus_current` TINYINT(1),
  `gus_enabled` TINYINT(1) DEFAULT 1
);
CREATE INDEX `i_g_user_session_username` ON `g_user_session`(`gus_username`);
CREATE INDEX `i_g_user_session_last_login` ON `g_user_session`(`gus_last_login`);
CREATE INDEX `i_g_user_session_expiration` ON `g_user_session`(`gus_expiration`);

CREATE TABLE `g_user_session_scheme` (
  `guss_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gus_id` INT(11) NOT NULL,
  `guasmi_id` INT(11) DEFAULT NULL, -- NULL means scheme 'password'
  `guss_expiration` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `guss_last_login` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `guss_use_counter` INT(11) DEFAULT 0,
  `guss_enabled` TINYINT(1) DEFAULT 1,
  FOREIGN KEY(`gus_id`) REFERENCES `g_user_session`(`gus_id`) ON DELETE CASCADE,
  FOREIGN KEY(`guasmi_id`) REFERENCES `g_user_auth_scheme_module_instance`(`guasmi_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_user_session_scheme_last_login` ON `g_user_session_scheme`(`guss_last_login`);
CREATE INDEX `i_g_user_session_scheme_expiration` ON `g_user_session_scheme`(`guss_expiration`);

CREATE TABLE `g_scope` (
  `gs_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gs_name` VARCHAR(128) NOT NULL UNIQUE,
  `gs_display_name` VARCHAR(256) DEFAULT '',
  `gs_description` VARCHAR(512),
  `gs_password_required` TINYINT(1) DEFAULT 1,
  `gs_enabled` TINYINT(1) DEFAULT 1
);

CREATE TABLE `g_user_auth_scheme_group` (
  `guasg_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `guasg_name` VARCHAR(128) NOT NULL,
  `guasg_display_name` VARCHAR(256) DEFAULT '',
  `guasg_description` VARCHAR(512)
);

CREATE TABLE `g_user_auth_scheme_group_auth_scheme_module_instance` (
  `guasgasmi_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `guasg_id` INT(11) NOT NULL,
  `guasmi_id` INT(11) NOT NULL,
  `guasgasmi_max_use` INT(11) DEFAULT 0, -- 0: unlimited
  FOREIGN KEY(`guasg_id`) REFERENCES `g_user_auth_scheme_group`(`guasg_id`) ON DELETE CASCADE,
  FOREIGN KEY(`guasmi_id`) REFERENCES `g_user_auth_scheme_module_instance`(`guasmi_id`) ON DELETE CASCADE
);

CREATE TABLE `g_user_auth_scheme_group_scope` (
  `gsuasg_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `guasg_id` INT(11) NOT NULL,
  `gs_id` INT(11) NOT NULL,
  FOREIGN KEY(`guasg_id`) REFERENCES `g_user_auth_scheme_group`(`guasg_id`) ON DELETE CASCADE,
  FOREIGN KEY(`gs_id`) REFERENCES `g_scope`(`gs_id`) ON DELETE CASCADE
);

CREATE TABLE `g_client_user_scope` (
  `gcus_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gs_id` INT(11) NOT NULL,
  `gcus_username` VARCHAR(256) NOT NULL,
  `gcus_client_id` VARCHAR(256) NOT NULL,
  `gcus_granted` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `gcus_enabled` TINYINT(1) DEFAULT 1,
  FOREIGN KEY(`gs_id`) REFERENCES `g_scope`(`gs_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_client_user_scope_username` ON `g_client_user_scope`(`gcus_username`);
CREATE INDEX `i_g_client_user_scope_client_id` ON `g_client_user_scope`(`gcus_client_id`);

INSERT INTO `g_user_module_instance` (`gumi_module`, `gumi_name`, `gumi_display_name`, `gumi_order`, `gumi_parameters`) VALUES ('mock', 'mock', 'Mock user module', 0, '{"mock-param-string":"str1","mock-param-number":42,"mock-param-boolean":true,"mock-param-list":"elt1"}');
INSERT INTO `g_user_auth_scheme_module_instance` (`guasmi_module`, `guasmi_name`, `guasmi_display_name`, `guasmi_expiration`, `guasmi_parameters`) VALUES ('mock', 'mock_scheme_42', 'Mock 42', 600, '{"mock-value":"42","mock-user-forbidden":"user2","mock-param-string":"str1","mock-param-number":42,"mock-param-boolean":true,"mock-param-list":"elt2"}');
INSERT INTO `g_user_auth_scheme_module_instance` (`guasmi_module`, `guasmi_name`, `guasmi_display_name`, `guasmi_expiration`, `guasmi_parameters`) VALUES ('mock', 'mock_scheme_88', 'Mock 88', 600, '{"mock-value":"88","mock-user-forbidden":"user2","mock-param-string":"str1","mock-param-number":88,"mock-param-boolean":true,"mock-param-list":"elt2"}');
INSERT INTO `g_user_auth_scheme_module_instance` (`guasmi_module`, `guasmi_name`, `guasmi_display_name`, `guasmi_expiration`, `guasmi_parameters`) VALUES ('mock', 'mock_scheme_95', 'Mock 95', 300, '{"mock-value":"95","mock-param-string":"str1","mock-param-number":88,"mock-param-boolean":true,"mock-param-list":"elt2"}');
INSERT INTO `g_client_module_instance` (`gcmi_module`, `gcmi_name`, `gcmi_display_name`, `gcmi_order`, `gcmi_parameters`) VALUES ('mock', 'mock', 'Mock client module', 0, '{"mock-param-string":"str1","mock-param-number":42,"mock-param-boolean":true,"mock-param-list":"elt3"}');
INSERT INTO `g_plugin_module_instance` (`gpmi_module`, `gpmi_name`, `gpmi_display_name`, `gpmi_parameters`) VALUES ('oauth2-glewlwyd', 'glwd', 'OAuth2 Glewlwyd plugin', '{"url":"glwd","jwt-type":"sha","jwt-key-size":"256","key":"secret","access-token-duration":3600,"refresh-token-duration":1209600,"refresh-token-rolling":true,"auth-type-code-enabled":true,"auth-type-implicit-enabled":true,"auth-type-password-enabled":true,"auth-type-client-enabled":true,"auth-type-refresh-enabled":true,"scope":[{"name":"g_profile","refresh-token-rolling":true},{"name":"g_mock_1","refresh-token-rolling":true},{"name":"g_mock_2","refresh-token-rolling":false,"refresh-token-duration":7200}]}');
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`, `gs_password_required`) VALUES ('g_admin', 'Glewlwyd administration', 'Access to Glewlwyd''s administration API', 1);
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`, `gs_password_required`) VALUES ('g_profile', 'Glewlwyd profile', 'Access to the user''s profile API', 1);
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`, `gs_password_required`) VALUES ('scope1', 'Glewlwyd mock scope with password', 'Glewlwyd scope 1 scope description', 1);
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`, `gs_password_required`) VALUES ('scope2', 'Glewlwyd mock scope without password', 'Glewlwyd scope 2 scope description', 0);
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`, `gs_password_required`) VALUES ('scope3', 'Glewlwyd mock scope with password', 'Glewlwyd scope 3 scope description', 1);
INSERT INTO `g_user_auth_scheme_group` (`guasg_name`, `guasg_display_name`, `guasg_description`) VALUES ('mock_group_1', 'mock group 1', 'mock group description 1');
INSERT INTO `g_user_auth_scheme_group` (`guasg_name`, `guasg_display_name`, `guasg_description`) VALUES ('mock_group_2', 'mock group 2', 'mock group description 2');
INSERT INTO `g_user_auth_scheme_group` (`guasg_name`, `guasg_display_name`, `guasg_description`) VALUES ('mock_group_3', 'mock group 3', 'mock group description 3');
INSERT INTO `g_user_auth_scheme_group` (`guasg_name`, `guasg_display_name`, `guasg_description`) VALUES ('mock_group_4', 'mock group 4', 'mock group description 4');
INSERT INTO `g_user_auth_scheme_group_scope` (`guasg_id`, `gs_id`) VALUES ((SELECT `guasg_id` FROM `g_user_auth_scheme_group` WHERE `guasg_name` = 'mock_group_1'), (SELECT `gs_id` FROM `g_scope` WHERE `gs_name` = 'scope1'));
INSERT INTO `g_user_auth_scheme_group_scope` (`guasg_id`, `gs_id`) VALUES ((SELECT `guasg_id` FROM `g_user_auth_scheme_group` WHERE `guasg_name` = 'mock_group_2'), (SELECT `gs_id` FROM `g_scope` WHERE `gs_name` = 'scope1'));
INSERT INTO `g_user_auth_scheme_group_scope` (`guasg_id`, `gs_id`) VALUES ((SELECT `guasg_id` FROM `g_user_auth_scheme_group` WHERE `guasg_name` = 'mock_group_3'), (SELECT `gs_id` FROM `g_scope` WHERE `gs_name` = 'scope2'));
INSERT INTO `g_user_auth_scheme_group_scope` (`guasg_id`, `gs_id`) VALUES ((SELECT `guasg_id` FROM `g_user_auth_scheme_group` WHERE `guasg_name` = 'mock_group_4'), (SELECT `gs_id` FROM `g_scope` WHERE `gs_name` = 'scope3'));
INSERT INTO `g_user_auth_scheme_group_auth_scheme_module_instance` (`guasg_id`, `guasmi_id`) VALUES ((SELECT `guasg_id` FROM `g_user_auth_scheme_group` WHERE `guasg_name` = 'mock_group_1'), (SELECT `guasmi_id` FROM `g_user_auth_scheme_module_instance` WHERE `guasmi_name` = 'mock_scheme_42'));
INSERT INTO `g_user_auth_scheme_group_auth_scheme_module_instance` (`guasg_id`, `guasmi_id`) VALUES ((SELECT `guasg_id` FROM `g_user_auth_scheme_group` WHERE `guasg_name` = 'mock_group_1'), (SELECT `guasmi_id` FROM `g_user_auth_scheme_module_instance` WHERE `guasmi_name` = 'mock_scheme_88'));
INSERT INTO `g_user_auth_scheme_group_auth_scheme_module_instance` (`guasg_id`, `guasmi_id`) VALUES ((SELECT `guasg_id` FROM `g_user_auth_scheme_group` WHERE `guasg_name` = 'mock_group_2'), (SELECT `guasmi_id` FROM `g_user_auth_scheme_module_instance` WHERE `guasmi_name` = 'mock_scheme_95'));
INSERT INTO `g_user_auth_scheme_group_auth_scheme_module_instance` (`guasg_id`, `guasmi_id`) VALUES ((SELECT `guasg_id` FROM `g_user_auth_scheme_group` WHERE `guasg_name` = 'mock_group_3'), (SELECT `guasmi_id` FROM `g_user_auth_scheme_module_instance` WHERE `guasmi_name` = 'mock_scheme_95'));
INSERT INTO `g_user_auth_scheme_group_auth_scheme_module_instance` (`guasg_id`, `guasmi_id`, `guasgasmi_max_use`) VALUES ((SELECT `guasg_id` FROM `g_user_auth_scheme_group` WHERE `guasg_name` = 'mock_group_4'), (SELECT `guasmi_id` FROM `g_user_auth_scheme_module_instance` WHERE `guasmi_name` = 'mock_scheme_88'), 1);

-- ----------------------------------------------------- --
--              Mariadb/Mysql Database                   --
-- Initialize Glewlwyd Database for the backend server   --
-- The administration client app                         --
-- ----------------------------------------------------- --

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
  `gumi_parameters` TINYBLOB
);

CREATE TABLE `g_user_auth_scheme_module_instance` (
  `guasmi_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `guasmi_module` VARCHAR(128) NOT NULL,
  `guasmi_expiration` INT(11) NOT NULL DEFAULT 0,
  `guasmi_name` VARCHAR(128) NOT NULL,
  `guasmi_display_name` VARCHAR(256),
  `guasmi_parameters` TINYBLOB
);

CREATE TABLE `g_client_module_instance` (
  `gcmi_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gcmi_module` VARCHAR(128) NOT NULL,
  `gcmi_order` INT(11) NOT NULL,
  `gcmi_name` VARCHAR(128) NOT NULL,
  `gcmi_parameters` TINYBLOB
);

CREATE TABLE `g_plugin_module_instance` (
  `gp_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gp_module` VARCHAR(128) NOT NULL,
  `gp_name` VARCHAR(128) NOT NULL,
  `gp_parameters` TINYBLOB
);

CREATE TABLE `g_user_session` (
  `gus_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gus_uuid` VARCHAR(128) NOT NULL,
  `gus_username` VARCHAR(256) NOT NULL,
  `gus_expiration` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `gus_last_login` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `gus_enabled` TINYINT(1) DEFAULT 1
);

CREATE TABLE `g_user_session_scheme` (
  `guss_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gus_id` INT(11) NOT NULL,
  `guasmi_id` INT(11) DEFAULT NULL, -- NULL means scheme 'password'
  `guss_expiration` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `guss_last_login` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `guss_enabled` TINYINT(1) DEFAULT 1,
  FOREIGN KEY(`gus_id`) REFERENCES `g_user_session`(`gus_id`) ON DELETE CASCADE,
  FOREIGN KEY(`guasmi_id`) REFERENCES `g_user_auth_scheme_module_instance`(`guasmi_id`) ON DELETE CASCADE
);

CREATE TABLE `g_scope` (
  `gs_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gs_name` VARCHAR(128) NOT NULL,
  `gs_display_name` VARCHAR(256),
  `gs_description` VARCHAR(512),
  `gs_requires_password` TINYINT(1) DEFAULT 1,
  `gs_enabled` TINYINT(1) DEFAULT 1
);

CREATE TABLE `g_user_auth_scheme_group` (
  `guasg_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `guasg_name` VARCHAR(128) NOT NULL,
  `guasg_display_name` VARCHAR(256),
  `guasg_description` VARCHAR(512)
);

CREATE TABLE `g_user_auth_scheme_group_auth_scheme_module_instance` (
  `guasgasmi_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `guasg_id` INT(11) NOT NULL,
  `guasmi_id` INT(11) NOT NULL,
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

INSERT INTO `g_user_module_instance` (`gumi_module`, `gumi_name`, `gumi_order`, `gumi_parameters`) VALUES ('mock', 'mock', 0, '{"mock-param-string":"str1","mock-param-number":42,"mock-param-boolean":true,"mock-param-list":"elt1"}');
INSERT INTO `g_user_auth_scheme_module_instance` (`guasmi_module`, `guasmi_name`, `guasmi_display_name`, `guasmi_expiration`, `guasmi_parameters`) VALUES ('mock', 'mock_scheme_42', 'Mock 42', 600, '{"mock-value":"42","mock-param-string":"str1","mock-param-number":42,"mock-param-boolean":true,"mock-param-list":"elt2"}');
INSERT INTO `g_user_auth_scheme_module_instance` (`guasmi_module`, `guasmi_name`, `guasmi_display_name`, `guasmi_expiration`, `guasmi_parameters`) VALUES ('mock', 'mock_scheme_88', 'Mock 88', 600, '{"mock-value":"88","mock-param-string":"str1","mock-param-number":88,"mock-param-boolean":true,"mock-param-list":"elt2"}');
INSERT INTO `g_client_module_instance` (`gcmi_module`, `gcmi_name`, `gcmi_order`, `gcmi_parameters`) VALUES ('mock', 'mock', 0, '{"mock-param-string":"str1","mock-param-number":42,"mock-param-boolean":true,"mock-param-list":"elt3"}');
INSERT INTO `g_plugin_module_instance` (`gp_module`, `gp_name`, `gp_parameters`) VALUES ('oauth2-glewlwyd', 'glwd-1', '{"url":"glwd","jwt-type":"sha","jwt-key-size":"256","key":"secret","access-token-duration":3600,"refresh-token-duration":1209600,"scope":[{"name":"g_profile","rolling-refresh":true}]}');
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`, `gs_requires_password`) VALUES ('g_admin', 'Glewlwyd administration', 'Access to Glewlwyd''s administration API', 1);
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`, `gs_requires_password`) VALUES ('g_profile', 'Glewlwyd profile', 'Access to the user''s profile API', 1);
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`, `gs_requires_password`) VALUES ('g_mock', 'Glewlwyd mock scope', 'Glewlwyd mock scope description', 0);
INSERT INTO `g_user_auth_scheme_group` (`guasg_name`, `guasg_display_name`, `guasg_description`) VALUES ('mock_group', 'mock group', 'mock group description');
INSERT INTO `g_user_auth_scheme_group_scope` (`guasg_id`, `gs_id`) VALUES ((SELECT `guasg_id` FROM `g_user_auth_scheme_group` WHERE `guasg_name` = 'mock_group'), (SELECT `gs_id` FROM `g_scope` WHERE `gs_name` = 'g_mock'));
INSERT INTO `g_user_auth_scheme_group_auth_scheme_module_instance` (`guasg_id`, `guasmi_id`) VALUES ((SELECT `guasg_id` FROM `g_user_auth_scheme_group` WHERE `guasg_name` = 'mock_group'), (SELECT `guasmi_id` FROM `g_user_auth_scheme_module_instance` WHERE `guasmi_name` = 'mock_scheme_42'));
INSERT INTO `g_user_auth_scheme_group_auth_scheme_module_instance` (`guasg_id`, `guasmi_id`) VALUES ((SELECT `guasg_id` FROM `g_user_auth_scheme_group` WHERE `guasg_name` = 'mock_group'), (SELECT `guasmi_id` FROM `g_user_auth_scheme_module_instance` WHERE `guasmi_name` = 'mock_scheme_88'));

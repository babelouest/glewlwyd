-- ----------------------------------------------------- --
--              Mariadb/Mysql Database                   --
-- Initialize Glewlwyd Database for the backend server   --
-- The administration client app                         --
-- And the default user 'admin' with password 'password' --
-- ----------------------------------------------------- --

DROP TABLE IF EXISTS `g_scope`;
DROP TABLE IF EXISTS `g_user_module_instance`;
DROP TABLE IF EXISTS `g_user_auth_scheme_module_instance`;
DROP TABLE IF EXISTS `g_client_module_instance`;
DROP TABLE IF EXISTS `g_user_session_scheme`;
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
  `guasmi_order` INT(11) NOT NULL,
  `guasmi_name` VARCHAR(128) NOT NULL,
  `guasmi_parameters` TINYBLOB
);

CREATE TABLE `g_client_module_instance` (
  `gcmi_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gcmi_module` VARCHAR(128) NOT NULL,
  `gcmi_order` INT(11) NOT NULL,
  `gcmi_name` VARCHAR(128) NOT NULL,
  `gcmi_parameters` TINYBLOB
);

CREATE TABLE `g_user_session` (
  `gus_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gus_uuid` VARCHAR(128) NOT NULL,
  `gus_username` VARCHAR(256) NOT NULL,
  `gus_expiration` TIMESTAMP NOT NULL,
  `gus_last_login` TIMESTAMP NOT NULL,
  `gus_enabled` TINYINT(1) DEFAULT 1
);

CREATE TABLE `g_user_session_scheme` (
  `guss_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gus_id` INT(11) NOT NULL,
  `guss_scheme_name` VARCHAR(128) NOT NULL,
  `guss_expiration` TIMESTAMP NOT NULL,
  `guss_last_login` TIMESTAMP NOT NULL,
  `guss_enabled` TINYINT(1) DEFAULT 1,
  FOREIGN KEY(`gus_id`) REFERENCES `g_user_session`(`gus_id`) ON DELETE CASCADE
);

CREATE TABLE `g_scope` (
  `gs_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gs_name` VARCHAR(128) NOT NULL,
  `gs_display_name` VARCHAR(256),
  `gs_description` VARCHAR(512)
);

INSERT INTO `g_user_module_instance` (`gumi_module`, `gumi_name`, `gumi_order`, `gumi_parameters`) VALUES ('mock', 'mock', 0, '{"mock-param-string":"str1","mock-param-number":42,"mock-param-boolean":true,"mock-param-list":"elt1"}');
INSERT INTO `g_user_auth_scheme_module_instance` (`guasmi_module`, `guasmi_name`, `guasmi_order`, `guasmi_parameters`) VALUES ('mock', 'mock', 0, '{"mock-param-string":"str1","mock-param-number":42,"mock-param-boolean":true,"mock-param-list":"elt2"}');
INSERT INTO `g_client_module_instance` (`gcmi_module`, `gcmi_name`, `gcmi_order`, `gcmi_parameters`) VALUES ('mock', 'mock', 0, '{"mock-param-string":"str1","mock-param-number":42,"mock-param-boolean":true,"mock-param-list":"elt3"}');
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`) VALUES ('g_admin', 'Glewlwyd administration', 'Access to Glewlwyd''s administration API');
INSERT INTO `g_scope` (`gs_name`, `gs_display_name`, `gs_description`) VALUES ('g_profile', 'Glewlwyd profile', 'Access to the user''s profile API');

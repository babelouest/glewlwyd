-- ----------------------------------------------------- --
--              Mariadb/Mysql Database                   --
-- Initialize Glewlwyd Database for the backend server   --
-- The administration client app                         --
-- And the default user 'admin' with password 'password' --
-- ----------------------------------------------------- --

DROP TABLE IF EXISTS `g_user_module_instance`;
DROP TABLE IF EXISTS `g_user_session_scheme`;
DROP TABLE IF EXISTS `g_user_session`;

CREATE TABLE `g_user_module_instance` (
  `gumi_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gumi_uid` INT(11) NOT NULL,
  `gumi_order` INT(11) NOT NULL,
  `gumi_name` VARCHAR(128) NOT NULL,
  `gumi_parameters` TINYBLOB,
  `gumi_enabled` TINYINT(1) DEFAULT 1
);

CREATE TABLE `g_user_session` (
  `gus_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gus_uuid` VARCHAR(128) NOT NULL,
  `gus_username` VARCHAR(256) NOT NULL,
  `gus_expiration` TIMESTAMP NOT NULL,
  `gus_enabled` TINYINT(1) DEFAULT 1
);

CREATE TABLE `g_user_session_scheme` (
  `guss_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gus_id` INT(11) NOT NULL,
  `guss_scheme_name` VARCHAR(128) NOT NULL,
  `guss_expiration` TIMESTAMP NOT NULL,
  `guss_enabled` TINYINT(1) DEFAULT 1,
  FOREIGN KEY(`gus_id`) REFERENCES `g_user_session`(`gus_id`) ON DELETE CASCADE
);

INSERT INTO `g_user_module_instance` (`gumi_uid`, `gumi_name`, `gumi_order`) VALUES (42, 'mock', 0);

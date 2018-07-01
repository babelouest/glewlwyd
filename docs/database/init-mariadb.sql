-- ----------------------------------------------------- --
--              Mariadb/Mysql Database                   --
-- Initialize Glewlwyd Database for the backend server   --
-- The administration client app                         --
-- And the default user 'admin' with password 'password' --
-- ----------------------------------------------------- --

DROP TABLE IF EXISTS `g_user_module_instance`;

CREATE TABLE `g_user_module_instance` (
  `gumi_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gumi_uid` INT(11) NOT NULL,
  `gumi_name` VARCHAR(128) NOT NULL,
  `gumi_parameters` TINYBLOB,
  `gumi_enabled` TINYINT(1) DEFAULT 1
);

INSERT INTO `g_user_module_instance` (`gumi_uid`, `gumi_display_name`) VALUES (42, 'mock');

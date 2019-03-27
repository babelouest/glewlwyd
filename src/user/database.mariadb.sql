DROP TABLE IF EXISTS `g_user_property`;
DROP TABLE IF EXISTS `g_user_scope_user`;
DROP TABLE IF EXISTS `g_user_scope`;
DROP TABLE IF EXISTS `g_user`;

CREATE TABLE `g_user` (
  `gu_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gu_username` VARCHAR(128) NOT NULL UNIQUE,
  `gu_name` VARCHAR(256) DEFAULT '',
  `gu_email` VARCHAR(512),
  `gu_enabled` TINYINT(1) DEFAULT 1,
  `gu_password` VARCHAR(256)
);

CREATE TABLE `g_user_scope` (
  `gus_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gus_name` VARCHAR(128) NOT NULL,
  `gu_id` INT(11),
  FOREIGN KEY(`gu_id`) REFERENCES `g_user`(`gu_id`) ON DELETE CASCADE
);

CREATE TABLE `g_user_scope_user` (
  `gusu_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gu_id` INT(11),
  `gus_id` INT(11),
  FOREIGN KEY(`gu_id`) REFERENCES `g_user`(`gu_id`) ON DELETE CASCADE,
  FOREIGN KEY(`gus_id`) REFERENCES `g_user_scope`(`gus_id`) ON DELETE CASCADE
);

CREATE TABLE `g_user_property` (
  `gup_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gu_id` INT(11),
  `gup_name` VARCHAR(128) NOT NULL,
  `gup_value_tiny` VARCHAR(512) DEFAULT NULL,
  `gup_value_small` BLOB DEFAULT NULL,
  `gup_value_medium` MEDIUMBLOB DEFAULT NULL,
  FOREIGN KEY(`gu_id`) REFERENCES `g_user`(`gu_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_user_property_name` ON `g_user_property`(`gup_name`);

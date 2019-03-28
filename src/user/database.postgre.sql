DROP TABLE IF EXISTS `g_user_property`;
DROP TABLE IF EXISTS `g_user_scope_user`;
DROP TABLE IF EXISTS `g_user_scope`;
DROP TABLE IF EXISTS `g_user`;

CREATE TABLE `g_user` (
  `gu_id` SERIAL PRIMARY KEY,
  `gu_username` VARCHAR(128) NOT NULL UNIQUE,
  `gu_name` VARCHAR(256) DEFAULT '',
  `gu_email` VARCHAR(512),
  `gu_password` VARCHAR(256),
  `gu_enabled` SMALLINT DEFAULT 1
);

CREATE TABLE `g_user_scope` (
  `gus_id` SERIAL PRIMARY KEY,
  `gus_name` VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE `g_user_scope_user` (
  `gusu_id` SERIAL PRIMARY KEY,
  `gu_id` SERIAL,
  `gus_id` SERIAL,
  FOREIGN KEY(`gu_id`) REFERENCES `g_user`(`gu_id`) ON DELETE CASCADE,
  FOREIGN KEY(`gus_id`) REFERENCES `g_user_scope`(`gus_id`) ON DELETE CASCADE
);

CREATE TABLE `g_user_property` (
  `gup_id` SERIAL PRIMARY KEY,
  `gu_id` SERIAL,
  `gup_name` VARCHAR(128) NOT NULL,
  `gup_value` TEXT DEFAULT NULL,
  FOREIGN KEY(`gu_id`) REFERENCES `g_user`(`gu_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_user_property_name` ON `g_user_property`(`gup_name`);

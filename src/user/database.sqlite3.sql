DROP TABLE IF EXISTS `g_user_property`;
DROP TABLE IF EXISTS `g_user_scope_user`;
DROP TABLE IF EXISTS `g_user_scope`;
DROP TABLE IF EXISTS `g_user`;

CREATE TABLE `g_user` (
  `gu_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gu_username` TEXT NOT NULL UNIQUE,
  `gu_name` TEXT DEFAULT '',
  `gu_email` TEXT,
  `gu_password` TEXT,
  `gu_enabled` INTEGER DEFAULT 1
);

CREATE TABLE `g_user_scope` (
  `gus_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gus_name` TEXT NOT NULL UNIQUE,
  FOREIGN KEY(`gu_id`) REFERENCES `g_user`(`gu_id`) ON DELETE CASCADE
);

CREATE TABLE `g_user_scope_user` (
  `gusu_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gu_id` INTEGER,
  `gus_id` INTEGER,
  FOREIGN KEY(`gu_id`) REFERENCES `g_user`(`gu_id`) ON DELETE CASCADE,
  FOREIGN KEY(`gus_id`) REFERENCES `g_user_scope`(`gus_id`) ON DELETE CASCADE
);

CREATE TABLE `g_user_property` (
  `gup_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gu_id` INTEGER,
  `gup_name` TEXT NOT NULL,
  `gup_value` TEXT DEFAULT NULL,
  FOREIGN KEY(`gu_id`) REFERENCES `g_user`(`gu_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_user_property_name` ON `g_user_property`(`gup_name`);

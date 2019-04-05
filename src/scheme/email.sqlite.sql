DROP TABLE IF EXISTS `gss_code`;

CREATE TABLE `g_user_scheme_code` (
  `gusc_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gusc_issued_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `gusc_username` TEXT NOT NULL,
  `gusc_enabled` INTEGER DEFAULT 1,
  `gusc_code_hash` TEXT,
  `gusc_result` INTEGER DEFAULT 0
);
CREATE INDEX `i_gssc_username` ON `gss_code`(`gssc_username`);

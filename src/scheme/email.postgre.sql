DROP TABLE IF EXISTS `gss_code`;

CREATE TABLE `g_user_scheme_code` (
  `gusc_id` SERIAL PRIMARY KEY,
  `gusc_issued_at` TIMESTAMP NOT NULL DEFAULT NOW(),
  `gusc_username` VARCHAR(128) NOT NULL,
  `gusc_enabled` SMALLINT DEFAULT 1,
  `gusc_code_hash` VARCHAR(128),
  `gusc_result` SMALLINT DEFAULT 0
);
CREATE INDEX `i_gssc_username` ON `gss_code`(`gssc_username`);

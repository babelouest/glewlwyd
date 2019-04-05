DROP TABLE IF EXISTS `gss_code`;

CREATE TABLE `g_user_scheme_code` (
  `gusc_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gusc_issued_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `gusc_username` VARCHAR(128) NOT NULL,
  `gusc_enabled` TINYINT(1) DEFAULT 1,
  `gusc_code_hash` VARCHAR(128),
  `gusc_result` TINYINT(1) DEFAULT 0
);
CREATE INDEX `i_gssc_username` ON `gss_code`(`gssc_username`);

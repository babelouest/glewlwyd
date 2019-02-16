DROP TABLE IF EXISTS `gpg_code`;

CREATE TABLE `gpg_code` (
  `gpgc_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gpgc_username` VARCHAR(256) NOT NULL,
  `gpgc_client_id` VARCHAR(256) NOT NULL,
  `gpgc_redirect_uri` VARCHAR(512) NOT NULL,
  `gpgc_scope` VARCHAR(512),
  `gpgc_code_hash` VARCHAR(512) NOT NULL,
  `gpgc_expiration` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `gpgc_enabled` TINYINT(1) DEFAULT 1
);
CREATE INDEX `i_gpgc_code_hash` ON `gpg_code`(`gpgc_code_hash`);

CREATE TABLE `gpg_refresh_token` (
  `gpgr_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gus_uuid` VARCHAR(128),
  `gpgc_id` INT(11),
  `gpgr_issued_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `gpgr_expiration` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `gpgr_token_hash` VARCHAR(512) NOT NULL,
  `gpgr_issued_for` VARCHAR(256),
  FOREIGN KEY(`gpgc_id`) REFERENCES `gpg_code`(`gpgc_id`) ON DELETE CASCADE
);
CREATE INDEX `i_gpgr_token_hash` ON `gpg_refresh_token`(`gpgr_token_hash`);

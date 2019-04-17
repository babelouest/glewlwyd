DROP TABLE IF EXISTS `g_client_property`;
DROP TABLE IF EXISTS `g_client_scope_client`;
DROP TABLE IF EXISTS `g_client_scope`;
DROP TABLE IF EXISTS `g_client`;

CREATE TABLE `g_client` (
  `gc_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gc_client_id` VARCHAR(128) NOT NULL UNIQUE,
  `gc_name` VARCHAR(256) DEFAULT '',
  `gc_description` VARCHAR(512) DEFAULT '',
  `gc_confidential` TINYINT(1) DEFAULT 0,
  `gc_password` VARCHAR(256),
  `gc_enabled` TINYINT(1) DEFAULT 1
);

CREATE TABLE `g_client_scope` (
  `gcs_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gcs_name` VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE `g_client_scope_client` (
  `gcsu_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gc_id` INT(11),
  `gcs_id` INT(11),
  FOREIGN KEY(`gc_id`) REFERENCES `g_client`(`gc_id`) ON DELETE CASCADE,
  FOREIGN KEY(`gcs_id`) REFERENCES `g_client_scope`(`gcs_id`) ON DELETE CASCADE
);

CREATE TABLE `g_client_property` (
  `gcp_id` INT(11) PRIMARY KEY AUTO_INCREMENT,
  `gc_id` INT(11),
  `gcp_name` VARCHAR(128) NOT NULL,
  `gcp_value_tiny` VARCHAR(512) DEFAULT NULL,
  `gcp_value_small` BLOB DEFAULT NULL,
  `gcp_value_medium` MEDIUMBLOB DEFAULT NULL,
  FOREIGN KEY(`gc_id`) REFERENCES `g_client`(`gc_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_client_property_name` ON `g_client_property`(`gcp_name`);

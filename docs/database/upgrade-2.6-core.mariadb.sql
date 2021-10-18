-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.5.0 2.6.0
-- Copyright 2021 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

ALTER TABLE g_user_auth_scheme_module_instance
ADD guasmi_forbid_user_profile TINYINT(1) DEFAULT 0,
ADD guasmi_forbid_user_reset_credential TINYINT(1) DEFAULT 0;

CREATE TABLE g_user_middleware_module_instance (
  gummi_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gummi_module VARCHAR(128) NOT NULL,
  gummi_order INT(11) NOT NULL,
  gummi_name VARCHAR(128) NOT NULL,
  gummi_display_name VARCHAR(256) DEFAULT '',
  gummi_parameters MEDIUMBLOB,
  gummi_enabled TINYINT(1) DEFAULT 1
);

CREATE INDEX i_gpop_client_id ON gpo_par(gpop_client_id);

CREATE TABLE gpo_ciba (
  gpob_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpob_plugin_name VARCHAR(256) NOT NULL,
  gpob_client_id VARCHAR(256) NOT NULL,
  gpob_x5t_s256 VARCHAR(64),
  gpob_username VARCHAR(256) NOT NULL,
  gpob_client_notification_token VARCHAR(1024),
  gpob_jti_hash VARCHAR(512),
  gpob_auth_req_id VARCHAR(128),
  gpob_user_req_id VARCHAR(128),
  gpob_binding_message VARCHAR(256),
  gpob_status TINYINT(1) DEFAULT 0, -- 0: created, 1: accepted, 2: error, 3: closed
  gpob_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpob_issued_for VARCHAR(256), -- IP address or hostname
  gpob_user_agent VARCHAR(256),
  gpob_enabled TINYINT(1) DEFAULT 1
);
CREATE INDEX i_gpob_client_id ON gpo_ciba(gpob_client_id);
CREATE INDEX i_gpob_jti_hash ON gpo_ciba(gpob_jti_hash);
CREATE INDEX i_gpob_client_notification_token ON gpo_ciba(gpob_client_notification_token);
CREATE INDEX i_gpob_auth_req_id ON gpo_ciba(gpob_auth_req_id);
CREATE INDEX i_gpob_user_req_id ON gpo_ciba(gpob_user_req_id);

CREATE TABLE gpo_ciba_scope (
  gpocs_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpob_id INT(11),
  gpops_scope VARCHAR(128) NOT NULL,
  gpobs_granted TINYINT(1) DEFAULT 0,
  FOREIGN KEY(gpob_id) REFERENCES gpo_ciba(gpob_id) ON DELETE CASCADE
);

CREATE TABLE gpo_ciba_scheme (
  gpobh_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpob_id INT(11),
  gpobh_scheme_module VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpob_id) REFERENCES gpo_ciba(gpob_id) ON DELETE CASCADE
);

ALTER TABLE gpo_code
ADD gpoc_s_hash VARCHAR(512);

ALTER TABLE gpo_id_token
ADD gpoc_id INT(11) DEFAULT NULL,
ADD gpor_id INT(11),
ADD gpoi_sid_hash VARCHAR(512),
ADD FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE,
ADD FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE;

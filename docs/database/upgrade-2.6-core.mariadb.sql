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

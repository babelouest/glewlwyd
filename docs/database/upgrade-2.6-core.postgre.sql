-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.5.0 2.6.0
-- Copyright 2021 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

ALTER TABLE g_user_auth_scheme_module_instance
ADD guasmi_forbid_user_profile SMALLINT DEFAULT 0,
ADD guasmi_forbid_user_reset_credential SMALLINT DEFAULT 0;

CREATE TABLE g_user_middleware_module_instance (
  gummi_id SERIAL PRIMARY KEY,
  gummi_module VARCHAR(128) NOT NULL,
  gummi_order INTEGER NOT NULL,
  gummi_name VARCHAR(128) NOT NULL,
  gummi_display_name VARCHAR(256) DEFAULT '',
  gummi_parameters TEXT,
  gummi_enabled SMALLINT DEFAULT 1
);

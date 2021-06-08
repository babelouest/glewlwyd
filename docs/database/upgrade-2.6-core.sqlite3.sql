-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.5.0 2.6.0
-- Copyright 2021 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

ALTER TABLE g_user_auth_scheme_module_instance
ADD guasmi_forbid_user_profile INTEGER DEFAULT 0,
ADD guasmi_forbid_user_reset_credential INTEGER DEFAULT 0;

CREATE TABLE g_user_middleware_module_instance (
  gummi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gummi_module TEXT NOT NULL,
  gummi_order INTEGER NOT NULL,
  gummi_name TEXT NOT NULL,
  gummi_display_name TEXT DEFAULT '',
  gummi_parameters TEXT,
  gummi_enabled INTEGER DEFAULT 1
);

-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.5.0 2.6.0
-- Copyright 2021 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

ALTER TABLE g_user_auth_scheme_module_instance
ADD guasmi_forbid_user_profile TINYINT(1) DEFAULT 0,
ADD guasmi_forbid_user_reset_credential TINYINT(1) DEFAULT 0;

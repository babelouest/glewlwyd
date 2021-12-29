-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.6.0 2.7.0
-- Copyright 2021 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

CREATE TABLE g_misc_config (
  gmc_id INT(11) INTEGER PRIMARY KEY AUTOINCREMENT,
  gmc_type TEXT NOT NULL,
  gmc_name TEXT,
  gmc_value TEXT
);
CREATE INDEX i_gmc_type ON g_misc_config(gmc_type);
CREATE INDEX i_gmc_name ON g_misc_config(gmc_name);

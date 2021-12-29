-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.6.0 2.7.0
-- Copyright 2021 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

CREATE TABLE g_misc_config (
  gmc_id INT(11) PRIMARY KEY,
  gmc_type VARCHAR(128) NOT NULL,
  gmc_name VARCHAR(128),
  gmc_value TEXT DEFAULT NULL
);
CREATE INDEX i_gmc_type ON g_misc_config(gmc_type);
CREATE INDEX i_gmc_name ON g_misc_config(gmc_name);

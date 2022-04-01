-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.6.0 2.7.0
-- Copyright 2021 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

CREATE TABLE g_misc_config (
  gmc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gmc_type TEXT NOT NULL,
  gmc_name TEXT,
  gmc_value TEXT
);
CREATE INDEX i_gmc_type ON g_misc_config(gmc_type);
CREATE INDEX i_gmc_name ON g_misc_config(gmc_name);

ALTER TABLE gpo_code
Add gpoc_dpop_jkt TEXT;

ALTER TABLE gpo_device_authorization
Add gpoc_dpop_jkt TEXT;

ALTER TABLE gpo_par
Add gpop_dpop_jkt TEXT;

ALTER TABLE gpo_ciba
Add gpob_dpop_jkt TEXT;

CREATE TABLE gpo_dpop_client_nonce (
  gpodcn_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpodcn_client_id TEXT NOT NULL,
  gpodcn_nonce TEXT NOT NULL,
  gpodcn_counter INTEGER DEFAULT 0
);

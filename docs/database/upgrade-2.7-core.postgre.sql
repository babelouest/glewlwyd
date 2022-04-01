-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.6.0 2.7.0
-- Copyright 2021 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

CREATE TABLE g_misc_config (
  gmc_id SERIAL PRIMARY KEY,
  gmc_type VARCHAR(128) NOT NULL,
  gmc_name VARCHAR(128),
  gmc_value TEXT DEFAULT NULL
);
CREATE INDEX i_gmc_type ON g_misc_config(gmc_type);
CREATE INDEX i_gmc_name ON g_misc_config(gmc_name);

ALTER TABLE gpo_code
Add gpoc_dpop_jkt VARCHAR(512);

ALTER TABLE gpo_device_authorization
Add gpoda_dpop_jkt VARCHAR(512);

ALTER TABLE gpo_par
Add gpop_dpop_jkt VARCHAR(512);

ALTER TABLE gpo_ciba
Add gpob_dpop_jkt VARCHAR(512);

CREATE TABLE gpo_dpop_client_nonce (
  gpodcn_id SERIAL PRIMARY KEY,
  gpodcn_client_id VARCHAR(256) NOT NULL,
  gpodcn_nonce VARCHAR(128) NOT NULL,
  gpodcn_counter SMALLINT DEFAULT 0
);

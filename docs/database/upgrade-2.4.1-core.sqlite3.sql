-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.4.0 2.4.1
-- Copyright 2020 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

ALTER TABLE gpo_code
ADD gpoc_resource INTEGER;

ALTER TABLE gpo_refresh_token
ADD gpor_resource INTEGER;

ALTER TABLE gpo_access_token
ADD gpoa_resource INTEGER;

ALTER TABLE gpo_device_authorization
ADD gpoda_resource INTEGER;

CREATE TABLE gpo_dpop (
  gpod_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpod_plugin_name INTEGER NOT NULL,
  gpod_client_id INTEGER NOT NULL,
  gpod_jti_hash INTEGER NOT NULL,
  gpod_jkt INTEGER NOT NULL,
  gpod_htm INTEGER NOT NULL,
  gpod_htu INTEGER NOT NULL,
  gpod_iat TIMESTAMP NOT NULL,
  gpod_last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX i_gpod_jti_hash ON gpo_dpop(gpod_jti_hash);

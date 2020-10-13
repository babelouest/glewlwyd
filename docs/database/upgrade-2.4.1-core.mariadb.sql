-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.4.0 2.4.1
-- Copyright 2020 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

ALTER TABLE gpo_code
ADD gpoc_resource VARCHAR(512);

ALTER TABLE gpo_refresh_token
ADD gpor_resource VARCHAR(512);

ALTER TABLE gpo_access_token
ADD gpoa_resource VARCHAR(512);

ALTER TABLE gpo_device_authorization
ADD gpoda_resource VARCHAR(512);

CREATE TABLE gpo_dpop (
  gpod_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpod_plugin_name VARCHAR(256) NOT NULL,
  gpod_client_id VARCHAR(256) NOT NULL,
  gpod_jti_hash VARCHAR(512) NOT NULL,
  gpod_jkt VARCHAR(512) NOT NULL,
  gpod_htm VARCHAR(128) NOT NULL,
  gpod_htu VARCHAR(512) NOT NULL,
  gpod_iat TIMESTAMP NOT NULL,
  gpod_last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX i_gpod_jti_hash ON gpo_dpop(gpod_jti_hash);

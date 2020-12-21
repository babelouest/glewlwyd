-- ----------------------------------------------------- --
-- Upgrade Glewlwyd 2.4.0 2.5.0
-- Copyright 2020 Nicolas Mora <mail@babelouest.org>     --
-- License: MIT                                          --
-- ----------------------------------------------------- --

ALTER TABLE g_user_module_instance
ADD gumi_multiple_passwords INTEGER DEFAULT 0;

ALTER TABLE gpo_code
ADD gpoc_resource TEXT;

ALTER TABLE gpo_refresh_token
ADD gpor_resource TEXT;

ALTER TABLE gpo_access_token
ADD gpoa_resource TEXT;

ALTER TABLE gpo_device_authorization
ADD gpoda_resource TEXT;

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

CREATE TABLE g_user_password (
  guw_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gu_id INTEGER,
  guw_password TEXT,
  FOREIGN KEY(gu_id) REFERENCES g_user(gu_id) ON DELETE CASCADE
);

INSERT INTO g_user_password (gu_id, guw_password)
SELECT gu_id, gu_password FROM g_user;

-- SQLite3 doesn't support DROP COLUMN, using a backup table to remove this column is dangerous because of all the foreign keys.
-- So instead I'll set the old gu_password to NULL
UPDATE g_user SET gu_password=NULL;

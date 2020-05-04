-- Upgrade Glewlwyd 2.2.x 2.3.0

ALTER TABLE gpg_access_token
ADD gpoa_jti VARCHAR(128);
CREATE INDEX i_gpoa_jti ON gpo_access_token(gpoa_jti);

-- store device authorization requests
CREATE TABLE gpo_device_authorization (
  gpoda_id SERIAL PRIMARY KEY,
  gpoda_plugin_name VARCHAR(256) NOT NULL,
  gpoda_client_id VARCHAR(256) NOT NULL,
  gpoda_username VARCHAR(256),
  gpoda_created_at TIMESTAMPTZ DEFAULT NOW(),
  gpoda_expires_at TIMESTAMPTZ DEFAULT NOW(),
  gpoda_issued_for VARCHAR(256), -- IP address or hostname of the deice client
  gpoda_device_code_hash VARCHAR(512) NOT NULL,
  gpoda_user_code_hash VARCHAR(512) NOT NULL,
  gpoda_status SMALLINT DEFAULT 0, -- 0: created, 1: user verified, 2 device completed, 3 disabled
  gpoda_last_check TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX i_gpoda_device_code_hash ON gpo_device_authorization(gpoda_device_code_hash);
CREATE INDEX i_gpoda_user_code_hash ON gpo_device_authorization(gpoda_user_code_hash);

CREATE TABLE gpo_device_authorization_scope (
  gpodas_id SERIAL PRIMARY KEY,
  gpoda_id INTEGER,
  gpodas_scope VARCHAR(128) NOT NULL,
  gpodas_allowed SMALLINT DEFAULT 0,
  FOREIGN KEY(gpoda_id) REFERENCES gpo_device_authorization(gpoda_id) ON DELETE CASCADE
);

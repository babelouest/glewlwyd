-- Upgrade Glewlwyd 2.2.x 2.3.0

ALTER TABLE gpg_access_token
ADD gpoa_jti VARCHAR(128);
CREATE INDEX i_gpoa_jti ON gpo_access_token(gpoa_jti);

ALTER TABLE gpo_refresh_token
ADD gpor_jti VARCHAR(128);
CREATE INDEX i_gpor_jti ON gpo_refresh_token(gpor_jti);

ALTER TABLE gpo_client_registration
ADD gpocr_management_at_hash VARCHAR(512);
CREATE INDEX i_gpocr_management_at_hash ON gpo_client_registration(gpocr_management_at_hash);

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

CREATE TABLE gpo_device_scheme (
  gpodh_id SERIAL PRIMARY KEY,
  gpoda_id INTEGER,
  gpodh_scheme_module VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpoda_id) REFERENCES gpo_code(gpo_device_authorization) ON DELETE CASCADE
);

-- store device authorization requests
CREATE TABLE gpg_device_authorization (
  gpgda_id SERIAL PRIMARY KEY,
  gpgda_plugin_name VARCHAR(256) NOT NULL,
  gpgda_client_id VARCHAR(256) NOT NULL,
  gpgda_username VARCHAR(256),
  gpgda_created_at TIMESTAMPTZ DEFAULT NOW(),
  gpgda_expires_at TIMESTAMPTZ DEFAULT NOW(),
  gpgda_issued_for VARCHAR(256), -- IP address or hostname of the deice client
  gpgda_device_code_hash VARCHAR(512) NOT NULL,
  gpgda_user_code_hash VARCHAR(512) NOT NULL,
  gpgda_status SMALLINT DEFAULT 0, -- 0: created, 1: user verified, 2 device completed, 3 disabled
  gpgda_last_check TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX i_gpgda_device_code_hash ON gpg_device_authorization(gpgda_device_code_hash);
CREATE INDEX i_gpgda_user_code_hash ON gpg_device_authorization(gpgda_user_code_hash);

CREATE TABLE gpg_device_authorization_scope (
  gpgdas_id SERIAL PRIMARY KEY,
  gpgda_id INTEGER,
  gpgdas_scope VARCHAR(128) NOT NULL,
  gpgdas_allowed SMALLINT DEFAULT 0,
  FOREIGN KEY(gpgda_id) REFERENCES gpg_device_authorization(gpgda_id) ON DELETE CASCADE
);

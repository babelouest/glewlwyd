-- Upgrade Glewlwyd 2.2.x 2.3.0

ALTER TABLE gpg_access_token
ADD gpoa_jti TEXT;
CREATE INDEX i_gpoa_jti ON gpo_access_token(gpoa_jti);

-- store device authorization requests
CREATE TABLE gpo_device_authorization (
  gpoda_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoda_plugin_name TEXT NOT NULL,
  gpoda_client_id TEXT NOT NULL,
  gpoda_username TEXT,
  gpoda_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoda_expires_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoda_issued_for TEXT, -- IP address or hostname of the deice client
  gpoda_device_code_hash TEXT NOT NULL,
  gpoda_user_code_hash TEXT NOT NULL,
  gpoda_status INTEGER DEFAULT 0, -- 0: created, 1: user verified, 2 device completed, 3 disabled
  gpoda_last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX i_gpoda_device_code_hash ON gpo_device_authorization(gpoda_device_code_hash);
CREATE INDEX i_gpoda_user_code_hash ON gpo_device_authorization(gpoda_user_code_hash);

CREATE TABLE gpo_device_authorization_scope (
  gpodas_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoda_id INTEGER,
  gpodas_scope TEXT NOT NULL,
  gpodas_allowed INTEGER DEFAULT 0,
  FOREIGN KEY(gpoda_id) REFERENCES gpo_device_authorization(gpoda_id) ON DELETE CASCADE
);

-- store device authorization requests
CREATE TABLE gpg_device_authorization (
  gpgda_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpgda_plugin_name TEXT NOT NULL,
  gpgda_client_id TEXT NOT NULL,
  gpgda_username TEXT,
  gpgda_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpgda_expires_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpgda_issued_for TEXT, -- IP address or hostname of the deice client
  gpgda_device_code_hash TEXT NOT NULL,
  gpgda_user_code_hash TEXT NOT NULL,
  gpgda_status INTEGER DEFAULT 0, -- 0: created, 1: user verified, 2 device completed, 3 disabled
  gpgda_last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX i_gpgda_device_code_hash ON gpg_device_authorization(gpgda_device_code_hash);
CREATE INDEX i_gpgda_user_code_hash ON gpg_device_authorization(gpgda_user_code_hash);

CREATE TABLE gpg_device_authorization_scope (
  gpgdas_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpgda_id INTEGER,
  gpgdas_scope TEXT NOT NULL,
  gpgdas_allowed INTEGER DEFAULT 0,
  FOREIGN KEY(gpgda_id) REFERENCES gpg_device_authorization(gpgda_id) ON DELETE CASCADE
);

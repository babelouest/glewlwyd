-- Upgrade Glewlwyd 2.2.x 2.3.0

ALTER TABLE gpg_access_token
ADD gpoa_jti VARCHAR(128);
CREATE INDEX i_gpoa_jti ON gpo_access_token(gpoa_jti);

-- store device authorization requests
CREATE TABLE gpo_device_authorization (
  gpoda_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoda_plugin_name VARCHAR(256) NOT NULL,
  gpoda_client_id VARCHAR(256) NOT NULL,
  gpoda_username VARCHAR(256),
  gpoda_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoda_expires_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoda_issued_for VARCHAR(256), -- IP address or hostname of the deice client
  gpoda_device_code_hash VARCHAR(512) NOT NULL,
  gpoda_user_code_hash VARCHAR(512) NOT NULL,
  gpoda_status TINYINT(1) DEFAULT 0, -- 0: created, 1: user verified, 2 device completed, 3 disabled
  gpoda_last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX i_gpoda_device_code_hash ON gpo_device_authorization(gpoda_device_code_hash);
CREATE INDEX i_gpoda_user_code_hash ON gpo_device_authorization(gpoda_user_code_hash);

CREATE TABLE gpo_device_authorization_scope (
  gpodas_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gpoda_id INT(11),
  gpodas_scope VARCHAR(128) NOT NULL,
  gpodas_allowed TINYINT(1) DEFAULT 0,
  FOREIGN KEY(gpoda_id) REFERENCES gpo_device_authorization(gpoda_id) ON DELETE CASCADE
);

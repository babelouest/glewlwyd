DROP TABLE IF EXISTS gpo_client_registration;
DROP TABLE IF EXISTS gpo_subject_identifier;
DROP TABLE IF EXISTS gpo_id_token;
DROP TABLE IF EXISTS gpo_access_token_scope;
DROP TABLE IF EXISTS gpo_access_token;
DROP TABLE IF EXISTS gpo_refresh_token_scope;
DROP TABLE IF EXISTS gpo_refresh_token;
DROP TABLE IF EXISTS gpo_code_scheme;
DROP TABLE IF EXISTS gpo_code_scope;
DROP TABLE IF EXISTS gpo_code;
DROP TABLE IF EXISTS gpo_client_token_request;
DROP TABLE IF EXISTS gpo_device_scheme;
DROP TABLE IF EXISTS gpo_device_authorization_scope;
DROP TABLE IF EXISTS gpo_device_authorization;

CREATE TABLE gpo_code (
  gpoc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoc_plugin_name TEXT NOT NULL,
  gpoc_authorization_type INTEGER NOT NULL,
  gpoc_username TEXT NOT NULL,
  gpoc_client_id TEXT NOT NULL,
  gpoc_redirect_uri TEXT NOT NULL,
  gpoc_code_hash TEXT NOT NULL,
  gpoc_nonce TEXT,
  gpoc_claims_request TEXT DEFAULT NULL,
  gpoc_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpoc_issued_for TEXT, -- IP address or hostname
  gpoc_user_agent TEXT,
  gpoc_code_challenge TEXT,
  gpoc_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gpoc_code_hash ON gpo_code(gpoc_code_hash);
CREATE INDEX i_gpoc_code_challenge ON gpo_code(gpoc_code_challenge);

CREATE TABLE gpo_code_scope (
  gpocs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoc_id INTEGER,
  gpocs_scope TEXT NOT NULL,
  FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE
);

CREATE TABLE gpo_code_scheme (
  gpoch_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoc_id INTEGER,
  gpoch_scheme_module TEXT NOT NULL,
  FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE
);

CREATE TABLE gpo_refresh_token (
  gpor_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpor_plugin_name TEXT NOT NULL,
  gpor_authorization_type INTEGER NOT NULL,
  gpoc_id INTEGER DEFAULT NULL,
  gpor_username TEXT NOT NULL,
  gpor_client_id TEXT,
  gpor_claims_request TEXT DEFAULT NULL,
  gpor_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_duration INTEGER,
  gpor_rolling_expiration INTEGER DEFAULT 0,
  gpor_issued_for TEXT, -- IP address or hostname
  gpor_user_agent TEXT,
  gpor_token_hash TEXT NOT NULL,
  gpor_jti TEXT,
  gpor_enabled INTEGER DEFAULT 1,
  FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE
);
CREATE INDEX i_gpor_token_hash ON gpo_refresh_token(gpor_token_hash);
CREATE INDEX i_gpor_jti ON gpo_refresh_token(gpor_jti);

CREATE TABLE gpo_refresh_token_scope (
  gpors_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpor_id INTEGER,
  gpors_scope TEXT NOT NULL,
  FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE
);

-- Access token table, to store meta information on access token sent
CREATE TABLE gpo_access_token (
  gpoa_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoa_plugin_name TEXT NOT NULL,
  gpoa_authorization_type INTEGER NOT NULL,
  gpor_id INTEGER DEFAULT NULL,
  gpoa_username TEXT,
  gpoa_client_id TEXT,
  gpoa_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoa_issued_for TEXT, -- IP address or hostname
  gpoa_user_agent TEXT,
  gpoa_token_hash TEXT NOT NULL,
  gpoa_jti TEXT,
  gpoa_enabled INTEGER DEFAULT 1,
  FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE
);
CREATE INDEX i_gpoa_token_hash ON gpo_access_token(gpoa_token_hash);
CREATE INDEX i_gpoa_jti ON gpo_access_token(gpoa_jti);

CREATE TABLE gpo_access_token_scope (
  gpoas_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoa_id INT(11),
  gpoas_scope TEXT NOT NULL,
  FOREIGN KEY(gpoa_id) REFERENCES gpo_access_token(gpoa_id) ON DELETE CASCADE
);

-- Id token table, to store meta information on id token sent
CREATE TABLE gpo_id_token (
  gpoi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoi_plugin_name TEXT NOT NULL,
  gpoi_authorization_type INTEGER NOT NULL,
  gpoi_username TEXT,
  gpoi_client_id TEXT,
  gpoi_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoi_issued_for TEXT, -- IP address or hostname
  gpoi_user_agent TEXT,
  gpoi_hash TEXT,
  gpoi_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gpoi_hash ON gpo_id_token(gpoi_hash);

-- subject identifier table to store subs and their relations to usernames, client_id and sector_identifier
CREATE TABLE gpo_subject_identifier (
  gposi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gposi_plugin_name TEXT NOT NULL,
  gposi_username TEXT NOT NULL,
  gposi_client_id TEXT,
  gposi_sector_identifier_uri TEXT,
  gposi_sub TEXT NOT NULL
);
CREATE INDEX i_gposi_sub ON gpo_subject_identifier(gposi_sub);

-- store meta information on client registration
CREATE TABLE gpo_client_registration (
  gpocr_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpocr_plugin_name TEXT NOT NULL,
  gpocr_cient_id TEXT NOT NULL,
  gpocr_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoa_id INTEGER,
  gpocr_issued_for TEXT, -- IP address or hostname
  gpocr_user_agent TEXT,
  FOREIGN KEY(gpoa_id) REFERENCES gpo_access_token(gpoa_id) ON DELETE CASCADE
);

-- store meta information about client request on token endpoint
CREATE TABLE gpo_client_token_request (
  gpoctr_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoctr_plugin_name TEXT NOT NULL,
  gpoctr_cient_id TEXT NOT NULL,
  gpoctr_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoctr_issued_for TEXT, -- IP address or hostname
  gpoctr_jti_hash TEXT
);

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

CREATE TABLE gpo_device_scheme (
  gpodh_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoda_id INTEGER,
  gpodh_scheme_module TEXT NOT NULL,
  FOREIGN KEY(gpoda_id) REFERENCES gpo_device_authorization(gpoda_id) ON DELETE CASCADE
);

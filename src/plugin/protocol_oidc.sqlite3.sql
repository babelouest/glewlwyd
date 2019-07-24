DROP TABLE IF EXISTS gpo_id_token_scope;
DROP TABLE IF EXISTS gpo_id_token;
DROP TABLE IF EXISTS gpo_access_token_scope;
DROP TABLE IF EXISTS gpo_access_token;
DROP TABLE IF EXISTS gpo_refresh_token_scope;
DROP TABLE IF EXISTS gpo_refresh_token;
DROP TABLE IF EXISTS gpo_code_scheme;
DROP TABLE IF EXISTS gpo_code_scope;
DROP TABLE IF EXISTS gpo_code;

CREATE TABLE gpo_code (
  gpoc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoc_authorization_type INTEGER NOT NULL,
  gpoc_username TEXT NOT NULL,
  gpoc_client_id TEXT NOT NULL,
  gpoc_redirect_uri TEXT NOT NULL,
  gpoc_code_hash TEXT NOT NULL,
  gpoc_nonce TEXT,
  gpoc_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpoc_issued_for TEXT, -- IP address or hostname
  gpoc_user_agent TEXT,
  gpoc_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gpoc_code_hash ON gpo_code(gpoc_code_hash);

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
  gpor_authorization_type INTEGER NOT NULL,
  gpoc_id INTEGER DEFAULT NULL,
  gpor_username TEXT NOT NULL,
  gpor_client_id TEXT,
  gpor_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_duration INTEGER,
  gpor_rolling_expiration INTEGER DEFAULT 0,
  gpor_issued_for TEXT, -- IP address or hostname
  gpor_user_agent TEXT,
  gpor_token_hash TEXT NOT NULL,
  gpor_enabled INTEGER DEFAULT 1,
  FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE
);
CREATE INDEX i_gpor_token_hash ON gpo_refresh_token(gpor_token_hash);

CREATE TABLE gpo_refresh_token_scope (
  gpors_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpor_id INTEGER,
  gpors_scope TEXT NOT NULL,
  FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE
);

-- Access token table, to store meta information on access token sent
CREATE TABLE gpo_access_token (
  gpoa_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoa_authorization_type INTEGER NOT NULL,
  gpor_id INTEGER DEFAULT NULL,
  gpoa_username TEXT,
  gpoa_client_id TEXT,
  gpoa_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoa_issued_for TEXT, -- IP address or hostname
  gpoa_user_agent TEXT,
  FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE
);

CREATE TABLE gpo_access_token_scope (
  gpoas_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoa_id INT(11),
  gpoas_scope TEXT NOT NULL,
  FOREIGN KEY(gpoa_id) REFERENCES gpo_access_token(gpoa_id) ON DELETE CASCADE
);

-- Id token table, to store meta information on id token sent
CREATE TABLE gpo_id_token (
  gpoi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoi_authorization_type INTEGER NOT NULL,
  gpoi_username TEXT,
  gpoi_client_id TEXT,
  gpoi_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoi_issued_for TEXT, -- IP address or hostname
  gpoi_user_agent TEXT,
  gpoi_hash TEXT
);

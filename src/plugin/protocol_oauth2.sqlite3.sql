DROP TABLE IF EXISTS gpg_access_token_scope;
DROP TABLE IF EXISTS gpg_access_token;
DROP TABLE IF EXISTS gpg_refresh_token_scope;
DROP TABLE IF EXISTS gpg_refresh_token;
DROP TABLE IF EXISTS gpg_code_scope;
DROP TABLE IF EXISTS gpg_code;

CREATE TABLE gpg_code (
  gpgc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpgc_plugin_name TEXT NOT NULL,
  gpgc_username TEXT NOT NULL,
  gpgc_client_id TEXT NOT NULL,
  gpgc_redirect_uri TEXT NOT NULL,
  gpgc_code_hash TEXT NOT NULL,
  gpgc_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgc_issued_for TEXT, -- IP address or hostname
  gpgc_user_agent TEXT,
  gpgc_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gpgc_code_hash ON gpg_code(gpgc_code_hash);

CREATE TABLE gpg_code_scope (
  gpgcs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpgc_id INTEGER,
  gpgcs_scope TEXT NOT NULL,
  FOREIGN KEY(gpgc_id) REFERENCES gpg_code(gpgc_id) ON DELETE CASCADE
);

CREATE TABLE gpg_refresh_token (
  gpgr_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpgr_plugin_name TEXT NOT NULL,
  gpgr_authorization_type INTEGER NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  gpgc_id INTEGER DEFAULT NULL,
  gpgr_username TEXT NOT NULL,
  gpgr_client_id TEXT,
  gpgr_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgr_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgr_last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpgr_duration INTEGER,
  gpgr_rolling_expiration INTEGER DEFAULT 0,
  gpgr_issued_for TEXT, -- IP address or hostname
  gpgr_user_agent TEXT,
  gpgr_token_hash TEXT NOT NULL,
  gpgr_enabled INTEGER DEFAULT 1,
  FOREIGN KEY(gpgc_id) REFERENCES gpg_code(gpgc_id) ON DELETE CASCADE
);
CREATE INDEX i_gpgr_token_hash ON gpg_refresh_token(gpgr_token_hash);

CREATE TABLE gpg_refresh_token_scope (
  gpgrs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpgr_id INTEGER,
  gpgrs_scope TEXT NOT NULL,
  FOREIGN KEY(gpgr_id) REFERENCES gpg_refresh_token(gpgr_id) ON DELETE CASCADE
);

-- Access token table, to store meta information on access token sent
CREATE TABLE gpg_access_token (
  gpga_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpga_plugin_name TEXT NOT NULL,
  gpga_authorization_type INTEGER NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  gpgr_id INTEGER DEFAULT NULL,
  gpga_username TEXT,
  gpga_client_id TEXT,
  gpga_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpga_issued_for TEXT, -- IP address or hostname
  gpga_user_agent TEXT,
  FOREIGN KEY(gpgr_id) REFERENCES gpg_refresh_token(gpgr_id) ON DELETE CASCADE
);

CREATE TABLE gpg_access_token_scope (
  gpgas_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpga_id INT(11),
  gpgas_scope TEXT NOT NULL,
  FOREIGN KEY(gpga_id) REFERENCES gpg_access_token(gpga_id) ON DELETE CASCADE
);

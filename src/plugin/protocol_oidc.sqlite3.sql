DROP TABLE IF EXISTS gpo_ciba_scope;
DROP TABLE IF EXISTS gpo_ciba_scheme;
DROP TABLE IF EXISTS gpo_ciba;
DROP TABLE IF EXISTS gpo_par_scope;
DROP TABLE IF EXISTS gpo_par;
DROP TABLE IF EXISTS gpo_rar;
DROP TABLE IF EXISTS gpo_dpop;
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
  gpoc_resource TEXT,
  gpoc_claims_request TEXT DEFAULT NULL,
  gpoc_authorization_details TEXT DEFAULT NULL,
  gpoc_s_hash TEXT,
  gpoc_sid TEXT,
  gpoc_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpoc_issued_for TEXT, -- IP address or hostname
  gpoc_user_agent TEXT,
  gpoc_code_challenge TEXT,
  gpoc_dpop_jkt TEXT,
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
  gpor_resource TEXT,
  gpor_claims_request TEXT DEFAULT NULL,
  gpor_authorization_details TEXT DEFAULT NULL,
  gpor_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpor_duration INTEGER,
  gpor_rolling_expiration INTEGER DEFAULT 0,
  gpor_issued_for TEXT, -- IP address or hostname
  gpor_user_agent TEXT,
  gpor_token_hash TEXT NOT NULL,
  gpor_jti TEXT,
  gpor_dpop_jkt TEXT,
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
  gpoa_resource TEXT,
  gpoa_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoa_issued_for TEXT, -- IP address or hostname
  gpoa_user_agent TEXT,
  gpoa_token_hash TEXT NOT NULL,
  gpoa_jti TEXT,
  gpoa_authorization_details TEXT DEFAULT NULL,
  gpoa_enabled INTEGER DEFAULT 1,
  FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE
);
CREATE INDEX i_gpoa_token_hash ON gpo_access_token(gpoa_token_hash);
CREATE INDEX i_gpoa_jti ON gpo_access_token(gpoa_jti);

CREATE TABLE gpo_access_token_scope (
  gpoas_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoa_id INTEGER,
  gpoas_scope TEXT NOT NULL,
  FOREIGN KEY(gpoa_id) REFERENCES gpo_access_token(gpoa_id) ON DELETE CASCADE
);

-- Id token table, to store meta information on id token sent
CREATE TABLE gpo_id_token (
  gpoi_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpoc_id INTEGER,
  gpor_id INTEGER,
  gpoi_plugin_name TEXT NOT NULL,
  gpoi_authorization_type INTEGER NOT NULL,
  gpoi_username TEXT,
  gpoi_client_id TEXT,
  gpoi_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoi_issued_for TEXT, -- IP address or hostname
  gpoi_user_agent TEXT,
  gpoi_hash TEXT,
  gpoi_sid TEXT,
  gpoi_enabled INTEGER DEFAULT 1,
  FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE,
  FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE
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
  gpocr_management_at_hash TEXT,
  gpocr_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoa_id INTEGER,
  gpocr_issued_for TEXT, -- IP address or hostname
  gpocr_user_agent TEXT,
  FOREIGN KEY(gpoa_id) REFERENCES gpo_access_token(gpoa_id) ON DELETE CASCADE
);
CREATE INDEX i_gpocr_management_at_hash ON gpo_client_registration(gpocr_management_at_hash);

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
  gpoda_resource TEXT,
  gpoda_username TEXT,
  gpoda_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoda_expires_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gpoda_issued_for TEXT, -- IP address or hostname of the device client
  gpoda_device_code_hash TEXT NOT NULL,
  gpoda_user_code_hash TEXT NOT NULL,
  gpoda_sid TEXT,
  gpoda_status INTEGER DEFAULT 0, -- 0: created, 1: user verified, 2 device completed, 3 disabled
  gpoda_authorization_details TEXT DEFAULT NULL,
  gpoda_dpop_jkt TEXT,
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

CREATE TABLE gpo_dpop (
  gpod_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpod_plugin_name TEXT NOT NULL,
  gpod_client_id TEXT NOT NULL,
  gpod_jti_hash TEXT NOT NULL,
  gpod_jkt TEXT NOT NULL,
  gpod_htm TEXT NOT NULL,
  gpod_htu TEXT NOT NULL,
  gpod_iat TIMESTAMP NOT NULL,
  gpod_last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX i_gpod_jti_hash ON gpo_dpop(gpod_jti_hash);

CREATE TABLE gpo_rar (
  gporar_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gporar_plugin_name TEXT NOT NULL,
  gporar_client_id TEXT NOT NULL,
  gporar_type TEXT NOT NULL,
  gporar_username TEXT,
  gporar_consent INTEGER DEFAULT 0,
  gporar_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gporar_client_id ON gpo_rar(gporar_client_id);
CREATE INDEX i_gporar_type ON gpo_rar(gporar_type);
CREATE INDEX i_gporar_username ON gpo_rar(gporar_username);

CREATE TABLE gpo_par (
  gpop_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpop_plugin_name TEXT NOT NULL,
  gpop_response_type TEXT NOT NULL,
  gpop_state TEXT,
  gpop_username TEXT,
  gpop_client_id TEXT NOT NULL,
  gpop_redirect_uri TEXT NOT NULL,
  gpop_request_uri_hash TEXT NOT NULL,
  gpop_nonce TEXT,
  gpop_code_challenge TEXT,
  gpop_resource TEXT,
  gpop_dpop_jkt TEXT,
  gpop_claims_request TEXT DEFAULT NULL,
  gpop_authorization_details TEXT DEFAULT NULL,
  gpop_additional_parameters TEXT DEFAULT NULL,
  gpop_status INTEGER DEFAULT 0, -- 0 created, 1 validated, 2 completed
  gpop_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpop_issued_for TEXT, -- IP address or hostname
  gpop_user_agent TEXT
);
CREATE INDEX i_gpop_client_id ON gpo_par(gpop_client_id);
CREATE INDEX i_gpop_request_uri_hash ON gpo_par(gpop_request_uri_hash);
CREATE INDEX i_gpop_code_challenge ON gpo_par(gpop_code_challenge);

CREATE TABLE gpo_par_scope (
  gpops_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpop_id INTEGER,
  gpops_scope TEXT NOT NULL,
  FOREIGN KEY(gpop_id) REFERENCES gpo_par(gpop_id) ON DELETE CASCADE
);

CREATE TABLE gpo_ciba (
  gpob_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpob_plugin_name TEXT NOT NULL,
  gpob_client_id TEXT NOT NULL,
  gpob_x5t_s256 TEXT,
  gpob_username TEXT NOT NULL,
  gpob_client_notification_token TEXT,
  gpob_jti_hash TEXT,
  gpob_auth_req_id TEXT,
  gpob_user_req_id TEXT,
  gpob_binding_message TEXT,
  gpob_sid TEXT,
  gpob_status INTEGER DEFAULT 0, -- 0: created, 1: accepted, 2: error, 3: closed
  gpob_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gpob_issued_for TEXT, -- IP address or hostname
  gpob_user_agent TEXT,
  gpob_enabled INTEGER DEFAULT 1
);
CREATE INDEX i_gpob_client_id ON gpo_ciba(gpob_client_id);
CREATE INDEX i_gpob_jti_hash ON gpo_ciba(gpob_jti_hash);
CREATE INDEX i_gpob_client_notification_token ON gpo_ciba(gpob_client_notification_token);
CREATE INDEX i_gpob_auth_req_id ON gpo_ciba(gpob_auth_req_id);
CREATE INDEX i_gpob_user_req_id ON gpo_ciba(gpob_user_req_id);

CREATE TABLE gpo_ciba_scope (
  gpocs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpob_id INTEGER,
  gpops_scope TEXT NOT NULL,
  gpobs_granted INTEGER DEFAULT 0,
  FOREIGN KEY(gpob_id) REFERENCES gpo_ciba(gpob_id) ON DELETE CASCADE
);

CREATE TABLE gpo_ciba_scheme (
  gpobh_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gpob_id INTEGER,
  gpobh_scheme_module TEXT NOT NULL,
  FOREIGN KEY(gpob_id) REFERENCES gpo_ciba(gpob_id) ON DELETE CASCADE
);

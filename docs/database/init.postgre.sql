-- ----------------------------------------------------- --
--                PostgreSQL Database                    --
-- Initialize Glewlwyd Database for the backend server   --
-- The administration client app                         --
-- ----------------------------------------------------- --

DROP TABLE IF EXISTS g_client_user_scope;
DROP TABLE IF EXISTS g_scope_group_auth_scheme_module_instance;
DROP TABLE IF EXISTS g_scope_group;
DROP TABLE IF EXISTS g_user_session_scheme;
DROP TABLE IF EXISTS g_scope;
DROP TABLE IF EXISTS g_plugin_module_instance;
DROP TABLE IF EXISTS g_user_module_instance;
DROP TABLE IF EXISTS g_user_auth_scheme_module_instance;
DROP TABLE IF EXISTS g_client_module_instance;
DROP TABLE IF EXISTS g_user_session;
DROP TABLE IF EXISTS g_client_property;
DROP TABLE IF EXISTS g_client_scope_client;
DROP TABLE IF EXISTS g_client_scope;
DROP TABLE IF EXISTS g_client;
DROP TABLE IF EXISTS g_user_property;
DROP TABLE IF EXISTS g_user_scope_user;
DROP TABLE IF EXISTS g_user_scope;
DROP TABLE IF EXISTS g_user;
DROP TABLE IF EXISTS gpg_access_token_scope;
DROP TABLE IF EXISTS gpg_access_token;
DROP TABLE IF EXISTS gpg_refresh_token_scope;
DROP TABLE IF EXISTS gpg_refresh_token;
DROP TABLE IF EXISTS gpg_code_scope;
DROP TABLE IF EXISTS gpg_code;
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
DROP TABLE IF EXISTS gs_code;
DROP TABLE IF EXISTS gs_webauthn_assertion;
DROP TABLE IF EXISTS gs_webauthn_credential;
DROP TABLE IF EXISTS gs_webauthn_user;
DROP TABLE IF EXISTS gs_otp;
DROP TABLE IF EXISTS gs_user_certificate;
DROP TABLE IF EXISTS gs_user_pkcs12;
DROP TABLE IF EXISTS gpr_session;
DROP TABLE IF EXISTS gs_oauth2_session;
DROP TABLE IF EXISTS gs_oauth2_registration;

CREATE TABLE g_user_module_instance (
  gumi_id SERIAL PRIMARY KEY,
  gumi_module VARCHAR(128) NOT NULL,
  gumi_order INTEGER NOT NULL,
  gumi_name VARCHAR(128) NOT NULL,
  gumi_display_name VARCHAR(256) DEFAULT '',
  gumi_parameters TEXT,
  gumi_readonly SMALLINT DEFAULT 0,
  gumi_enabled SMALLINT DEFAULT 1
);

CREATE TABLE g_user_auth_scheme_module_instance (
  guasmi_id SERIAL PRIMARY KEY,
  guasmi_module VARCHAR(128) NOT NULL,
  guasmi_expiration INTEGER NOT NULL DEFAULT 0,
  guasmi_max_use INTEGER DEFAULT 0, -- 0: unlimited
  guasmi_allow_user_register SMALLINT DEFAULT 1,
  guasmi_name VARCHAR(128) NOT NULL,
  guasmi_display_name VARCHAR(256) DEFAULT '',
  guasmi_parameters TEXT,
  guasmi_enabled SMALLINT DEFAULT 1
);

CREATE TABLE g_client_module_instance (
  gcmi_id SERIAL PRIMARY KEY,
  gcmi_module VARCHAR(128) NOT NULL,
  gcmi_order INTEGER NOT NULL,
  gcmi_name VARCHAR(128) NOT NULL,
  gcmi_display_name VARCHAR(256) DEFAULT '',
  gcmi_parameters TEXT,
  gcmi_readonly SMALLINT DEFAULT 0,
  gcmi_enabled SMALLINT DEFAULT 1
);

CREATE TABLE g_plugin_module_instance (
  gpmi_id SERIAL PRIMARY KEY,
  gpmi_module VARCHAR(128) NOT NULL,
  gpmi_name VARCHAR(128) NOT NULL,
  gpmi_display_name VARCHAR(256) DEFAULT '',
  gpmi_parameters TEXT,
  gpmi_enabled SMALLINT DEFAULT 1
);

CREATE TABLE g_user_session (
  gus_id SERIAL PRIMARY KEY,
  gus_session_hash VARCHAR(128) NOT NULL,
  gus_user_agent VARCHAR(256),
  gus_issued_for VARCHAR(256), -- IP address or hostname
  gus_username VARCHAR(256) NOT NULL,
  gus_expiration TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gus_last_login TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gus_current SMALLINT,
  gus_enabled SMALLINT DEFAULT 1
);
CREATE INDEX i_g_user_session_username ON g_user_session(gus_username);
CREATE INDEX i_g_user_session_last_login ON g_user_session(gus_last_login);
CREATE INDEX i_g_user_session_expiration ON g_user_session(gus_expiration);

CREATE TABLE g_user_session_scheme (
  guss_id SERIAL PRIMARY KEY,
  gus_id INTEGER NOT NULL,
  guasmi_id INTEGER DEFAULT NULL, -- NULL means scheme 'password'
  guss_expiration TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  guss_last_login TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  guss_use_counter INTEGER DEFAULT 0,
  guss_enabled SMALLINT DEFAULT 1,
  FOREIGN KEY(gus_id) REFERENCES g_user_session(gus_id) ON DELETE CASCADE,
  FOREIGN KEY(guasmi_id) REFERENCES g_user_auth_scheme_module_instance(guasmi_id) ON DELETE CASCADE
);
CREATE INDEX i_g_user_session_scheme_last_login ON g_user_session_scheme(guss_last_login);
CREATE INDEX i_g_user_session_scheme_expiration ON g_user_session_scheme(guss_expiration);

CREATE TABLE g_scope (
  gs_id SERIAL PRIMARY KEY,
  gs_name VARCHAR(128) NOT NULL UNIQUE,
  gs_display_name VARCHAR(256) DEFAULT '',
  gs_description VARCHAR(512),
  gs_password_required SMALLINT DEFAULT 1,
  gs_password_max_age INTEGER DEFAULT 0,
  gs_enabled SMALLINT DEFAULT 1
);

CREATE TABLE g_scope_group (
  gsg_id SERIAL PRIMARY KEY,
  gs_id INTEGER,
  gsg_name VARCHAR(128) NOT NULL,
  FOREIGN KEY(gs_id) REFERENCES g_scope(gs_id) ON DELETE CASCADE
);

CREATE TABLE g_scope_group_auth_scheme_module_instance (
  gsgasmi_id SERIAL PRIMARY KEY,
  gsg_id INTEGER NOT NULL,
  guasmi_id INTEGER NOT NULL,
  FOREIGN KEY(gsg_id) REFERENCES g_scope_group(gsg_id) ON DELETE CASCADE,
  FOREIGN KEY(guasmi_id) REFERENCES g_user_auth_scheme_module_instance(guasmi_id) ON DELETE CASCADE
);

CREATE TABLE g_client_user_scope (
  gcus_id SERIAL PRIMARY KEY,
  gs_id INTEGER NOT NULL,
  gcus_username VARCHAR(256) NOT NULL,
  gcus_client_id VARCHAR(256) NOT NULL,
  gcus_granted TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gcus_enabled SMALLINT DEFAULT 1,
  FOREIGN KEY(gs_id) REFERENCES g_scope(gs_id) ON DELETE CASCADE
);
CREATE INDEX i_g_client_user_scope_username ON g_client_user_scope(gcus_username);
CREATE INDEX i_g_client_user_scope_client_id ON g_client_user_scope(gcus_client_id);

CREATE TABLE g_client (
  gc_id SERIAL PRIMARY KEY,
  gc_client_id VARCHAR(128) NOT NULL UNIQUE,
  gc_name VARCHAR(256) DEFAULT '',
  gc_description VARCHAR(512) DEFAULT '',
  gc_confidential SMALLINT DEFAULT 0,
  gc_password VARCHAR(256),
  gc_enabled SMALLINT DEFAULT 1
);

CREATE TABLE g_client_scope (
  gcs_id SERIAL PRIMARY KEY,
  gcs_name VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE g_client_scope_client (
  gcsu_id SERIAL PRIMARY KEY,
  gc_id SERIAL,
  gcs_id SERIAL,
  FOREIGN KEY(gc_id) REFERENCES g_client(gc_id) ON DELETE CASCADE,
  FOREIGN KEY(gcs_id) REFERENCES g_client_scope(gcs_id) ON DELETE CASCADE
);

CREATE TABLE g_client_property (
  gcp_id SERIAL PRIMARY KEY,
  gc_id SERIAL,
  gcp_name VARCHAR(128) NOT NULL,
  gcp_value TEXT DEFAULT NULL,
  FOREIGN KEY(gc_id) REFERENCES g_client(gc_id) ON DELETE CASCADE
);
CREATE INDEX i_g_client_property_name ON g_client_property(gcp_name);

CREATE TABLE g_user (
  gu_id SERIAL PRIMARY KEY,
  gu_username VARCHAR(128) NOT NULL UNIQUE,
  gu_name VARCHAR(256) DEFAULT '',
  gu_email VARCHAR(512) DEFAULT '',
  gu_password VARCHAR(256),
  gu_enabled SMALLINT DEFAULT 1
);

CREATE TABLE g_user_scope (
  gus_id SERIAL PRIMARY KEY,
  gus_name VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE g_user_scope_user (
  gusu_id SERIAL PRIMARY KEY,
  gu_id SERIAL,
  gus_id SERIAL,
  FOREIGN KEY(gu_id) REFERENCES g_user(gu_id) ON DELETE CASCADE,
  FOREIGN KEY(gus_id) REFERENCES g_user_scope(gus_id) ON DELETE CASCADE
);

CREATE TABLE g_user_property (
  gup_id SERIAL PRIMARY KEY,
  gu_id SERIAL,
  gup_name VARCHAR(128) NOT NULL,
  gup_value TEXT DEFAULT NULL,
  FOREIGN KEY(gu_id) REFERENCES g_user(gu_id) ON DELETE CASCADE
);
CREATE INDEX i_g_user_property_name ON g_user_property(gup_name);

CREATE TABLE gpg_code (
  gpgc_id SERIAL PRIMARY KEY,
  gpgc_plugin_name VARCHAR(256) NOT NULL,
  gpgc_username VARCHAR(256) NOT NULL,
  gpgc_client_id VARCHAR(256) NOT NULL,
  gpgc_redirect_uri VARCHAR(512) NOT NULL,
  gpgc_code_hash VARCHAR(512) NOT NULL,
  gpgc_expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gpgc_issued_for VARCHAR(256), -- IP address or hostname
  gpgc_user_agent VARCHAR(256),
  gpgc_code_challenge VARCHAR(128),
  gpgc_enabled SMALLINT DEFAULT 1
);
CREATE INDEX i_gpgc_code_hash ON gpg_code(gpgc_code_hash);
CREATE INDEX i_gpgc_code_challenge ON gpg_code(gpgc_code_challenge);

CREATE TABLE gpg_code_scope (
  gpgcs_id SERIAL PRIMARY KEY,
  gpgc_id INTEGER,
  gpgcs_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpgc_id) REFERENCES gpg_code(gpgc_id) ON DELETE CASCADE
);

CREATE TABLE gpg_refresh_token (
  gpgr_id SERIAL PRIMARY KEY,
  gpgr_plugin_name VARCHAR(256) NOT NULL,
  gpgr_authorization_type SMALLINT NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  gpgc_id INTEGER DEFAULT NULL,
  gpgr_username VARCHAR(256) NOT NULL,
  gpgr_client_id VARCHAR(256),
  gpgr_issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gpgr_expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gpgr_last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gpgr_duration INTEGER,
  gpgr_rolling_expiration SMALLINT DEFAULT 0,
  gpgr_issued_for VARCHAR(256), -- IP address or hostname
  gpgr_user_agent VARCHAR(256),
  gpgr_token_hash VARCHAR(512) NOT NULL,
  gpgr_enabled SMALLINT DEFAULT 1,
  FOREIGN KEY(gpgc_id) REFERENCES gpg_code(gpgc_id) ON DELETE CASCADE
);
CREATE INDEX i_gpgr_token_hash ON gpg_refresh_token(gpgr_token_hash);

CREATE TABLE gpg_refresh_token_scope (
  gpgrs_id SERIAL PRIMARY KEY,
  gpgr_id INTEGER,
  gpgrs_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpgr_id) REFERENCES gpg_refresh_token(gpgr_id) ON DELETE CASCADE
);

-- Access token table, to store meta information on access token sent
CREATE TABLE gpg_access_token (
  gpga_id SERIAL PRIMARY KEY,
  gpga_plugin_name VARCHAR(256) NOT NULL,
  gpga_authorization_type SMALLINT NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  gpgr_id INTEGER DEFAULT NULL,
  gpga_username VARCHAR(256),
  gpga_client_id VARCHAR(256),
  gpga_issued_at TIMESTAMPTZ DEFAULT NOW(),
  gpga_issued_for VARCHAR(256), -- IP address or hostname
  gpga_user_agent VARCHAR(256),
  gpga_token_hash VARCHAR(512) NOT NULL,
  gpga_enabled TINYINT(1) DEFAULT 1,
  FOREIGN KEY(gpgr_id) REFERENCES gpg_refresh_token(gpgr_id) ON DELETE CASCADE
);
CREATE INDEX i_gpga_token_hash ON gpg_access_token(gpga_token_hash);

CREATE TABLE gpg_access_token_scope (
  gpgas_id SERIAL PRIMARY KEY,
  gpga_id INTEGER,
  gpgas_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpga_id) REFERENCES gpg_access_token(gpga_id) ON DELETE CASCADE
);

CREATE TABLE gpo_code (
  gpoc_id SERIAL PRIMARY KEY,
  gpoc_plugin_name VARCHAR(256) NOT NULL,
  gpoc_authorization_type SMALLINT NOT NULL,
  gpoc_username VARCHAR(256) NOT NULL,
  gpoc_client_id VARCHAR(256) NOT NULL,
  gpoc_redirect_uri VARCHAR(512) NOT NULL,
  gpoc_code_hash VARCHAR(512) NOT NULL,
  gpoc_nonce VARCHAR(512),
  gpoc_claims_request TEXT DEFAULT NULL,
  gpoc_expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gpoc_issued_for VARCHAR(256), -- IP address or hostname
  gpoc_user_agent VARCHAR(256),
  gpoc_code_challenge VARCHAR(128),
  gpoc_enabled SMALLINT DEFAULT 1
);
CREATE INDEX i_gpoc_code_hash ON gpo_code(gpoc_code_hash);
CREATE INDEX i_gpoc_code_challenge ON gpo_code(gpoc_code_challenge);

CREATE TABLE gpo_code_scope (
  gpocs_id SERIAL PRIMARY KEY,
  gpoc_id INTEGER,
  gpocs_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE
);

CREATE TABLE gpo_code_scheme (
  gpoch_id SERIAL PRIMARY KEY,
  gpoc_id INTEGER,
  gpoch_scheme_module VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE
);

CREATE TABLE gpo_refresh_token (
  gpor_id SERIAL PRIMARY KEY,
  gpor_plugin_name VARCHAR(256) NOT NULL,
  gpor_authorization_type SMALLINT NOT NULL,
  gpoc_id INTEGER DEFAULT NULL,
  gpor_username VARCHAR(256) NOT NULL,
  gpor_client_id VARCHAR(256),
  gpor_claims_request TEXT DEFAULT NULL,
  gpor_issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gpor_expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gpor_last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gpor_duration INTEGER,
  gpor_rolling_expiration SMALLINT DEFAULT 0,
  gpor_issued_for VARCHAR(256), -- IP address or hostname
  gpor_user_agent VARCHAR(256),
  gpor_token_hash VARCHAR(512) NOT NULL,
  gpor_enabled SMALLINT DEFAULT 1,
  FOREIGN KEY(gpoc_id) REFERENCES gpo_code(gpoc_id) ON DELETE CASCADE
);
CREATE INDEX i_gpor_token_hash ON gpo_refresh_token(gpor_token_hash);

CREATE TABLE gpo_refresh_token_scope (
  gpors_id SERIAL PRIMARY KEY,
  gpor_id INTEGER,
  gpors_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE
);

-- Access token table, to store meta information on access token sent
CREATE TABLE gpo_access_token (
  gpoa_id SERIAL PRIMARY KEY,
  gpoa_plugin_name VARCHAR(256) NOT NULL,
  gpoa_authorization_type SMALLINT NOT NULL,
  gpor_id INTEGER DEFAULT NULL,
  gpoa_username VARCHAR(256),
  gpoa_client_id VARCHAR(256),
  gpoa_issued_at TIMESTAMPTZ DEFAULT NOW(),
  gpoa_issued_for VARCHAR(256), -- IP address or hostname
  gpoa_user_agent VARCHAR(256),
  gpoa_token_hash VARCHAR(512) NOT NULL,
  gpoa_enabled TINYINT(1) DEFAULT 1,
  FOREIGN KEY(gpor_id) REFERENCES gpo_refresh_token(gpor_id) ON DELETE CASCADE
);
CREATE INDEX i_gpoa_token_hash ON gpo_access_token(gpoa_token_hash);

CREATE TABLE gpo_access_token_scope (
  gpoas_id SERIAL PRIMARY KEY,
  gpoa_id INTEGER,
  gpoas_scope VARCHAR(128) NOT NULL,
  FOREIGN KEY(gpoa_id) REFERENCES gpo_access_token(gpoa_id) ON DELETE CASCADE
);

-- Id token table, to store meta information on id token sent
CREATE TABLE gpo_id_token (
  gpoi_id SERIAL PRIMARY KEY,
  gpoi_plugin_name VARCHAR(256) NOT NULL,
  gpoi_authorization_type SMALLINT NOT NULL,
  gpoi_username VARCHAR(256),
  gpoi_client_id VARCHAR(256),
  gpoi_issued_at TIMESTAMPTZ DEFAULT NOW(),
  gpoi_issued_for VARCHAR(256), -- IP address or hostname
  gpoi_user_agent VARCHAR(256),
  gpoi_hash VARCHAR(512),
  gpoi_enabled SMALLINT(1) DEFAULT 1
);

-- subject identifier table to store subs and their relations to usernames, client_id and sector_identifier
CREATE TABLE gpo_subject_identifier (
  gposi_id SERIAL PRIMARY KEY,
  gposi_plugin_name VARCHAR(256) NOT NULL,
  gposi_username VARCHAR(256) NOT NULL,
  gposi_client_id VARCHAR(256),
  gposi_sector_identifier_uri VARCHAR(256),
  gposi_sub VARCHAR(256) NOT NULL
);
CREATE INDEX i_gposi_sub ON gpo_subject_identifier(gposi_sub);

-- store meta information on client registration
CREATE TABLE gpo_client_registration (
  gpocr_id SERIAL PRIMARY KEY,
  gpocr_plugin_name VARCHAR(256) NOT NULL,
  gpocr_cient_id VARCHAR(256) NOT NULL,
  gpocr_created_at TIMESTAMPTZ DEFAULT NOW(),
  gpoa_id INTEGER,
  gpocr_issued_for VARCHAR(256), -- IP address or hostname
  gpocr_user_agent VARCHAR(256),
  FOREIGN KEY(gpoa_id) REFERENCES gpo_access_token(gpoa_id) ON DELETE CASCADE
);

CREATE TABLE gs_code (
  gsc_id SERIAL PRIMARY KEY,
  gsc_mod_name VARCHAR(128) NOT NULL,
  gsc_issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gsc_username VARCHAR(128) NOT NULL,
  gsc_enabled SMALLINT DEFAULT 1,
  gsc_code_hash VARCHAR(128),
  gsc_result SMALLINT DEFAULT 0
);
CREATE INDEX i_gsc_username ON gs_code(gsc_username);

CREATE TABLE gs_webauthn_user (
  gswu_id SERIAL PRIMARY KEY,
  gswu_mod_name VARCHAR(128) NOT NULL,
  gswu_username VARCHAR(128) NOT NULL,
  gswu_user_id VARCHAR(128) NOT NULL
);
CREATE INDEX i_gswu_username ON gs_webauthn_user(gswu_username);

CREATE TABLE gs_webauthn_credential (
  gswc_id SERIAL PRIMARY KEY,
  gswu_id INTEGER NOT NULL,
  gswc_session_hash VARCHAR(128) NOT NULL,
  gswc_name VARCHAR(128),
  gswc_challenge_hash VARCHAR(128),
  gswc_credential_id VARCHAR(256),
  gswc_certificate VARCHAR(128),
  gswc_public_key TEXT DEFAULT NULL,
  gswc_counter INTEGER DEFAULT 0,
  gswc_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gswc_status SMALLINT DEFAULT 0, -- 0 new, 1 registered, 2 error, 3 disabled, 4 removed
  FOREIGN KEY(gswu_id) REFERENCES gs_webauthn_user(gswu_id) ON DELETE CASCADE
);
CREATE INDEX i_gswc_credential_id ON gs_webauthn_credential(gswc_credential_id);
CREATE INDEX i_gswc_session_hash ON gs_webauthn_credential(gswc_session_hash);

CREATE TABLE gs_webauthn_assertion (
  gswa_id SERIAL PRIMARY KEY,
  gswu_id INTEGER NOT NULL,
  gswc_id INTEGER,
  gswa_session_hash VARCHAR(128) NOT NULL,
  gswa_challenge_hash VARCHAR(128),
  gswa_counter INTEGER DEFAULT 0,
  gswa_issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gswa_status SMALLINT DEFAULT 0, -- 0 new, 1 verified, 2 not verified, 3 error
  gswa_mock SMALLINT DEFAULT 0,
  FOREIGN KEY(gswu_id) REFERENCES gs_webauthn_user(gswu_id) ON DELETE CASCADE,
  FOREIGN KEY(gswc_id) REFERENCES gs_webauthn_credential(gswc_id) ON DELETE CASCADE
);
CREATE INDEX i_gswa_session_hash ON gs_webauthn_assertion(gswa_session_hash);

CREATE TABLE gs_otp (
  gso_id SERIAL PRIMARY KEY,
  gso_mod_name VARCHAR(128) NOT NULL,
  gso_issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gso_last_used TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gso_username VARCHAR(128) NOT NULL,
  gso_otp_type SMALLINT DEFAULT 0, -- 0 HOTP, 1 TOTP
  gso_secret VARCHAR(128) NOT NULL,
  gso_hotp_moving_factor INTEGER,
  gso_totp_time_step_size INTEGER
);
CREATE INDEX i_gsso_username ON gs_otp(gso_username);

CREATE TABLE gs_user_certificate (
  gsuc_id SERIAL PRIMARY KEY,
  gsuc_mod_name VARCHAR(128) NOT NULL,
  gsuc_username VARCHAR(128) NOT NULL,
  gsuc_enabled SMALLINT DEFAULT 1,
  gsuc_x509_certificate_content TEXT DEFAULT NULL,
  gsuc_x509_certificate_id VARCHAR(128) NOT NULL,
  gsuc_x509_certificate_dn VARCHAR(512) NOT NULL,
  gsuc_x509_certificate_issuer_dn VARCHAR(512) NOT NULL,
  gsuc_activation TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gsuc_expiration TIMESTAMPTZ DEFAULT NOW(),
  gsuc_last_used TIMESTAMPTZ DEFAULT NOW(),
  gsuc_last_user_agent VARCHAR(512) DEFAULT NULL
);
CREATE INDEX i_gsuc_username ON gs_user_certificate(gsuc_username);
CREATE INDEX i_gsuc_x509_certificate_id ON gs_user_certificate(gsuc_x509_certificate_id);

CREATE TABLE gs_user_pkcs12 (
  gsup_id SERIAL PRIMARY KEY,
  gsup_mod_name VARCHAR(128) NOT NULL,
  gsup_username VARCHAR(128) NOT NULL,
  gsup_x509_certificate_content TEXT DEFAULT NULL,
  gsup_pkcs12_content TEXT DEFAULT NULL,
  gsup_pkcs12_password VARCHAR(32) DEFAULT NULL,
  gsup_activation TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gsup_expiration TIMESTAMPTZ DEFAULT NOW(),
  gsup_host VARCHAR(512) DEFAULT NULL,
  gsup_user_agent VARCHAR(512) DEFAULT NULL
);
CREATE INDEX i_gsup_username ON gs_user_pkcs12(gsup_username);

CREATE TABLE gpr_session (
  gprs_id SERIAL PRIMARY KEY,
  gprs_plugin_name VARCHAR(256) NOT NULL,
  gprs_username VARCHAR(256) NOT NULL,
  gprs_name VARCHAR(512),
  gprs_email VARCHAR(512),
  gprs_code_hash VARCHAR(512),
  gprs_password_set SMALLINT DEFAULT 0,
  gprs_session_hash VARCHAR(512),
  gprs_token_hash VARCHAR(512),
  gprs_expires_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprs_issued_for VARCHAR(256), -- IP address or hostname
  gprs_user_agent VARCHAR(256),
  gprs_enabled SMALLINT DEFAULT 1
);
CREATE INDEX i_gprs_session_hash ON gpr_session(gprs_session_hash);
CREATE INDEX i_gprs_gprs_token_hash ON gpr_session(gprs_token_hash);
CREATE INDEX i_gprs_gprs_gprs_code_hash ON gpr_session(gprs_code_hash);

CREATE TABLE gs_oauth2_registration (
  gsor_id SERIAL PRIMARY KEY,
  gsor_mod_name VARCHAR(128) NOT NULL,
  gsor_provider VARCHAR(128) NOT NULL,
  gsor_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gsor_username VARCHAR(128) NOT NULL,
  gsor_userinfo_sub VARCHAR(128)
);
CREATE INDEX i_gsor_username ON gs_oauth2_registration(gsor_username);

CREATE TABLE gs_oauth2_session (
  gsos_id SERIAL PRIMARY KEY,
  gsor_id INTEGER,
  gsos_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gsos_expires_at TIMESTAMPTZ,
  gsos_state TEXT NOT NULL,
  gsos_session_export TEXT,
  gsos_status SMALLINT DEFAULT 0, -- 0: registration, 1: authentication, 2: verified, 3: cancelled
  FOREIGN KEY(gsor_id) REFERENCES gs_oauth2_registration(gsor_id) ON DELETE CASCADE
);

INSERT INTO g_scope (gs_name, gs_display_name, gs_description, gs_password_required, gs_password_max_age) VALUES ('g_admin', 'Glewlwyd administration', 'Access to Glewlwyd''s administration API', 1, 600);
INSERT INTO g_scope (gs_name, gs_display_name, gs_description, gs_password_required, gs_password_max_age) VALUES ('g_profile', 'Glewlwyd profile', 'Access to the user''s profile API', 1, 600);
INSERT INTO g_scope (gs_name, gs_display_name, gs_description, gs_password_required, gs_password_max_age) VALUES ('openid', 'Open ID', 'Open ID Connect scope', 0, 0);
INSERT INTO g_user_module_instance (gumi_module, gumi_order, gumi_name, gumi_display_name, gumi_parameters, gumi_readonly) VALUES ('database', 0, 'database', 'Database backend', '{"use-glewlwyd-connection":true,"data-format":{"picture":{"multiple":false,"read":true,"write":true,"profile-read":true,"profile-write":true}}}', 0);
INSERT INTO g_client_module_instance (gcmi_module, gcmi_order, gcmi_name, gcmi_display_name, gcmi_parameters, gcmi_readonly) VALUES ('database', 0, 'database', 'Database backend', '{"use-glewlwyd-connection":true,"data-format":{"redirect_uri":{"multiple":true,"read":true,"write":true},"authorization_type":{"multiple":true,"read":true,"write":true}},"client_secret":{"read":true,"write":true}}', 0);
INSERT INTO g_user (gu_username, gu_name, gu_password, gu_email, gu_enabled) VALUES ('admin', 'The Administrator', crypt('password', gen_salt('bf')), '', 1);
INSERT INTO g_user_scope (gus_name) VALUES ('g_admin');
INSERT INTO g_user_scope (gus_name) VALUES ('g_profile');
INSERT INTO g_user_scope_user (gu_id, gus_id) VALUES ((SELECT gu_id from g_user WHERE gu_username='admin'), (SELECT gus_id FROM g_user_scope WHERE gus_name='g_admin'));
INSERT INTO g_user_scope_user (gu_id, gus_id) VALUES ((SELECT gu_id from g_user WHERE gu_username='admin'), (SELECT gus_id FROM g_user_scope WHERE gus_name='g_profile'));

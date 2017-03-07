-- SQlite3 init script

DROP TABLE IF EXISTS `g_refresh_token_scope`;
DROP TABLE IF EXISTS `g_code_scope`;
DROP TABLE IF EXISTS `g_code`;
DROP TABLE IF EXISTS `g_client_user_scope`;
DROP TABLE IF EXISTS `g_client_authorization_type`;
DROP TABLE IF EXISTS `g_resource_scope`;
DROP TABLE IF EXISTS `g_client_scope`;
DROP TABLE IF EXISTS `g_user_scope`;
DROP TABLE IF EXISTS `g_client_scope`;
DROP TABLE IF EXISTS `g_access_token`;
DROP TABLE IF EXISTS `g_refresh_token`;
DROP TABLE IF EXISTS `g_session`;
DROP TABLE IF EXISTS `g_resource`;
DROP TABLE IF EXISTS `g_reset_password`;
DROP TABLE IF EXISTS `g_redirect_uri`;
DROP TABLE IF EXISTS `g_client`;
DROP TABLE IF EXISTS `g_authorization_type`;
DROP TABLE IF EXISTS `g_scope`;
DROP TABLE IF EXISTS `g_user`;

-- ----------- --
-- Data tables --
-- ----------- --

-- User table, contains registered users with their password encrypted
CREATE TABLE `g_user` (
  `gu_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gu_name` TEXT DEFAULT '',
  `gu_email` TEXT DEFAULT '',
  `gu_login` TEXT NOT NULL UNIQUE,
  `gu_password` TEXT NOT NULL,
  `gu_enabled` INTEGER DEFAULT 1
);
CREATE INDEX `i_g_user` ON `g_user`(`gu_id`);
CREATE INDEX `i_g_user_name` ON `g_user`(`gu_name`);
CREATE INDEX `i_g_user_login` ON `g_user`(`gu_login`);

-- Scope table, contain all scope values available
CREATE TABLE `g_scope` (
  `gs_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gs_name` TEXT NOT NULL,
  `gs_description` TEXT DEFAULT ''
);
CREATE INDEX `i_g_scope` ON `g_scope`(`gs_id`);
CREATE INDEX `i_g_scope_name` ON `g_scope`(`gs_name`);

-- Authorization type table, to store authorization type available
CREATE TABLE `g_authorization_type` (
  `got_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `got_code` INTEGER NOT NULL UNIQUE, -- 0: Authorization Code Grant, 1: Code Grant, 2: Implicit Grant, 3: Resource Owner Password Credentials Grant, 4: Client Credentials Grant
  `got_name` TEXT NOT NULL,
  `got_description` TEXT DEFAULT '',
  `got_enabled` INTEGER DEFAULT 1
);
CREATE INDEX `i_g_authorization_type` ON `g_authorization_type`(`got_id`);
CREATE INDEX `i_g_authorization_name` ON `g_authorization_type`(`got_name`);
CREATE INDEX `i_g_authorization_code` ON `g_authorization_type`(`got_code`);

-- Client table, contains all registered clients with their client_id
CREATE TABLE `g_client` (
  `gc_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gc_name` TEXT NOT NULL,
  `gc_description` TEXT DEFAULT '',
  `gc_client_id` TEXT NOT NULL UNIQUE,
  `gc_client_password` TEXT,
  `gc_confidential` INTEGER DEFAULT 0,
  `gc_enabled` INTEGER DEFAULT 1
);
CREATE INDEX `i_g_client` ON `g_client`(`gc_id`);
CREATE INDEX `i_g_client_name` ON `g_client`(`gc_name`);
CREATE INDEX `i_g_client_id` ON `g_client`(`gc_client_id`);

-- Redirect URI, contains all registered redirect_uti values for the clients
CREATE TABLE `g_redirect_uri` (
  `gru_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gc_id` INTEGER NOT NULL,
  `gru_name` TEXT NOT NULL,
  `gru_uri` TEXT,
  FOREIGN KEY(`gc_id`) REFERENCES `g_client`(`gc_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_redirect_uri` ON `g_redirect_uri`(`gru_id`);

-- Resource table, contains all registered resource server
CREATE TABLE `g_resource` (
  `gr_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gr_name` TEXT NOT NULL UNIQUE,
  `gr_description` TEXT DEFAULT '',
  `gr_uri` TEXT
);
CREATE INDEX `i_g_resource` ON `g_resource`(`gr_id`);
CREATE INDEX `i_g_resource_name` ON `g_resource`(`gr_name`);

-- Reset a user password
CREATE TABLE `g_reset_password` (
  `grp_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `grp_username` TEXT NOT NULL,
  `grp_ip_source` TEXT NOT NULL,
  `grp_token` TEXT NOT NULL,
  `grp_enabled` INTEGER DEFAULT 1,
  `grp_issued_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `grp_reset_at` TIMESTAMP NULL
);
CREATE INDEX `i_g_reset_password` ON `g_reset_password`(`grp_id`);
CREATE INDEX `i_g_reset_password_username` ON `g_reset_password`(`grp_username`);

-- ------------ --
-- Token tables --
-- ------------ --

-- Refresh token table, to store a signature and meta information on all refresh_tokens sent
CREATE TABLE `g_refresh_token` (
  `grt_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `grt_hash` TEXT NOT NULL,
  `grt_authorization_type` INTEGER NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  `grt_username` TEXT NOT NULL,
  `gc_client_id` TEXT,
  `grt_scope` TEXT,
  `grt_issued_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `grt_last_seen` TIMESTAMP NULL,
  `grt_expired_at` TIMESTAMP NULL,
  `grt_ip_source` TEXT NOT NULL,
  `grt_enabled` INTEGER DEFAULT 1
);
CREATE INDEX `i_g_refresh_token` ON `g_refresh_token`(`grt_id`);
CREATE INDEX `i_g_refresh_token_username` ON `g_refresh_token`(`grt_username`);

-- Access token table, to store meta information on access_token sent
CREATE TABLE `g_access_token` (
  `gat_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `grt_id` INTEGER,
  `gat_authorization_type` INTEGER NOT NULL, -- 0: Authorization Code Grant, 1: Implicit Grant, 2: Resource Owner Password Credentials Grant, 3: Client Credentials Grant
  `gat_issued_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `gat_ip_source` TEXT NOT NULL,
  FOREIGN KEY(`grt_id`) REFERENCES `g_refresh_token`(`grt_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_access_token` ON `g_access_token`(`gat_id`);

-- Session table, to store signature and meta information on session tokens sent
CREATE TABLE `g_session` (
  `gss_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gss_hash` TEXT NOT NULL,
  `gss_username` TEXT NOT NULL,
  `gss_issued_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `gss_last_seen` TIMESTAMP NULL,
  `gss_expired_at` TIMESTAMP NULL,
  `gss_ip_source` TEXT NOT NULL,
  `gss_enabled` INTEGER DEFAULT 1
);
CREATE INDEX `i_g_session` ON `g_session`(`gss_id`);
CREATE INDEX `i_g_session_username` ON `g_session`(`gss_username`);

-- -------------- --
-- Linking tables --
-- -------------- --

-- User scope table, to store scope available for each user
CREATE TABLE `g_user_scope` (
  `gus_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gu_id` INTEGER NOT NULL,
  `gs_id` INTEGER NOT NULL,
  FOREIGN KEY(`gu_id`) REFERENCES `g_user`(`gu_id`) ON DELETE CASCADE,
  FOREIGN KEY(`gs_id`) REFERENCES `g_scope`(`gs_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_user_scope` ON `g_user_scope`(`gus_id`);

-- Client scope table, to store scope available for a client on client authentication
CREATE TABLE `g_client_scope` (
  `gcs_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gc_id` INTEGER NOT NULL,
  `gs_id` INTEGER NOT NULL,
  FOREIGN KEY(`gc_id`) REFERENCES `g_client`(`gc_id`) ON DELETE CASCADE,
  FOREIGN KEY(`gs_id`) REFERENCES `g_scope`(`gs_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_client_scope` ON `g_client_scope`(`gcs_id`);

-- Resource scope table, to store scope required for a resource service
CREATE TABLE `g_resource_scope` (
  `grs_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gr_id` INTEGER NOT NULL,
  `gs_id` INTEGER NOT NULL,
  FOREIGN KEY(`gr_id`) REFERENCES `g_resource`(`gr_id`) ON DELETE CASCADE,
  FOREIGN KEY(`gs_id`) REFERENCES `g_scope`(`gs_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_resource_scope` ON `g_resource_scope`(`grs_id`);

-- Client authorization type table, to store authorization types available for the client
CREATE TABLE `g_client_authorization_type` (
  `gcat_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gc_client_id` TEXT NOT NULL,
  `got_id` INTEGER NOT NULL,
  FOREIGN KEY(`got_id`) REFERENCES `g_authorization_type`(`got_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_client_authorization_type` ON `g_client_authorization_type`(`gcat_id`);

-- Client user scope table, to store the authorization of the user to use scope for this client
CREATE TABLE `g_client_user_scope` (
  `gcus_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gc_client_id` TEXT NOT NULL,
  `gco_username` TEXT NOT NULL,
  `gs_id` INTEGER NOT NULL,
  FOREIGN KEY(`gs_id`) REFERENCES `g_scope`(`gs_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_client_user_scope` ON `g_client_user_scope`(`gcus_id`);
CREATE INDEX `i_g_client_user_scope_username` ON `g_client_user_scope`(`gco_username`);

-- Code table, used to store auth code sent with response_type code and validate it with response_type authorization_code
CREATE TABLE `g_code` (
  `gco_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gco_date` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `gco_code_hash` TEXT NOT NULL,
  `gco_ip_source` TEXT NOT NULL,
  `gco_enabled` INTEGER DEFAULT 1,
  `gc_client_id` TEXT NOT NULL,
  `gco_username` TEXT NOT NULL,
  `gco_redirect_uri` TEXT
);
CREATE INDEX `i_g_code` ON `g_code`(`gco_id`);
CREATE INDEX `i_g_code_username` ON `g_code`(`gco_username`);

-- Code scope table, used to link a generated code to a list of scopes
CREATE TABLE `g_code_scope` (
  `gcs_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `gco_id` INTEGER NOT NULL,
  `gs_id` INTEGER NOT NULL,
  FOREIGN KEY(`gco_id`) REFERENCES `g_code`(`gco_id`) ON DELETE CASCADE,
  FOREIGN KEY(`gs_id`) REFERENCES `g_scope`(`gs_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_code_scope` ON `g_code_scope`(`gcs_id`);

-- Refresh token scope table, used to link a generated refresh token to a list of scopes
CREATE TABLE `g_refresh_token_scope` (
  `grts_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `grt_id` INTEGER NOT NULL,
  `gs_id` INTEGER NOT NULL,
  FOREIGN KEY(`grt_id`) REFERENCES `g_refresh_token`(`grt_id`) ON DELETE CASCADE,
  FOREIGN KEY(`gs_id`) REFERENCES `g_scope`(`gs_id`) ON DELETE CASCADE
);
CREATE INDEX `i_g_refresh_token_scope` ON `g_refresh_token_scope`(`grts_id`);

INSERT INTO g_authorization_type (got_name, got_code, got_description) VALUES ('authorization_code', 0, 'Authorization Code Grant - Access token: https://tools.ietf.org/html/rfc6749#section-4.1');
INSERT INTO g_authorization_type (got_name, got_code, got_description) VALUES ('code', 1, 'Authorization Code Grant - Authorization: https://tools.ietf.org/html/rfc6749#section-4.1');
INSERT INTO g_authorization_type (got_name, got_code, got_description) VALUES ('token', 2, 'Implicit Grant: https://tools.ietf.org/html/rfc6749#section-4.2');
INSERT INTO g_authorization_type (got_name, got_code, got_description) VALUES ('password', 3, 'Resource Owner Password Credentials Grant: https://tools.ietf.org/html/rfc6749#section-4.3');
INSERT INTO g_authorization_type (got_name, got_code, got_description) VALUES ('client_credentials', 4, 'Client Credentials Grant: https://tools.ietf.org/html/rfc6749#section-4.4');
INSERT INTO g_scope (gs_name, gs_description) VALUES ('g_admin', 'Glewlwyd admin scope');
INSERT INTO g_scope (gs_name, gs_description) VALUES ('g_profile', 'Glewlwyd profile scope');

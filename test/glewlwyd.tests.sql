
-- ----------- --
-- Test values --
-- ----------- --
-- Delete initial values
DELETE FROM `g_client_user_scope`;
DELETE FROM `g_client_authorization_type`;
DELETE FROM `g_resource_scope`;
DELETE FROM `g_client_scope`;
DELETE FROM `g_user_scope`;
DELETE FROM `g_resource`;
DELETE FROM `g_redirect_uri`;
DELETE FROM `g_client`;
DELETE FROM `g_scope`;
DELETE FROM `g_user`;

-- Mariadb/Mysql user add queries
INSERT INTO g_user (gu_login, gu_name, gu_email, gu_password, gu_enabled) VALUES ('admin', 'The Boss', 'boss@glewlwyd.domain', PASSWORD('MyAdminPassword2016!'), 1);
INSERT INTO g_user (gu_login, gu_name, gu_email, gu_password, gu_enabled) VALUES ('user1', 'Dave Lopper1', 'user1@glewlwyd.domain', PASSWORD('MyUser1Password!'), 1);
INSERT INTO g_user (gu_login, gu_name, gu_email, gu_password, gu_enabled) VALUES ('user2', 'Dave Lopper2', 'user2@glewlwyd.domain', PASSWORD('MyUser2Password!'), 1);
INSERT INTO g_user (gu_login, gu_name, gu_email, gu_password, gu_enabled) VALUES ('user3', 'Dave Lopper3', 'user3@glewlwyd.domain', PASSWORD('MyUser3Password!'), 1);

-- SQLite3 user add queries (passwords are md5/base64 encoded, but they are the same as below)
-- INSERT INTO g_user (gu_login, gu_name, gu_email, gu_password, gu_enabled) VALUES ('admin', 'The Boss', 'boss@glewlwyd.domain', '{MD5}Fq5Um/6ZzkTEE01faw8dlw==', 1);
-- INSERT INTO g_user (gu_login, gu_name, gu_email, gu_password, gu_enabled) VALUES ('user1', 'Dave Lopper1', 'user1@glewlwyd.domain', '{MD5}5jDmBvYYgDjSOobF6bsjdw==', 1);
-- INSERT INTO g_user (gu_login, gu_name, gu_email, gu_password, gu_enabled) VALUES ('user2', 'Dave Lopper2', 'user2@glewlwyd.domain', '{MD5}SGTYDlfN1G2QkANBZgzCIQ==', 1);
-- INSERT INTO g_user (gu_login, gu_name, gu_email, gu_password, gu_enabled) VALUES ('user3', 'Dave Lopper3', 'user3@glewlwyd.domain', '{MD5}MSs++hzB5w==', 1);

INSERT INTO g_scope (gs_name, gs_description) VALUES ('g_admin', 'Glewlwyd admin scope');
INSERT INTO g_scope (gs_name, gs_description) VALUES ('g_profile', 'Glewlwyd profile scope');
INSERT INTO g_scope (gs_name, gs_description) VALUES ('scope1', 'Description for scope1');
INSERT INTO g_scope (gs_name, gs_description) VALUES ('scope2', 'Description for scope2');
INSERT INTO g_scope (gs_name, gs_description) VALUES ('scope3', 'Description for scope3');

INSERT INTO g_client (gc_name, gc_description, gc_client_id) VALUES ('client1', 'Description for client1', 'client1_id');
INSERT INTO g_client (gc_name, gc_description, gc_client_id) VALUES ('client2', 'Description for client2', 'client2_id');
-- Mariadb/Mysql
INSERT INTO g_client (gc_name, gc_description, gc_client_id, gc_client_password, gc_confidential) VALUES ('client3', 'Description for client3', 'client3_id', PASSWORD('client3_password'), 1);
-- SQLite3 (password is md5/base64 encoded, but it is the same as below)
-- INSERT INTO g_client (gc_name, gc_description, gc_client_id, gc_client_password, gc_confidential) VALUES ('client3', 'Description for client3', 'client3_id', '{MD5}Vaqk5DGQQunyN3gdVjMJGw==', 1);

INSERT INTO g_client_scope (gc_id, gs_id) VALUES ((SELECT gc_id from g_client WHERE gc_client_id='client3_id'), (SELECT gs_id from g_scope WHERE gs_name='scope2'));
INSERT INTO g_client_scope (gc_id, gs_id) VALUES ((SELECT gc_id from g_client WHERE gc_client_id='client3_id'), (SELECT gs_id from g_scope WHERE gs_name='scope3'));

INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_client1_1', '../app/test-token.html?param=client1_cb1', (SELECT gc_id from g_client WHERE gc_client_id='client1_id'));
INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_client1_2', '../app/test-token.html?param=client1_cb2', (SELECT gc_id from g_client WHERE gc_client_id='client1_id'));
INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_client1_3', 'http://localhost:3000/', (SELECT gc_id from g_client WHERE gc_client_id='client1_id'));
INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_client2', '../app/test-token.html?param=client2_cb', (SELECT gc_id from g_client WHERE gc_client_id='client2_id'));
INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_client3', '../app/test-token.html?param=client3_cb', (SELECT gc_id from g_client WHERE gc_client_id='client3_id'));

INSERT INTO g_resource (gr_name, gr_description, gr_uri) VALUES ('resource1', 'Description for resource1', 'http://resource1.domain');
INSERT INTO g_resource (gr_name, gr_description, gr_uri) VALUES ('resource2', 'Description for resource2', 'http://resource1.domain');
INSERT INTO g_resource (gr_name, gr_description, gr_uri) VALUES ('resource3', 'Description for resource3', 'http://resource1.domain');

INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='admin'), (SELECT gs_id from g_scope WHERE gs_name='g_admin'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='admin'), (SELECT gs_id from g_scope WHERE gs_name='g_profile'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user1'), (SELECT gs_id from g_scope WHERE gs_name='scope1'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user1'), (SELECT gs_id from g_scope WHERE gs_name='scope2'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user1'), (SELECT gs_id from g_scope WHERE gs_name='scope3'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user1'), (SELECT gs_id from g_scope WHERE gs_name='g_profile'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user2'), (SELECT gs_id from g_scope WHERE gs_name='scope1'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user2'), (SELECT gs_id from g_scope WHERE gs_name='g_profile'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user3'), (SELECT gs_id from g_scope WHERE gs_name='scope1'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user3'), (SELECT gs_id from g_scope WHERE gs_name='scope2'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user3'), (SELECT gs_id from g_scope WHERE gs_name='scope3'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user3'), (SELECT gs_id from g_scope WHERE gs_name='g_profile'));

INSERT INTO g_resource_scope (gr_id, gs_id) VALUES ((SELECT gr_id from g_resource WHERE gr_name='resource1'), (SELECT gs_id from g_scope WHERE gs_name='scope1'));
INSERT INTO g_resource_scope (gr_id, gs_id) VALUES ((SELECT gr_id from g_resource WHERE gr_name='resource1'), (SELECT gs_id from g_scope WHERE gs_name='scope2'));
INSERT INTO g_resource_scope (gr_id, gs_id) VALUES ((SELECT gr_id from g_resource WHERE gr_name='resource2'), (SELECT gs_id from g_scope WHERE gs_name='scope2'));
INSERT INTO g_resource_scope (gr_id, gs_id) VALUES ((SELECT gr_id from g_resource WHERE gr_name='resource3'), (SELECT gs_id from g_scope WHERE gs_name='scope3'));

INSERT INTO g_client_authorization_type (gc_client_id, got_id) VALUES ('client1_id', (SELECT got_id from g_authorization_type WHERE got_name='code'));
INSERT INTO g_client_authorization_type (gc_client_id, got_id) VALUES ('client1_id', (SELECT got_id from g_authorization_type WHERE got_name='token'));
INSERT INTO g_client_authorization_type (gc_client_id, got_id) VALUES ('client2_id', (SELECT got_id from g_authorization_type WHERE got_name='code'));
INSERT INTO g_client_authorization_type (gc_client_id, got_id) VALUES ('client3_id', (SELECT got_id FROM g_authorization_type WHERE got_name='code'));
INSERT INTO g_client_authorization_type (gc_client_id, got_id) VALUES ('client3_id', (SELECT got_id from g_authorization_type WHERE got_name='token'));
INSERT INTO g_client_authorization_type (gc_client_id, got_id) VALUES ('client3_id', (SELECT got_id from g_authorization_type WHERE got_name='password'));
INSERT INTO g_client_authorization_type (gc_client_id, got_id) VALUES ('client3_id', (SELECT got_id FROM g_authorization_type WHERE got_name='client_credentials'));

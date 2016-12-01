
-- ----------- --
-- Test values --
-- ----------- --

-- Mariadb/Mysql user add queries
INSERT INTO g_user (gu_login, gu_password, gu_enabled) VALUES ('admin', PASSWORD('MyAdminPassword2016!'), 1);
INSERT INTO g_user (gu_login, gu_password, gu_enabled) VALUES ('user1', PASSWORD('MyUser1Password!'), 1);
INSERT INTO g_user (gu_login, gu_password, gu_enabled) VALUES ('user2', PASSWORD('MyUser2Password!'), 1);
INSERT INTO g_user (gu_login, gu_password, gu_enabled) VALUES ('user3', PASSWORD('MyUser3Password!'), 1);

-- SQLite3 user add queries (passwords are md5 encoded, but they are the same as below)
-- INSERT INTO g_user (gu_login, gu_password, gu_enabled) VALUES ('admin', '16ae549bfe99ce44c4134d5f6b0f1d97', 1);
-- INSERT INTO g_user (gu_login, gu_password, gu_enabled) VALUES ('user1', 'e630e606f6188038d23a86c5e9bb2377', 1);
-- INSERT INTO g_user (gu_login, gu_password, gu_enabled) VALUES ('user2', '4864d80e57cdd46d90900341660cc221', 1);
-- INSERT INTO g_user (gu_login, gu_password, gu_enabled) VALUES ('user3', '312b3efa1cc1e700b08cfa0981dca89f', 1);

INSERT INTO g_scope (gs_name) VALUES ('scope1');
INSERT INTO g_scope (gs_name) VALUES ('scope2');
INSERT INTO g_scope (gs_name) VALUES ('scope3');

INSERT INTO g_client (gc_name, gc_description, gc_client_id) VALUES ('client1', 'Description for client1', 'client1_id');
INSERT INTO g_client (gc_name, gc_description, gc_client_id) VALUES ('client2', 'Description for client2', 'client2_id');
-- Mariadb/Mysql
INSERT INTO g_client (gc_name, gc_description, gc_client_id, gc_client_password, gc_confidential) VALUES ('client3', 'Description for client3', 'client3_id', PASSWORD('client3_password'), 1);
-- SQLite3
-- INSERT INTO g_client (gc_name, gc_description, gc_client_id, gc_client_password, gc_confidential) VALUES ('client3', 'Description for client3', 'client3_id', '55aaa4e4319042e9f237781d5633091b', 1);

INSERT INTO g_client_authorization_type (gc_id, got_id) VALUES ((SELECT gc_id FROM g_client WHERE gc_client_id='client3_id'), (SELECT got_id FROM g_authorization_type WHERE got_code=4));

INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_client1_1', '../static/index.html?param=client1_cb1', (SELECT gc_id from g_client WHERE gc_client_id='client1_id'));
INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_client1_2', '../static/index.html?param=client1_cb2', (SELECT gc_id from g_client WHERE gc_client_id='client1_id'));
INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_client2', '../static/index.html?param=client2_cb', (SELECT gc_id from g_client WHERE gc_client_id='client2_id'));
INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_client3', '../static/index.html?param=client3_cb', (SELECT gc_id from g_client WHERE gc_client_id='client3_id'));

INSERT INTO g_resource (gr_name, gr_description) VALUES ('resource1', 'Description for resource1');
INSERT INTO g_resource (gr_name, gr_description) VALUES ('resource2', 'Description for resource2');
INSERT INTO g_resource (gr_name, gr_description) VALUES ('resource3', 'Description for resource3');

INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='admin'), (SELECT gs_id from g_scope WHERE gs_name='g_admin'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user1'), (SELECT gs_id from g_scope WHERE gs_name='scope1'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user1'), (SELECT gs_id from g_scope WHERE gs_name='scope2'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user1'), (SELECT gs_id from g_scope WHERE gs_name='scope3'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user2'), (SELECT gs_id from g_scope WHERE gs_name='scope1'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user3'), (SELECT gs_id from g_scope WHERE gs_name='scope1'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user3'), (SELECT gs_id from g_scope WHERE gs_name='scope2'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user3'), (SELECT gs_id from g_scope WHERE gs_name='scope3'));

INSERT INTO g_resource_scope (gr_id, gs_id) VALUES ((SELECT gr_id from g_resource WHERE gr_name='resource1'), (SELECT gs_id from g_scope WHERE gs_name='scope1'));
INSERT INTO g_resource_scope (gr_id, gs_id) VALUES ((SELECT gr_id from g_resource WHERE gr_name='resource1'), (SELECT gs_id from g_scope WHERE gs_name='scope2'));
INSERT INTO g_resource_scope (gr_id, gs_id) VALUES ((SELECT gr_id from g_resource WHERE gr_name='resource2'), (SELECT gs_id from g_scope WHERE gs_name='scope2'));
INSERT INTO g_resource_scope (gr_id, gs_id) VALUES ((SELECT gr_id from g_resource WHERE gr_name='resource3'), (SELECT gs_id from g_scope WHERE gs_name='scope3'));

INSERT INTO g_client_authorization_type (gc_id, got_id) VALUES ((SELECT gc_id from g_client WHERE gc_client_id='client1_id'), (SELECT got_id from g_authorization_type WHERE got_name='code'));
INSERT INTO g_client_authorization_type (gc_id, got_id) VALUES ((SELECT gc_id from g_client WHERE gc_client_id='client1_id'), (SELECT got_id from g_authorization_type WHERE got_name='token'));
INSERT INTO g_client_authorization_type (gc_id, got_id) VALUES ((SELECT gc_id from g_client WHERE gc_client_id='client2_id'), (SELECT got_id from g_authorization_type WHERE got_name='code'));
INSERT INTO g_client_authorization_type (gc_id, got_id) VALUES ((SELECT gc_id from g_client WHERE gc_client_id='client3_id'), (SELECT got_id from g_authorization_type WHERE got_name='token'));

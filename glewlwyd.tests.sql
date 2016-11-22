
-- ----------- --
-- Test values --
-- ----------- --

INSERT INTO g_authorization_type (got_name, got_code, got_description) VALUES ('authorization_code', 0, 'Authorization Code Grant - Access token: https://tools.ietf.org/html/rfc6749#section-4.1');
INSERT INTO g_authorization_type (got_name, got_code, got_description) VALUES ('code', 1, 'Authorization Code Grant - Authorization: https://tools.ietf.org/html/rfc6749#section-4.1');
INSERT INTO g_authorization_type (got_name, got_code, got_description) VALUES ('token', 2, 'Implicit Grant: https://tools.ietf.org/html/rfc6749#section-4.2');
INSERT INTO g_authorization_type (got_name, got_code, got_description) VALUES ('password', 3, 'Resource Owner Password Credentials Grant: https://tools.ietf.org/html/rfc6749#section-4.3');
INSERT INTO g_authorization_type (got_name, got_code, got_description) VALUES ('client_credentials', 4, 'Client Credentials Grant: https://tools.ietf.org/html/rfc6749#section-4.4');

INSERT INTO g_user (gu_login, gu_password, gu_enabled) VALUES ('admin', PASSWORD('MyAdminPassword2016!'), 1);
INSERT INTO g_user (gu_login, gu_password, gu_enabled) VALUES ('user1', PASSWORD('MyUser1Password!'), 1);
INSERT INTO g_user (gu_login, gu_password, gu_enabled) VALUES ('user2', PASSWORD('MyUser2Password!'), 1);
INSERT INTO g_user (gu_login, gu_password, gu_enabled) VALUES ('user3', PASSWORD('MyUser3Password!'), 1);

INSERT INTO g_scope (gs_name) VALUES ('scope1');
INSERT INTO g_scope (gs_name) VALUES ('scope2');
INSERT INTO g_scope (gs_name) VALUES ('scope3');

INSERT INTO g_client (gc_name, gc_description, gc_client_id) VALUES ('client1', 'Description for client1', 'client1_id');
INSERT INTO g_client (gc_name, gc_description, gc_client_id) VALUES ('client2', 'Description for client2', 'client2_id');
INSERT INTO g_client (gc_name, gc_description, gc_client_id) VALUES ('client3', 'Description for client3', 'client3_id');

INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_client1_1', 'http://localhost/example-client1.com/cb1', (SELECT gc_id from g_client WHERE gc_client_id='client1_id'));
INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_client1_2', 'http://localhost/example-client1.com/cb2', (SELECT gc_id from g_client WHERE gc_client_id='client1_id'));
INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_client2', 'http://localhost/example-client2.com/cb', (SELECT gc_id from g_client WHERE gc_client_id='client2_id'));
INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_client3', 'http://localhost/example-client3.com/cb', (SELECT gc_id from g_client WHERE gc_client_id='client3_id'));

INSERT INTO g_resource (gr_name, gr_description) VALUES ('resource1', 'Description for resource1');
INSERT INTO g_resource (gr_name, gr_description) VALUES ('resource2', 'Description for resource2');
INSERT INTO g_resource (gr_name, gr_description) VALUES ('resource3', 'Description for resource3');

INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user1'), (SELECT gs_id from g_scope WHERE gs_name='scope1'));
INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='user1'), (SELECT gs_id from g_scope WHERE gs_name='scope2'));
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

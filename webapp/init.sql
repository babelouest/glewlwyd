
INSERT INTO g_client (gc_name, gc_description, gc_client_id) VALUES ('admin app', 'Glewlwyd administration app', 'g_admin');
INSERT INTO g_redirect_uri (gru_name, gru_uri, gc_id) VALUES ('uri_g_admin', '../app/index.html', (SELECT gc_id from g_client WHERE gc_client_id='g_admin'));
INSERT INTO g_client_authorization_type (gc_client_id, got_id) VALUES ('g_admin', (SELECT got_id from g_authorization_type WHERE got_name='code'));
INSERT INTO g_client_authorization_type (gc_client_id, got_id) VALUES ('g_admin', (SELECT got_id from g_authorization_type WHERE got_name='token'));

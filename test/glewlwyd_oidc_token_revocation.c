/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define USERNAME "user1"
#define PASSWORD "password"
#define SCOPE_LIST "g_profile"
#define SCOPE_INTROSPECT "g_admin"
#define CLIENT_CONFIDENTIAL_1 "client3_id"
#define CLIENT_CONFIDENTIAL_1_SECRET "password"
#define CLIENT_CONFIDENTIAL_2 "client4_id"
#define CLIENT_CONFIDENTIAL_2_SECRET "secret"
#define CLIENT_PUBLIC "client1_id"
#define REDIRECT_URI "..%2f..%2ftest-oidc.html?param=client3"
#define REDIRECT_URI_DECODED "../../test-oidc.html?param=client3"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define PLUGIN_MODULE "oidc"
#define PLUGIN_NAME "introspect"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_DISPLAY_NAME "Introspection test"
#define PLUGIN_JWT_TYPE "sha"
#define PLUGIN_JWT_KEY_SIZE "256"
#define PLUGIN_KEY "secret"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_ACCESS_TOKEN_DURATION 3600

#define TOKEN_TYPE_HINT_REFRESH "refresh_token"
#define TOKEN_TYPE_HINT_ACCESS "access_token"
#define TOKEN_TYPE_HINT_ID_TOKEN "id_token"

struct _u_request admin_req;

START_TEST(test_oidc_revocation_plugin_add_target_client)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisosososososososo}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", PLUGIN_JWT_TYPE,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", PLUGIN_KEY,
                                  "code-duration", PLUGIN_CODE_DURATION,
                                  "refresh-token-duration", PLUGIN_REFRESH_TOKEN_DURATION,
                                  "access-token-duration", PLUGIN_ACCESS_TOKEN_DURATION,
                                  "allow-non-oidc", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-implicit-enabled", json_true(),
                                  "auth-type-password-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "introspection-revocation-allowed", json_true(),
                                  "introspection-revocation-allow-target-client", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_revocation_plugin_add_auth_scope)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisososososososos[s]}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", PLUGIN_JWT_TYPE,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", PLUGIN_KEY,
                                  "code-duration", PLUGIN_CODE_DURATION,
                                  "refresh-token-duration", PLUGIN_REFRESH_TOKEN_DURATION,
                                  "access-token-duration", PLUGIN_ACCESS_TOKEN_DURATION,
                                  "allow-non-oidc", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-implicit-enabled", json_true(),
                                  "auth-type-password-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "introspection-revocation-allowed", json_true(),
                                  "introspection-revocation-auth-scope", SCOPE_INTROSPECT);

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_revocation_plugin_remove)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_revocation_invalid_format_target_client)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  const char * access_token;
  struct _u_map param;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  req.auth_basic_user = o_strdup(CLIENT_CONFIDENTIAL_1);
  req.auth_basic_password = o_strdup(CLIENT_CONFIDENTIAL_1_SECRET);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  access_token = json_string_value(json_object_get(j_body, "access_token"));
  ck_assert_ptr_ne(access_token, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  ck_assert_int_eq(u_map_init(&param), U_OK);
  ck_assert_int_eq(u_map_put(&param, "error", access_token), U_OK);
  ck_assert_int_eq(u_map_put(&param, "error_hint", "error"), U_OK);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/revoke", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, NULL, 400, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/revoke", CLIENT_CONFIDENTIAL_1, "error", NULL, NULL, 401, NULL, NULL, NULL), 1);
  u_map_clean(&param);
  json_decref(j_body);
}
END_TEST

START_TEST(test_oidc_revocation_access_token_target_client)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body, * j_response;
  const char * token;
  struct _u_map param;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  req.auth_basic_user = o_strdup(CLIENT_CONFIDENTIAL_1);
  req.auth_basic_password = o_strdup(CLIENT_CONFIDENTIAL_1_SECRET);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  token = json_string_value(json_object_get(j_body, "access_token"));
  ck_assert_ptr_ne(token, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  j_response = json_pack("{sossssssss}", "active", json_true(), "username", USERNAME, "client_id", CLIENT_CONFIDENTIAL_1, "token_type", TOKEN_TYPE_HINT_ACCESS, "scope", SCOPE_LIST);
  ck_assert_int_eq(u_map_init(&param), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token", token), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token_type_hint", TOKEN_TYPE_HINT_ACCESS), U_OK);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, &param, 200, j_response, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/revoke", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, &param, 200, NULL, NULL, NULL), 1);
  json_decref(j_response);
  j_response = json_pack("{so}", "active", json_false());
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, &param, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(u_map_put(&param, "token", "error"), U_OK);
  json_decref(j_response);
  u_map_clean(&param);
  json_decref(j_body);
}
END_TEST

START_TEST(test_oidc_revocation_refresh_token_target_client)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body, * j_response;
  const char * token;
  struct _u_map param;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  req.auth_basic_user = o_strdup(CLIENT_CONFIDENTIAL_1);
  req.auth_basic_password = o_strdup(CLIENT_CONFIDENTIAL_1_SECRET);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  token = json_string_value(json_object_get(j_body, "refresh_token"));
  ck_assert_ptr_ne(token, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  j_response = json_pack("{sossssssss}", "active", json_true(), "username", USERNAME, "client_id", CLIENT_CONFIDENTIAL_1, "token_type", TOKEN_TYPE_HINT_REFRESH, "scope", SCOPE_LIST);
  ck_assert_int_eq(u_map_init(&param), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token", token), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token_type_hint", TOKEN_TYPE_HINT_REFRESH), U_OK);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, &param, 200, j_response, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/revoke", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, &param, 200, NULL, NULL, NULL), 1);
  json_decref(j_response);
  j_response = json_pack("{so}", "active", json_false());
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, &param, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(u_map_put(&param, "token", "error"), U_OK);
  json_decref(j_response);
  u_map_clean(&param);
  json_decref(j_body);
}
END_TEST

START_TEST(test_oidc_revocation_invalid_format_bearer)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body, * j_body_introspect;
  const char * access_token, * token_auth;
  struct _u_map param;
  char * tmp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  req.auth_basic_user = o_strdup(CLIENT_CONFIDENTIAL_1);
  req.auth_basic_password = o_strdup(CLIENT_CONFIDENTIAL_1_SECRET);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  access_token = json_string_value(json_object_get(j_body, "access_token"));
  ck_assert_ptr_ne(access_token, NULL);
  ulfius_clean_response(&resp);
  
  ulfius_init_response(&resp);
  u_map_put(req.map_post_body, "scope", SCOPE_INTROSPECT);
  u_map_put(req.map_post_body, "username", ADMIN_USERNAME);
  u_map_put(req.map_post_body, "password", ADMIN_PASSWORD);
  o_free(req.auth_basic_user);
  req.auth_basic_user = NULL;
  o_free(req.auth_basic_password);
  req.auth_basic_password = NULL;
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body_introspect = ulfius_get_json_body_response(&resp, NULL);
  token_auth = json_string_value(json_object_get(j_body_introspect, "access_token"));
  ck_assert_ptr_ne(token_auth, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  ulfius_init_request(&req);
  tmp = msprintf("Bearer %s", token_auth);
  u_map_put(req.map_header, "Authorization", tmp);
  o_free(tmp);
  ck_assert_int_eq(u_map_init(&param), U_OK);
  ck_assert_int_eq(u_map_put(&param, "error", access_token), U_OK);
  ck_assert_int_eq(u_map_put(&param, "error_hint", "error"), U_OK);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/revoke", NULL, NULL, NULL, NULL, 400, NULL, NULL, NULL), 1);
  tmp = msprintf("Bearer %s", "error");
  u_map_put(req.map_header, "Authorization", tmp);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/revoke", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  o_free(tmp);
  ulfius_clean_request(&req);
  u_map_clean(&param);
  json_decref(j_body);
  json_decref(j_body_introspect);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oidc_revocation_access_token_target_bearer)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body, * j_response, * j_body_introspect;
  const char * token, * token_auth;
  struct _u_map param;
  char * tmp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  req.auth_basic_user = o_strdup(CLIENT_CONFIDENTIAL_1);
  req.auth_basic_password = o_strdup(CLIENT_CONFIDENTIAL_1_SECRET);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  token = json_string_value(json_object_get(j_body, "access_token"));
  ck_assert_ptr_ne(token, NULL);
  ulfius_clean_response(&resp);
  
  ulfius_init_response(&resp);
  u_map_put(req.map_post_body, "scope", SCOPE_INTROSPECT);
  u_map_put(req.map_post_body, "username", ADMIN_USERNAME);
  u_map_put(req.map_post_body, "password", ADMIN_PASSWORD);
  o_free(req.auth_basic_user);
  req.auth_basic_user = NULL;
  o_free(req.auth_basic_password);
  req.auth_basic_password = NULL;
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body_introspect = ulfius_get_json_body_response(&resp, NULL);
  token_auth = json_string_value(json_object_get(j_body_introspect, "access_token"));
  ck_assert_ptr_ne(token_auth, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  ulfius_init_request(&req);
  tmp = msprintf("Bearer %s", token_auth);
  u_map_put(req.map_header, "Authorization", tmp);
  o_free(tmp);
  
  j_response = json_pack("{sossssssss}", "active", json_true(), "username", USERNAME, "client_id", CLIENT_CONFIDENTIAL_1, "token_type", TOKEN_TYPE_HINT_ACCESS, "scope", SCOPE_LIST);
  ck_assert_int_eq(u_map_init(&param), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token", token), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token_type_hint", TOKEN_TYPE_HINT_ACCESS), U_OK);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, j_response, NULL, NULL), 1);
  u_map_remove_from_key(&param, "token_type_hint");
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/revoke", NULL, NULL, NULL, &param, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&req, "GET", SERVER_URI "/" PLUGIN_NAME "/userinfo", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_response);
  
  j_response = json_pack("{so}", "active", json_false());
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, j_response, NULL, NULL), 1);
  tmp = msprintf("Bearer %s", token);
  u_map_put(req.map_header, "Authorization", tmp);
  o_free(tmp);
  ck_assert_int_eq(run_simple_test(&req, "GET", SERVER_URI "/" PLUGIN_NAME "/userinfo", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_response);
  
  j_response = json_pack("{so}", "active", json_true());
  tmp = msprintf("Bearer %s", token_auth);
  u_map_put(req.map_header, "Authorization", tmp);
  o_free(tmp);
  ck_assert_int_eq(u_map_put(&param, "token", token_auth), U_OK);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, j_response, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/revoke", NULL, NULL, NULL, &param, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 401, NULL, NULL, NULL), 1);
  json_decref(j_response);

  u_map_clean(&param);
  json_decref(j_body);
  json_decref(j_body_introspect);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oidc_revocation_refresh_token_target_bearer)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body, * j_response, * j_body_introspect;
  const char * token, * token_auth;
  struct _u_map param;
  char * tmp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  req.auth_basic_user = o_strdup(CLIENT_CONFIDENTIAL_1);
  req.auth_basic_password = o_strdup(CLIENT_CONFIDENTIAL_1_SECRET);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  token = json_string_value(json_object_get(j_body, "refresh_token"));
  ck_assert_ptr_ne(token, NULL);
  ulfius_clean_response(&resp);
  
  ulfius_init_response(&resp);
  u_map_put(req.map_post_body, "scope", SCOPE_INTROSPECT);
  u_map_put(req.map_post_body, "username", ADMIN_USERNAME);
  u_map_put(req.map_post_body, "password", ADMIN_PASSWORD);
  o_free(req.auth_basic_user);
  req.auth_basic_user = NULL;
  o_free(req.auth_basic_password);
  req.auth_basic_password = NULL;
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body_introspect = ulfius_get_json_body_response(&resp, NULL);
  token_auth = json_string_value(json_object_get(j_body_introspect, "access_token"));
  ck_assert_ptr_ne(token_auth, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  ulfius_init_request(&req);
  tmp = msprintf("Bearer %s", token_auth);
  u_map_put(req.map_header, "Authorization", tmp);
  o_free(tmp);
  
  j_response = json_pack("{sossssssss}", "active", json_true(), "username", USERNAME, "client_id", CLIENT_CONFIDENTIAL_1, "token_type", TOKEN_TYPE_HINT_REFRESH, "scope", SCOPE_LIST);
  ck_assert_int_eq(u_map_init(&param), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token", token), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token_type_hint", TOKEN_TYPE_HINT_REFRESH), U_OK);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, j_response, NULL, NULL), 1);
  u_map_remove_from_key(&param, "token_type_hint");
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/revoke", NULL, NULL, NULL, &param, 200, NULL, NULL, NULL), 1);
  json_decref(j_response);
  j_response = json_pack("{so}", "active", json_false());
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, j_response, NULL, NULL), 1);
  json_decref(j_response);
  u_map_clean(&param);
  json_decref(j_body);
  json_decref(j_body_introspect);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oidc_revocation_id_token)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body, * j_body_introspect, * j_response;
  char * cookie, * id_token, * tmp;
  const char * token_auth;
  struct _u_map param;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/auth/");
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ck_assert_int_eq(ulfius_set_json_body_request(&req, j_body), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  ck_assert_int_eq(u_map_put(req.map_header, "Cookie", cookie), U_OK);
  o_free(cookie);
  ulfius_clean_response(&resp);
  
  // Set grant
  ulfius_init_response(&resp);
  o_free(req.http_verb);
  o_free(req.http_url);
  req.http_verb = strdup("PUT");
  req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT_CONFIDENTIAL_1);
  j_body = json_pack("{ss}", "scope", "openid");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_response(&resp);

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(req.http_verb);
  o_free(req.http_url);
  req.http_verb = o_strdup("GET");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/auth?response_type=id_token&g_continue&client_id=" CLIENT_CONFIDENTIAL_1 "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&nonce=nonce1234&scope=openid");
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=")+o_strlen("id_token="));
  if (o_strstr(id_token, "&") != NULL) {
    *o_strstr(id_token, "&") = '\0';
  }
  ulfius_clean_response(&resp);
  
  // Clean grant
  ulfius_init_response(&resp);
  o_free(req.http_verb);
  o_free(req.http_url);
  req.http_verb = strdup("PUT");
  req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT_CONFIDENTIAL_1);
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  u_map_remove_from_key(req.map_header, "Cookie");
  o_free(req.http_verb);
  o_free(req.http_url);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", SCOPE_INTROSPECT);
  u_map_put(req.map_post_body, "username", ADMIN_USERNAME);
  u_map_put(req.map_post_body, "password", ADMIN_PASSWORD);
  o_free(req.auth_basic_user);
  req.auth_basic_user = NULL;
  o_free(req.auth_basic_password);
  req.auth_basic_password = NULL;
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body_introspect = ulfius_get_json_body_response(&resp, NULL);
  token_auth = json_string_value(json_object_get(j_body_introspect, "access_token"));
  ck_assert_ptr_ne(token_auth, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  ulfius_init_request(&req);
  tmp = msprintf("Bearer %s", token_auth);
  u_map_put(req.map_header, "Authorization", tmp);
  o_free(tmp);
  
  j_response = json_pack("{sossssss}", "active", json_true(), "username", USERNAME, "client_id", CLIENT_CONFIDENTIAL_1, "token_type", TOKEN_TYPE_HINT_ID_TOKEN);
  ck_assert_int_eq(u_map_init(&param), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token", id_token), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token_type_hint", TOKEN_TYPE_HINT_ID_TOKEN), U_OK);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, j_response, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/revoke", NULL, NULL, NULL, &param, 200, NULL, NULL, NULL), 1);
  json_decref(j_response);
  j_response = json_pack("{so}", "active", json_false());
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, j_response, NULL, NULL), 1);
  json_decref(j_response);
  u_map_clean(&param);
  json_decref(j_body_introspect);
  ulfius_clean_request(&req);
  o_free(id_token);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc token revocation");
  tc_core = tcase_create("test_oidc_token_revocation");
  tcase_add_test(tc_core, test_oidc_revocation_plugin_add_target_client);
  tcase_add_test(tc_core, test_oidc_revocation_invalid_format_target_client);
  tcase_add_test(tc_core, test_oidc_revocation_access_token_target_client);
  tcase_add_test(tc_core, test_oidc_revocation_refresh_token_target_client);
  tcase_add_test(tc_core, test_oidc_revocation_plugin_remove);
  tcase_add_test(tc_core, test_oidc_revocation_plugin_add_auth_scope);
  tcase_add_test(tc_core, test_oidc_revocation_invalid_format_bearer);
  tcase_add_test(tc_core, test_oidc_revocation_access_token_target_bearer);
  tcase_add_test(tc_core, test_oidc_revocation_refresh_token_target_bearer);
  tcase_add_test(tc_core, test_oidc_revocation_id_token);
  tcase_add_test(tc_core, test_oidc_revocation_plugin_remove);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req;
  struct _u_response auth_resp;
  json_t * j_body;
  int res, do_test = 0, i;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&admin_req);
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", ADMIN_USERNAME, "password", ADMIN_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  j_body = NULL;
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    for (i=0; i<auth_resp.nb_cookies; i++) {
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(admin_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", ADMIN_USERNAME);
    do_test = 1;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
    do_test = 0;
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  json_decref(j_body);
  
  ulfius_clean_request(&admin_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

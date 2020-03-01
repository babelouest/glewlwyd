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
#define SCOPE_LIST_CLIENT_CONFIDENTIAL_1 "scope2 scope3"
#define CLIENT_CONFIDENTIAL_2 "client4_id"
#define CLIENT_CONFIDENTIAL_2_SECRET "secret"
#define CLIENT_PUBLIC "client1_id"
#define REDIRECT_URI "..%2f..%2ftest-oauth2.html?param=client1_cb1"
#define REDIRECT_URI_DECODED "../../test-oauth2.html?param=client1_cb1"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define PLUGIN_MODULE "oauth2-glewlwyd"
#define PLUGIN_NAME "introspect"
#define PLUGIN_DISPLAY_NAME "Introspection test"
#define PLUGIN_JWT_TYPE "sha"
#define PLUGIN_JWT_KEY_SIZE "256"
#define PLUGIN_KEY "secret"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_ACCESS_TOKEN_DURATION 3600

#define TOKEN_TYPE_HINT_REFRESH "refresh_token"
#define TOKEN_TYPE_HINT_ACCESS "access_token"

struct _u_request admin_req;

START_TEST(test_oauth2_introspection_plugin_add_target_client)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssisisisososososososo}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "jwt-type", PLUGIN_JWT_TYPE,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", PLUGIN_KEY,
                                  "code-duration", PLUGIN_CODE_DURATION,
                                  "refresh-token-duration", PLUGIN_REFRESH_TOKEN_DURATION,
                                  "access-token-duration", PLUGIN_ACCESS_TOKEN_DURATION,
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

START_TEST(test_oauth2_introspection_plugin_add_auth_scope)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssisisisosososososos[s]}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "jwt-type", PLUGIN_JWT_TYPE,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", PLUGIN_KEY,
                                  "code-duration", PLUGIN_CODE_DURATION,
                                  "refresh-token-duration", PLUGIN_REFRESH_TOKEN_DURATION,
                                  "access-token-duration", PLUGIN_ACCESS_TOKEN_DURATION,
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

START_TEST(test_oauth2_introspection_plugin_add_target_client_check_expiration)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssisisisososososososo}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "jwt-type", PLUGIN_JWT_TYPE,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", PLUGIN_KEY,
                                  "code-duration", PLUGIN_CODE_DURATION,
                                  "refresh-token-duration", 1,
                                  "access-token-duration", 1,
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

START_TEST(test_oauth2_introspection_plugin_remove)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oauth2_introspection_invalid_format_target_client)
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
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, NULL, 400, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_1, "error", NULL, NULL, 401, NULL, NULL, NULL), 1);
  u_map_clean(&param);
  json_decref(j_body);
}
END_TEST

START_TEST(test_oauth2_introspection_access_token_target_client)
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
  u_map_remove_from_key(&param, "token_type_hint");
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, &param, 200, j_response, NULL, NULL), 1);
  json_decref(j_response);
  j_response = json_pack("{so}", "active", json_false());
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_2, CLIENT_CONFIDENTIAL_2_SECRET, NULL, &param, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(u_map_put(&param, "token", "error"), U_OK);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, &param, 200, NULL, NULL, NULL), 1);
  json_decref(j_response);
  u_map_clean(&param);
  json_decref(j_body);
}
END_TEST

START_TEST(test_oauth2_introspection_refresh_token_target_client)
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
  u_map_remove_from_key(&param, "token_type_hint");
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, &param, 200, j_response, NULL, NULL), 1);
  json_decref(j_response);
  j_response = json_pack("{so}", "active", json_false());
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_2, CLIENT_CONFIDENTIAL_2_SECRET, NULL, &param, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(u_map_put(&param, "token", "error"), U_OK);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, &param, 200, NULL, NULL, NULL), 1);
  json_decref(j_response);
  u_map_clean(&param);
  json_decref(j_body);
}
END_TEST

START_TEST(test_oauth2_introspection_invalid_format_bearer)
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
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, NULL, 400, NULL, NULL, NULL), 1);
  tmp = msprintf("Bearer %s", "error");
  u_map_put(req.map_header, "Authorization", tmp);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  o_free(tmp);
  ulfius_clean_request(&req);
  u_map_clean(&param);
  json_decref(j_body);
  json_decref(j_body_introspect);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oauth2_introspection_access_token_target_bearer)
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
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, j_response, NULL, NULL), 1);
  json_decref(j_response);
  j_response = json_pack("{so}", "active", json_false());
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(u_map_put(&param, "token", "error"), U_OK);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, NULL, NULL, NULL), 1);
  json_decref(j_response);
  u_map_clean(&param);
  json_decref(j_body);
  json_decref(j_body_introspect);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oauth2_introspection_access_token_target_bearer_no_client_id)
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
  
  j_response = json_pack("{sossssss}", "active", json_true(), "username", USERNAME, "token_type", TOKEN_TYPE_HINT_ACCESS, "scope", SCOPE_LIST);
  ck_assert_int_eq(u_map_init(&param), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token", token), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token_type_hint", TOKEN_TYPE_HINT_ACCESS), U_OK);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, j_response, NULL, NULL), 1);
  u_map_remove_from_key(&param, "token_type_hint");
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, j_response, NULL, NULL), 1);
  json_decref(j_response);
  j_response = json_pack("{so}", "active", json_false());
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(u_map_put(&param, "token", "error"), U_OK);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, NULL, NULL, NULL), 1);
  json_decref(j_response);
  u_map_clean(&param);
  json_decref(j_body);
  json_decref(j_body_introspect);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oauth2_introspection_access_token_target_bearer_client_credentials)
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
  u_map_put(req.map_post_body, "grant_type", "client_credentials");
  u_map_put(req.map_post_body, "scope", SCOPE_LIST_CLIENT_CONFIDENTIAL_1);
  req.auth_basic_user = o_strdup(CLIENT_CONFIDENTIAL_1);
  req.auth_basic_password = o_strdup(CLIENT_CONFIDENTIAL_1_SECRET);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  token = json_string_value(json_object_get(j_body, "access_token"));
  ck_assert_ptr_ne(token, NULL);
  ulfius_clean_response(&resp);
  
  ulfius_init_response(&resp);
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
  
  j_response = json_pack("{sossssss}", "active", json_true(), "client_id", CLIENT_CONFIDENTIAL_1, "token_type", TOKEN_TYPE_HINT_ACCESS, "scope", SCOPE_LIST_CLIENT_CONFIDENTIAL_1);
  ck_assert_int_eq(u_map_init(&param), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token", token), U_OK);
  ck_assert_int_eq(u_map_put(&param, "token_type_hint", TOKEN_TYPE_HINT_ACCESS), U_OK);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, j_response, NULL, NULL), 1);
  u_map_remove_from_key(&param, "token_type_hint");
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, j_response, NULL, NULL), 1);
  json_decref(j_response);
  j_response = json_pack("{so}", "active", json_false());
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(u_map_put(&param, "token", "error"), U_OK);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, NULL, NULL, NULL), 1);
  json_decref(j_response);
  u_map_clean(&param);
  json_decref(j_body);
  json_decref(j_body_introspect);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oauth2_introspection_refresh_token_target_bearer)
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
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, j_response, NULL, NULL), 1);
  json_decref(j_response);
  j_response = json_pack("{so}", "active", json_false());
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(u_map_put(&param, "token", "error"), U_OK);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", NULL, NULL, NULL, &param, 200, NULL, NULL, NULL), 1);
  json_decref(j_response);
  u_map_clean(&param);
  json_decref(j_body);
  json_decref(j_body_introspect);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oauth2_introspection_token_target_client_check_expiration)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body, * j_response;
  const char * access_token, * refresh_token;
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
  refresh_token = json_string_value(json_object_get(j_body, "refresh_token"));
  ck_assert_ptr_ne(refresh_token, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ck_assert_int_eq(u_map_init(&param), U_OK);
  sleep(2);
  j_response = json_pack("{so}", "active", json_false());
  ck_assert_int_eq(u_map_put(&param, "token", access_token), U_OK);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, &param, 200, j_response, NULL, NULL), 1);
  ck_assert_int_eq(u_map_put(&param, "token", refresh_token), U_OK);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_CONFIDENTIAL_1, CLIENT_CONFIDENTIAL_1_SECRET, NULL, &param, 200, j_response, NULL, NULL), 1);
  json_decref(j_response);
  u_map_clean(&param);
  json_decref(j_body);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oauth2 token introspcetion");
  tc_core = tcase_create("test_oauth2_token_introspection");
  tcase_add_test(tc_core, test_oauth2_introspection_plugin_add_target_client);
  tcase_add_test(tc_core, test_oauth2_introspection_invalid_format_target_client);
  tcase_add_test(tc_core, test_oauth2_introspection_access_token_target_client);
  tcase_add_test(tc_core, test_oauth2_introspection_refresh_token_target_client);
  tcase_add_test(tc_core, test_oauth2_introspection_plugin_remove);
  tcase_add_test(tc_core, test_oauth2_introspection_plugin_add_auth_scope);
  tcase_add_test(tc_core, test_oauth2_introspection_invalid_format_bearer);
  tcase_add_test(tc_core, test_oauth2_introspection_access_token_target_bearer);
  tcase_add_test(tc_core, test_oauth2_introspection_refresh_token_target_bearer);
  tcase_add_test(tc_core, test_oauth2_introspection_access_token_target_bearer_no_client_id);
  tcase_add_test(tc_core, test_oauth2_introspection_access_token_target_bearer_client_credentials);
  tcase_add_test(tc_core, test_oauth2_introspection_plugin_remove);
  tcase_add_test(tc_core, test_oauth2_introspection_plugin_add_target_client_check_expiration);
  tcase_add_test(tc_core, test_oauth2_introspection_token_target_client_check_expiration);
  tcase_add_test(tc_core, test_oauth2_introspection_plugin_remove);
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

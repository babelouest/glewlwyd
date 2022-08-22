/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <check.h>

#include <orcania.h>
#include <yder.h>
#include <ulfius.h>
#include <rhonabwy.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define USER_USERNAME "user1"
#define USER_PASSWORD "password"
#define PLUGIN_MODULE "oauth2-glewlwyd"
#define PLUGIN_NAME "oauth2_code_replay"
#define SCOPE_LIST "scope1"
#define CLIENT_ID "client3_id"
#define CLIENT_SECRET "password"
#define CLIENT_REDIRECT_URI "../../test-oauth2.html?param=client3"
#define CLIENT_REDIRECT_URI_ENCODED "..%2F..%2Ftest-oauth2.html%3Fparam%3Dclient3"
#define RESPONSE_TYPE "code"

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_oauth2_code_replay_add_plugin_with_revoke_replay)
{
  json_t * j_param = json_pack("{sssssss{sssssssisisisosososososososososo}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "jwt-type", "sha",
                                  "jwt-key-size", "256",
                                  "key", "secret_" PLUGIN_NAME,
                                  "access-token-duration", 3600,
                                  "refresh-token-duration", 1209600,
                                  "code-duration", 600,
                                  "refresh-token-rolling", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-implicit-enabled", json_true(),
                                  "auth-type-code-revoke-replayed", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-password-enabled", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "introspection-revocation-allowed", json_true(),
                                  "introspection-revocation-allow-target-client", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oauth2_code_replay_test_revoked_tokens)
{
  struct _u_request req;
  struct _u_response resp;
  char * code;
  const char * refresh_token, * access_token, * access_token_refreshed;
  json_t * j_body_code, * j_body_refresh, * j_introspect;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "GET", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=" RESPONSE_TYPE "&client_id=" CLIENT_ID "&redirect_uri=" CLIENT_REDIRECT_URI_ENCODED "&scope=" SCOPE_LIST "&g_continue", 
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  ck_assert_ptr_ne(NULL, code);
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
      U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
      U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
      U_OPT_POST_BODY_PARAMETER, "code", code,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_body_code = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(refresh_token = json_string_value(json_object_get(j_body_code, "refresh_token")), NULL);
  ck_assert_ptr_ne(access_token = json_string_value(json_object_get(j_body_code, "access_token")), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
      U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
      U_OPT_POST_BODY_PARAMETER, "refresh_token", refresh_token,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_body_refresh = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(access_token_refreshed = json_string_value(json_object_get(j_body_refresh, "access_token")), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "token", refresh_token,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_introspect = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(j_introspect, "active"), json_true());
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_introspect);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "token", access_token,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_introspect = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(j_introspect, "active"), json_true());
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_introspect);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "token", access_token_refreshed,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_introspect = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(j_introspect, "active"), json_true());
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_introspect);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
      U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
      U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
      U_OPT_POST_BODY_PARAMETER, "code", code,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "token", refresh_token,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_introspect = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(j_introspect, "active"), json_false());
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_introspect);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "token", access_token,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_introspect = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(j_introspect, "active"), json_false());
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_introspect);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "token", access_token_refreshed,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_introspect = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(j_introspect, "active"), json_false());
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_introspect);
  
  json_decref(j_body_refresh);
  json_decref(j_body_code);
  o_free(code);
}
END_TEST

START_TEST(test_oauth2_code_replay_add_plugin_without_revoke_replay)
{
  json_t * j_param = json_pack("{sssssss{sssssssisisisosososososososososo}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "jwt-type", "sha",
                                  "jwt-key-size", "256",
                                  "key", "secret_" PLUGIN_NAME,
                                  "access-token-duration", 3600,
                                  "refresh-token-duration", 1209600,
                                  "code-duration", 600,
                                  "refresh-token-rolling", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-implicit-enabled", json_true(),
                                  "auth-type-code-revoke-replayed", json_false(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-password-enabled", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "introspection-revocation-allowed", json_true(),
                                  "introspection-revocation-allow-target-client", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oauth2_code_replay_test_non_revoked_tokens)
{
  struct _u_request req;
  struct _u_response resp;
  char * code;
  const char * refresh_token, * access_token, * access_token_refreshed;
  json_t * j_body_code, * j_body_refresh, * j_introspect;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "GET", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=" RESPONSE_TYPE "&client_id=" CLIENT_ID "&redirect_uri=" CLIENT_REDIRECT_URI_ENCODED "&scope=" SCOPE_LIST "&g_continue", 
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  ck_assert_ptr_ne(NULL, code);
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
      U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
      U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
      U_OPT_POST_BODY_PARAMETER, "code", code,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_body_code = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(refresh_token = json_string_value(json_object_get(j_body_code, "refresh_token")), NULL);
  ck_assert_ptr_ne(access_token = json_string_value(json_object_get(j_body_code, "access_token")), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
      U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
      U_OPT_POST_BODY_PARAMETER, "refresh_token", refresh_token,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_body_refresh = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(access_token_refreshed = json_string_value(json_object_get(j_body_refresh, "access_token")), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "token", refresh_token,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_introspect = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(j_introspect, "active"), json_true());
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_introspect);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "token", access_token,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_introspect = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(j_introspect, "active"), json_true());
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_introspect);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "token", access_token_refreshed,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_introspect = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(j_introspect, "active"), json_true());
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_introspect);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
      U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
      U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
      U_OPT_POST_BODY_PARAMETER, "code", code,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "token", refresh_token,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_introspect = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(j_introspect, "active"), json_true());
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_introspect);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "token", access_token,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_introspect = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(j_introspect, "active"), json_true());
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_introspect);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "POST", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
      U_OPT_AUTH_BASIC_USER, CLIENT_ID,
      U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
      U_OPT_POST_BODY_PARAMETER, "token", access_token_refreshed,
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_introspect = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(j_introspect, "active"), json_true());
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_introspect);
  
  json_decref(j_body_refresh);
  json_decref(j_body_code);
  o_free(code);
}
END_TEST

START_TEST(test_oauth2_code_replay_delete_plugin)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oauth2 code replay");
  tc_core = tcase_create("test_oauth2_code_replay");
  tcase_add_test(tc_core, test_oauth2_code_replay_add_plugin_with_revoke_replay);
  tcase_add_test(tc_core, test_oauth2_code_replay_test_revoked_tokens);
  tcase_add_test(tc_core, test_oauth2_code_replay_delete_plugin);
  tcase_add_test(tc_core, test_oauth2_code_replay_add_plugin_without_revoke_replay);
  tcase_add_test(tc_core, test_oauth2_code_replay_test_non_revoked_tokens);
  tcase_add_test(tc_core, test_oauth2_code_replay_delete_plugin);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req, scope_req, register_req;
  struct _u_response auth_resp, scope_resp;
  int res, do_test = 0, i;
  json_t * j_body, * j_register;
  char * cookie;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  ulfius_init_request(&admin_req);
  ulfius_init_request(&user_req);

  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&scope_req);
  ulfius_init_request(&register_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_response(&scope_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", ADMIN_USERNAME, "password", ADMIN_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    if (auth_resp.nb_cookies) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Admin %s authenticated", ADMIN_USERNAME);
      cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
      u_map_put(admin_req.map_header, "Cookie", cookie);
      o_free(cookie);
      do_test = 1;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication admin");
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);
  
  if (do_test) {
    // Getting a valid session id for authenticated http requests
    ulfius_init_request(&auth_req);
    ulfius_init_response(&auth_resp);
    auth_req.http_verb = strdup("POST");
    auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
    j_body = json_pack("{ssss}", "username", USER_USERNAME, "password", USER_PASSWORD);
    ulfius_set_json_body_request(&auth_req, j_body);
    json_decref(j_body);
    res = ulfius_send_http_request(&auth_req, &auth_resp);
    
    if (res == U_OK && auth_resp.status == 200) {
      for (i=0; i<auth_resp.nb_cookies; i++) {
        char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
        u_map_put(user_req.map_header, "Cookie", cookie);
        u_map_put(auth_req.map_header, "Cookie", cookie);
        u_map_put(scope_req.map_header, "Cookie", cookie);
        u_map_put(register_req.map_header, "Cookie", cookie);
        o_free(cookie);
      }
      ulfius_clean_response(&auth_resp);
      ulfius_init_response(&auth_resp);
      
      j_register = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_true());
      run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
      json_decref(j_register);
      
      j_body = json_pack("{sssssss{ss}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
      ulfius_set_json_body_request(&auth_req, j_body);
      json_decref(j_body);
      res = ulfius_send_http_request(&auth_req, &auth_resp);
      if (res == U_OK && auth_resp.status == 200) {
        j_register = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_true());
        run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
        json_decref(j_register);
        
        ulfius_clean_response(&auth_resp);
        ulfius_init_response(&auth_resp);
        j_body = json_pack("{sssssss{ss}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
        ulfius_set_json_body_request(&auth_req, j_body);
        json_decref(j_body);
        res = ulfius_send_http_request(&auth_req, &auth_resp);
        if (res == U_OK && auth_resp.status == 200) {
          y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USER_USERNAME);
      
          scope_req.http_verb = strdup("PUT");
          scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT_ID);
          j_body = json_pack("{ss}", "scope", SCOPE_LIST);
          ulfius_set_json_body_request(&scope_req, j_body);
          json_decref(j_body);
          if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT_ID, SCOPE_LIST);
          } else {
            do_test = 1;
          }
          ulfius_clean_response(&scope_resp);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "Error auth scheme 95");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Error auth scheme 42");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error auth password");
    }
    ulfius_clean_response(&auth_resp);
  }
  
  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  run_simple_test(&user_req, "DELETE", SERVER_URI "/auth/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&scope_req);
  ulfius_clean_request(&register_req);
  y_close_logs();
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

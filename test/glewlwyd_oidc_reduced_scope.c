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
#define PLUGIN_MODULE "oidc"
#define PLUGIN_NAME "oidc_rar"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_JWT_TYPE_RSA "rsa"
#define PLUGIN_JWT_KEY_SIZE "256"
#define SCOPE_OPENID "openid"
#define SCOPE_1 "scope1"
#define SCOPE_2 "scope2"
#define SCOPE_3 "scope3"
#define NONCE "nonce1234"
#define SCOPE_LIST (SCOPE_OPENID " " SCOPE_1 " " SCOPE_2 " " SCOPE_3)
#define CLIENT_ID "client_reduced"
#define CLIENT_SECRET "password"
#define CLIENT_REDIRECT "https://client.glewlwyd.tld"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_ACCESS_TOKEN_DURATION 3600
#define PLUGIN_PAR_PREFIX "urn:ietf:params:oauth:request_uri:"

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_oidc_reduced_scope_add_plugin)
{
  json_t * j_param = json_pack("{sssssss{sssssssssisisisososososososososossss}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", "sha",
                                  "jwt-key-size", "256",
                                  "key", "secret_" PLUGIN_NAME,
                                  "access-token-duration", 3600,
                                  "refresh-token-duration", 1209600,
                                  "code-duration", 600,
                                  "refresh-token-rolling", json_true(),
                                  "allow-non-oidc", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-id-token-enabled", json_true(),
                                  "auth-type-device-enabled", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "oauth-par-allowed", json_true(),
                                  "oauth-par-request_uri-prefix", PLUGIN_PAR_PREFIX,
                                  "restrict-scope-client-property", "scope");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_reduced_scope_add_client)
{
  json_t * j_param = json_pack("{sssososss[s]s[sss]s[ssss]}", "client_id", CLIENT_ID, "enabled", json_true(), "confidential", json_true(), "secret", CLIENT_SECRET, "redirect_uri", CLIENT_REDIRECT, "scope", SCOPE_OPENID, SCOPE_1, SCOPE_2, "authorization_type", "code", "token", "id_token", "device_authorization");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_reduced_scope_grant_client)
{
  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_reduced_scope_delete_plugin)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_reduced_scope_delete_client)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_reduced_scope_delete_grant_client)
{
  json_t * j_param = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_reduced_scope_auth_scope_not_reduced)
{
  char * scope;
  struct _u_response resp;
  struct _u_request * req = ulfius_duplicate_request(&user_req);
  
  ck_assert_int_eq(U_OK, ulfius_set_request_properties(req, U_OPT_HTTP_VERB, "GET",
                                                            U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth",
                                                            U_OPT_URL_PARAMETER, "client_id", CLIENT_ID,
                                                            U_OPT_URL_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                                            U_OPT_URL_PARAMETER, "scope", (SCOPE_OPENID " " SCOPE_1 " " SCOPE_2),
                                                            U_OPT_URL_PARAMETER, "response_type", "id_token token",
                                                            U_OPT_URL_PARAMETER, "nonce", "nonceAbcdXyz1234",
                                                            U_OPT_URL_PARAMETER, "g_continue", NULL,
                                                            U_OPT_NONE));
  ulfius_init_response(&resp);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(req, &resp));
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "scope="), NULL);
  scope = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "scope=") + o_strlen("scope="));
  if (o_strchr(scope, '&') != NULL) {
    *o_strchr(scope, '&') = '\0';
  }
  ck_assert_str_eq(scope, (SCOPE_OPENID "+" SCOPE_1 "+" SCOPE_2));
  ulfius_clean_request_full(req);
  ulfius_clean_response(&resp);
  o_free(scope);
}
END_TEST

START_TEST(test_oidc_reduced_scope_auth_scope_reduced)
{
  char * scope, * code;
  struct _u_response resp;
  struct _u_request * req = ulfius_duplicate_request(&user_req), code_req;
  json_t * j_body;
  
  ck_assert_int_eq(U_OK, ulfius_set_request_properties(req, U_OPT_HTTP_VERB, "GET",
                                                            U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth",
                                                            U_OPT_URL_PARAMETER, "client_id", CLIENT_ID,
                                                            U_OPT_URL_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                                            U_OPT_URL_PARAMETER, "scope", (SCOPE_OPENID " " SCOPE_1 " " SCOPE_3),
                                                            U_OPT_URL_PARAMETER, "response_type", "id_token token code",
                                                            U_OPT_URL_PARAMETER, "nonce", "nonceAbcdXyz1234",
                                                            U_OPT_URL_PARAMETER, "g_continue", NULL,
                                                            U_OPT_NONE));
  ulfius_init_response(&resp);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(req, &resp));
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "scope="), NULL);
  scope = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "scope=") + o_strlen("scope="));
  if (o_strchr(scope, '&') != NULL) {
    *o_strchr(scope, '&') = '\0';
  }
  code = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code="));
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  ck_assert_str_eq(scope, (SCOPE_OPENID "+" SCOPE_1));
  ulfius_clean_request_full(req);
  ulfius_clean_response(&resp);
  
  ulfius_init_request(&code_req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(U_OK, ulfius_set_request_properties(&code_req, U_OPT_HTTP_VERB, "POST",
                                                                  U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                                  U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                                  U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                                  U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                                  U_OPT_POST_BODY_PARAMETER, "code", code,
                                                                  U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                                                  U_OPT_NONE));
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&code_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq(json_string_value(json_object_get(j_body, "scope")), (SCOPE_OPENID " " SCOPE_1));
  json_decref(j_body);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&code_req);
  
  o_free(scope);
  o_free(code);
}
END_TEST

START_TEST(test_oidc_reduced_scope_auth_scope_invalid)
{
  struct _u_response resp;
  struct _u_request * req = ulfius_duplicate_request(&user_req);
  
  ck_assert_int_eq(U_OK, ulfius_set_request_properties(req, U_OPT_HTTP_VERB, "GET",
                                                            U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth",
                                                            U_OPT_URL_PARAMETER, "client_id", CLIENT_ID,
                                                            U_OPT_URL_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                                            U_OPT_URL_PARAMETER, "scope", (SCOPE_3),
                                                            U_OPT_URL_PARAMETER, "response_type", "id_token token",
                                                            U_OPT_URL_PARAMETER, "nonce", "nonceAbcdXyz1234",
                                                            U_OPT_URL_PARAMETER, "g_continue", NULL,
                                                            U_OPT_NONE));
  ulfius_init_response(&resp);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(req, &resp));
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "scope="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_scope"), NULL);

  ulfius_clean_request_full(req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_reduced_scope_par_scope_not_reduced)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_response, * j_body;
  char * code;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_POST_BODY_PARAMETER, "response_type", "code token",
                                U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "nonce", NONCE,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                U_OPT_POST_BODY_PARAMETER, "scope", (SCOPE_OPENID " " SCOPE_1 " " SCOPE_2),
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(201, resp.status);
  ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_response, "request_uri")), o_strlen(PLUGIN_PAR_PREFIX));
  ck_assert_int_eq(0, o_strncmp(json_string_value(json_object_get(j_response, "request_uri")), PLUGIN_PAR_PREFIX, o_strlen(PLUGIN_PAR_PREFIX)));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req);
  ulfius_copy_request(&req, &user_req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/auth"),
                                U_OPT_URL_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_URL_PARAMETER, "request_uri", json_string_value(json_object_get(j_response, "request_uri")),
                                U_OPT_URL_PARAMETER, "g_continue", NULL,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req);
  ulfius_copy_request(&req, &user_req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/token"),
                                U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                U_OPT_POST_BODY_PARAMETER, "code", code,
                                U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq(json_string_value(json_object_get(j_body, "scope")), (SCOPE_OPENID " " SCOPE_1 " " SCOPE_2));
  json_decref(j_body);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  o_free(code);
  json_decref(j_response);
}
END_TEST

START_TEST(test_oidc_reduced_scope_par_scope_reduced)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_response, * j_body;
  char * code;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_POST_BODY_PARAMETER, "response_type", "code token",
                                U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "nonce", NONCE,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                U_OPT_POST_BODY_PARAMETER, "scope", (SCOPE_OPENID " " SCOPE_1 " " SCOPE_3),
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(201, resp.status);
  ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_response, "request_uri")), o_strlen(PLUGIN_PAR_PREFIX));
  ck_assert_int_eq(0, o_strncmp(json_string_value(json_object_get(j_response, "request_uri")), PLUGIN_PAR_PREFIX, o_strlen(PLUGIN_PAR_PREFIX)));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req);
  ulfius_copy_request(&req, &user_req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/auth"),
                                U_OPT_URL_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_URL_PARAMETER, "request_uri", json_string_value(json_object_get(j_response, "request_uri")),
                                U_OPT_URL_PARAMETER, "g_continue", NULL,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req);
  ulfius_copy_request(&req, &user_req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/token"),
                                U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                U_OPT_POST_BODY_PARAMETER, "code", code,
                                U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq(json_string_value(json_object_get(j_body, "scope")), (SCOPE_OPENID " " SCOPE_1));
  json_decref(j_body);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  o_free(code);
  json_decref(j_response);
}
END_TEST

START_TEST(test_oidc_reduced_scope_par_scope_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_POST_BODY_PARAMETER, "response_type", "code token",
                                U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                U_OPT_POST_BODY_PARAMETER, "scope", (SCOPE_3),
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oidc_reduced_scope_device_verification_scope_not_reduced)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * redirect_uri, * code, * device_code;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", (SCOPE_OPENID " " SCOPE_1 " " SCOPE_2));
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_ptr_ne(code = json_string_value(json_object_get(j_resp, "user_code")), NULL);
  ck_assert_ptr_ne(device_code = json_string_value(json_object_get(j_resp, "device_code")), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/" PLUGIN_NAME "/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/device?code=%s&g_continue", code);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(redirect_uri = u_map_get(resp.map_header, "Location"), NULL);
  ck_assert_ptr_ne(o_strstr(redirect_uri, "prompt=deviceComplete"), NULL);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "refresh_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "id_token"), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "scope")), (SCOPE_OPENID " " SCOPE_1 " " SCOPE_2));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq((SCOPE_OPENID " " SCOPE_1 " " SCOPE_2), r_jwt_get_claim_str_value(jwt, "aud"));
  r_jwt_free(jwt);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_reduced_scope_device_verification_scope_reduced)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * redirect_uri, * code, * device_code;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", (SCOPE_OPENID " " SCOPE_1 " " SCOPE_3));
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_ptr_ne(code = json_string_value(json_object_get(j_resp, "user_code")), NULL);
  ck_assert_ptr_ne(device_code = json_string_value(json_object_get(j_resp, "device_code")), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/" PLUGIN_NAME "/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/device?code=%s&g_continue", code);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(redirect_uri = u_map_get(resp.map_header, "Location"), NULL);
  ck_assert_ptr_ne(o_strstr(redirect_uri, "prompt=deviceComplete"), NULL);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "refresh_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "id_token"), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "scope")), (SCOPE_OPENID " " SCOPE_1));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq((SCOPE_OPENID " " SCOPE_1), r_jwt_get_claim_str_value(jwt, "aud"));
  r_jwt_free(jwt);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_reduced_scope_device_verification_scope_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", (SCOPE_3));
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(403, resp.status);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc reduced scope");
  tc_core = tcase_create("test_oidc_reduced_scope");
  tcase_add_test(tc_core, test_oidc_reduced_scope_add_plugin);
  tcase_add_test(tc_core, test_oidc_reduced_scope_add_client);
  tcase_add_test(tc_core, test_oidc_reduced_scope_grant_client);
  tcase_add_test(tc_core, test_oidc_reduced_scope_auth_scope_not_reduced);
  tcase_add_test(tc_core, test_oidc_reduced_scope_auth_scope_reduced);
  tcase_add_test(tc_core, test_oidc_reduced_scope_auth_scope_invalid);
  tcase_add_test(tc_core, test_oidc_reduced_scope_par_scope_not_reduced);
  tcase_add_test(tc_core, test_oidc_reduced_scope_par_scope_reduced);
  tcase_add_test(tc_core, test_oidc_reduced_scope_par_scope_invalid);
  tcase_add_test(tc_core, test_oidc_reduced_scope_device_verification_scope_not_reduced);
  tcase_add_test(tc_core, test_oidc_reduced_scope_device_verification_scope_reduced);
  tcase_add_test(tc_core, test_oidc_reduced_scope_device_verification_scope_invalid);
  tcase_add_test(tc_core, test_oidc_reduced_scope_delete_grant_client);
  tcase_add_test(tc_core, test_oidc_reduced_scope_delete_client);
  tcase_add_test(tc_core, test_oidc_reduced_scope_delete_plugin);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req, register_req;
  struct _u_response auth_resp;
  int res, do_test = 0;
  json_t * j_body;
  char * cookie;

  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");

  ulfius_init_request(&admin_req);
  ulfius_init_request(&user_req);

  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&register_req);
  ulfius_init_response(&auth_resp);
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
      if (auth_resp.nb_cookies) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "User %s authenticated", USER_USERNAME);
        cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
        u_map_put(user_req.map_header, "Cookie", cookie);
        u_map_put(register_req.map_header, "Cookie", cookie);
        o_free(cookie);
        
        j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_true());
        run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
        json_decref(j_body);
        
        j_body = json_pack("{sssssss{ss}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
        run_simple_test(&user_req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
        json_decref(j_body);
        
        j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "register", json_true());
        run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
        json_decref(j_body);
        
        j_body = json_pack("{sssssss{ss}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "code", "88");
        run_simple_test(&user_req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
        json_decref(j_body);
        
        j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_true());
        run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
        json_decref(j_body);
        
        j_body = json_pack("{sssssss{ss}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
        run_simple_test(&user_req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
        json_decref(j_body);
        
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication user");
      do_test = 0;
    }
    ulfius_clean_response(&auth_resp);
    ulfius_clean_request(&auth_req);
  }

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_false());
  run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
  json_decref(j_body);
  
  j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "register", json_false());
  run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
  json_decref(j_body);
  
  j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_false());
  run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
  json_decref(j_body);

  char * url = msprintf("%s/auth/", SERVER_URI);
  run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  o_free(url);

  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&register_req);
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

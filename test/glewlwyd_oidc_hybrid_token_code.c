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
#define SCOPE_LIST "scope1 scope2 openid"
#define SCOPE_LIST_PARTIAL "scope1 openid"
#define SCOPE_LIST_PARTIAL_URL "scope1+openid"
#define SCOPE_LIST_MAX_USE "scope1 scope2 scope3 openid"
#define SCOPE_LIST_MAX_USE_URL "scope1+scope2+scope3+openid"
#define CLIENT "client1_id"
#define RESPONSE_TYPE "token code"

struct _u_request user_req;
char * code;

START_TEST(test_oidc_hybrid_token_code_redirect_login)
{
  char * url = msprintf("%s/oidc/auth?response_type=%s&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  int res = run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "login.html");
  o_free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_hybrid_token_code_redirect_login_post)
{
  char * url = o_strdup(SERVER_URI "/oidc/auth");
  struct _u_map body;
  
  u_map_init(&body);
  u_map_put(&body, "response_type", RESPONSE_TYPE);
  u_map_put(&body, "redirect_uri", "../../test-oauth2.html?param=client1_cb1");
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "state", "xyzabcd");
  u_map_put(&body, "nonce", "nonce1234");
  u_map_put(&body, "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(NULL, "POST", url, NULL, NULL, NULL, &body, 302, NULL, NULL, "login.html"), 1);
  o_free(url);
  u_map_clean(&body);
}
END_TEST

START_TEST(test_oidc_hybrid_token_code_valid)
{
  struct _u_response resp;
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/oidc/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_hybrid_token_code_valid_post)
{
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/oidc/auth", SERVER_URI);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("POST");
  u_map_put(user_req.map_post_body, "response_type", RESPONSE_TYPE);
  u_map_put(user_req.map_post_body, "client_id", CLIENT);
  u_map_put(user_req.map_post_body, "redirect_uri", "../../test-oauth2.html?param=client1_cb1");
  u_map_put(user_req.map_post_body, "state", "xyzabcd");
  u_map_put(user_req.map_post_body, "state", "xyzabcd");
  u_map_put(user_req.map_post_body, "nonce", "nonce1234");
  u_map_put(user_req.map_post_body, "scope", SCOPE_LIST);
  u_map_put(user_req.map_post_body, "g_continue", "true");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);

  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_hybrid_token_code_client_invalid)
{
  char * url = msprintf("%s/oidc/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, RESPONSE_TYPE, "invalid", SCOPE_LIST);
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "error=unauthorized_client");
  o_free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_hybrid_token_code_redirect_uri_invalid)
{
  char * url = msprintf("%s/oidc/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=invalid&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "error=unauthorized_client");
  o_free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_hybrid_token_code_scope_invalid)
{
  char * url = msprintf("%s/oidc/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, "scope4");
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "error=invalid_scope");
  o_free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_hybrid_token_code_empty)
{
  char * url = msprintf("%s/oidc/auth?response_type=%s&state=xyzabcd&nonce=nonce1234&g_continue", SERVER_URI, RESPONSE_TYPE);
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL);
  o_free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_hybrid_token_code_scope_grant_partial)
{
  struct _u_request auth_req, code_req;
  struct _u_response auth_resp, code_resp;
  json_t * j_body;
  char * cookie;

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_request(&code_req);
  ulfius_init_response(&code_resp);

  // Authenticate with password
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  // Get session cookie
  cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
  u_map_put(auth_req.map_header, "Cookie", cookie);
  u_map_put(code_req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_response(&auth_resp);

  // Grant access to scopes
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("PUT");
  auth_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", SCOPE_LIST_PARTIAL);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 42
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 95
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Get response_type=%s
  code_req.http_verb = strdup("GET");
  code_req.http_url = msprintf("%s/oidc/auth?response_type=%s&g_continue&state=xyzabcd&nonce=nonce1234&client_id=%s&redirect_uri=..%%2f..%%2ftest-oauth2.html%%3fparam%%3dclient1_cb1&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(code_resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(code_resp.map_header, "Location"), "code="), NULL);
  ck_assert_ptr_ne(o_strstr(o_strstr(u_map_get(code_resp.map_header, "Location"), "scope=") + o_strlen("scope="), SCOPE_LIST_PARTIAL_URL), NULL);
  ulfius_clean_response(&code_resp);

  // Clean grant scopes
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("PUT");
  auth_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);

  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&code_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST

START_TEST(test_oidc_hybrid_token_code_scope_grant_none)
{
  struct _u_request auth_req, code_req;
  struct _u_response auth_resp, code_resp;
  json_t * j_body;
  char * cookie;

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_request(&code_req);
  ulfius_init_response(&code_resp);

  // Authenticate with password
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  // Get session cookie
  cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
  u_map_put(auth_req.map_header, "Cookie", cookie);
  u_map_put(code_req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 42
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 95
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Try to get code
  code_req.http_verb = strdup("GET");
  code_req.http_url = msprintf("%s/oidc/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oauth2.html%%3fparam%%3dclient1_cb1&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(code_resp.map_header, "Location"), "code="), NULL);

  ulfius_clean_request(&code_req);
  ulfius_clean_response(&code_resp);
  ulfius_clean_request(&auth_req);
}
END_TEST

START_TEST(test_oidc_hybrid_token_code_scope_grant_all_authorize_partial)
{
  struct _u_request auth_req, code_req;
  struct _u_response auth_resp, code_resp;
  json_t * j_body;
  char * cookie;

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_request(&code_req);
  ulfius_init_response(&code_resp);

  // Authenticate with password
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  // Get session cookie
  cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
  u_map_put(auth_req.map_header, "Cookie", cookie);
  u_map_put(code_req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_response(&auth_resp);

  // Grant access to scopes
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("PUT");
  auth_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 95
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Try to get response_type=%s
  code_req.http_verb = strdup("GET");
  code_req.http_url = msprintf("%s/oidc/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oauth2.html%%3fparam%%3dclient1_cb1&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(code_resp.map_header, "Location"), "login.html"), NULL);

  // Clean grant scopes
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("PUT");
  auth_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);

  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&code_req);
  ulfius_clean_response(&auth_resp);
  ulfius_clean_response(&code_resp);
}
END_TEST

START_TEST(test_oidc_hybrid_token_code_retry_with_max_use)
{
  struct _u_request auth_req, code_req;
  struct _u_response auth_resp, code_resp;
  json_t * j_body;
  char * cookie;

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_request(&code_req);
  ulfius_init_response(&code_resp);

  // Authenticate with password
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  // Get session cookie
  cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
  u_map_put(auth_req.map_header, "Cookie", cookie);
  u_map_put(code_req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_response(&auth_resp);

  // Grant access to scopes
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("PUT");
  auth_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", SCOPE_LIST_MAX_USE);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 42
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 95
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Authenticate with scheme mock 88
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "code", "88");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Get response_type=%s
  code_req.http_verb = strdup("GET");
  code_req.http_url = msprintf("%s/oidc/auth?response_type=%s&g_continue&state=xyzabcd&nonce=nonce1234&client_id=%s&redirect_uri=..%%2f..%%2ftest-oauth2.html%%3fparam%%3dclient1_cb1&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST_MAX_USE);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(code_resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(code_resp.map_header, "Location"), "code="), NULL);
  ck_assert_ptr_ne(o_strstr(o_strstr(u_map_get(code_resp.map_header, "Location"), "scope=")+o_strlen("scope="), SCOPE_LIST_MAX_USE_URL), NULL);
  ulfius_clean_response(&code_resp);

  // Try to get another response_type=%s with the same session but redirected to login page
  ulfius_init_response(&code_resp);
  o_free(code_req.http_verb);
  o_free(code_req.http_url);
  code_req.http_verb = strdup("GET");
  code_req.http_url = msprintf("%s/oidc/auth?response_type=%s&g_continue&state=xyzabcd&nonce=nonce1234&client_id=%s&redirect_uri=..%%2f..%%2ftest-oauth2.html%%3fparam%%3dclient1_cb1&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST_MAX_USE);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(code_resp.map_header, "Location"), "login.html"), NULL);
  ulfius_clean_response(&code_resp);

  // Reauthenticate with scheme mock 88
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "code", "88");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);
  ulfius_clean_response(&auth_resp);

  // Get another code
  ulfius_init_response(&code_resp);
  o_free(code_req.http_verb);
  o_free(code_req.http_url);
  code_req.http_verb = strdup("GET");
  code_req.http_url = msprintf("%s/oidc/auth?response_type=%s&g_continue&state=xyzabcd&nonce=nonce1234&client_id=%s&redirect_uri=..%%2f..%%2ftest-oauth2.html%%3fparam%%3dclient1_cb1&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST_MAX_USE);
  ck_assert_int_eq(ulfius_send_http_request(&code_req, &code_resp), U_OK);
  ck_assert_int_eq(code_resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(code_resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(code_resp.map_header, "Location"), "code="), NULL);
  ck_assert_ptr_ne(o_strstr(o_strstr(u_map_get(code_resp.map_header, "Location"), "scope=")+o_strlen("scope="), SCOPE_LIST_MAX_USE_URL), NULL);
  ulfius_clean_response(&code_resp);

  // Clean grant scopes
  ulfius_init_response(&auth_resp);
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_verb = strdup("PUT");
  auth_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);

  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&code_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc hybrid token code");
  tc_core = tcase_create("test_oidc_hybrid_token_code");
  tcase_add_test(tc_core, test_oidc_hybrid_token_code_redirect_login);
  tcase_add_test(tc_core, test_oidc_hybrid_token_code_redirect_login_post);
  tcase_add_test(tc_core, test_oidc_hybrid_token_code_valid);
  tcase_add_test(tc_core, test_oidc_hybrid_token_code_valid_post);
  tcase_add_test(tc_core, test_oidc_hybrid_token_code_client_invalid);
  tcase_add_test(tc_core, test_oidc_hybrid_token_code_redirect_uri_invalid);
  tcase_add_test(tc_core, test_oidc_hybrid_token_code_scope_invalid);
  tcase_add_test(tc_core, test_oidc_hybrid_token_code_empty);
  tcase_add_test(tc_core, test_oidc_hybrid_token_code_scope_grant_partial);
  tcase_add_test(tc_core, test_oidc_hybrid_token_code_scope_grant_none);
  tcase_add_test(tc_core, test_oidc_hybrid_token_code_scope_grant_all_authorize_partial);
  tcase_add_test(tc_core, test_oidc_hybrid_token_code_retry_with_max_use);
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
  json_t * j_body, * j_register;
  int res, do_test = 0, i;
  char * url;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
  ulfius_init_request(&scope_req);
  ulfius_init_request(&register_req);
  ulfius_init_response(&scope_resp);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
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
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_true());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "register", json_true());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_true());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
    ulfius_set_json_body_request(&auth_req, j_body);
    json_decref(j_body);
    res = ulfius_send_http_request(&auth_req, &auth_resp);
    if (res == U_OK && auth_resp.status == 200) {
      j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_true());
      run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
      json_decref(j_register);
      
      ulfius_clean_response(&auth_resp);
      ulfius_init_response(&auth_resp);
      j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
      ulfius_set_json_body_request(&auth_req, j_body);
      json_decref(j_body);
      res = ulfius_send_http_request(&auth_req, &auth_resp);
      if (res == U_OK && auth_resp.status == 200) {
        y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);
    
        scope_req.http_verb = strdup("PUT");
        scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
        j_body = json_pack("{ss}", "scope", SCOPE_LIST);
        ulfius_set_json_body_request(&scope_req, j_body);
        json_decref(j_body);
        if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
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

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_false());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "register", json_false());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_false());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
  }
  
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&scope_req, j_body);
  json_decref(j_body);
  if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
  }
  
  url = msprintf("%s/auth/", SERVER_URI);
  run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  o_free(url);
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&scope_req);
  ulfius_clean_request(&register_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

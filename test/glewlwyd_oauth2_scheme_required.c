/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define USER_USERNAME "new_user"
#define USER_PASSWORD "password"

#define CLIENT "client1_id"
#define REDIRECT_URI "..%2f..%2ftest-oauth2.html?param=client1_cb1"
#define RESPONSE_TYPE_CODE "code"
#define RESPONSE_TYPE_TOKEN "token"

#define SCOPE "scheme_required_scope"
#define NAME "New Scope"
#define DESCRIPTION "Description for test-scope"
#define GROUP "group"
#define SCHEME1 "mock_scheme_42"
#define SCHEME1_VALUE "42"
#define SCHEME2 "mock_scheme_88"
#define SCHEME2_VALUE "88"
#define SCHEME3 "mock_scheme_95"
#define SCHEME3_VALUE "95"

struct _u_request admin_req;

START_TEST(test_oauth2_scheme_required_scope_set)
{
  json_t * j_parameters = json_pack("{ss ss ss so s{s[{ssss}{ssss}{ssss}]}s{si}}", "name", SCOPE, "display_name", NAME, "description", DESCRIPTION, "password_required", json_false(), "scheme", GROUP, "scheme_name", SCHEME1, "scheme_type", "mock", "scheme_name", SCHEME2, "scheme_type", "mock", "scheme_name", SCHEME3, "scheme_type", "mock", "scheme_required", GROUP, 2);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/scope/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssos[sss]ss}", "username", USER_USERNAME, "enabled", json_true(), "scope", SCOPE, "openid", "g_profile", "password", USER_PASSWORD);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oauth2_scheme_required_auth_flow)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  json_t * j_body;
  char * cookie;

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  
  // Authenticate with password
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USER_USERNAME, "password", USER_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  // Get session cookie
  cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
  u_map_put(auth_req.map_header, "Cookie", cookie);
  o_free(cookie);

  j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", SCHEME1, "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", SCHEME2, "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", SCHEME3, "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{ss}", "scope", SCOPE " openid");
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/auth/grant/" CLIENT, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/glwd/auth?response_type=" RESPONSE_TYPE_CODE "&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&nonce=abcdxyz&scope=" SCOPE " openid&g_continue", NULL, NULL, NULL, NULL, 302, NULL, NULL, "login.html"), 1);

  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/glwd/auth?response_type=" RESPONSE_TYPE_TOKEN "&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&nonce=abcdxyz&scope=" SCOPE " openid&g_continue", NULL, NULL, NULL, NULL, 302, NULL, NULL, "login.html"), 1);

  // Authenticate scheme mock 42
  j_body = json_pack("{sssssss{ss}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", SCHEME1, "value", "code", SCHEME1_VALUE);
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/glwd/auth?response_type=" RESPONSE_TYPE_CODE "&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&nonce=abcdxyz&scope=" SCOPE " openid&g_continue", NULL, NULL, NULL, NULL, 302, NULL, NULL, "login.html"), 1);

  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/glwd/auth?response_type=" RESPONSE_TYPE_TOKEN "&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&nonce=abcdxyz&scope=" SCOPE " openid&g_continue", NULL, NULL, NULL, NULL, 302, NULL, NULL, "login.html"), 1);

  // Authenticate scheme mock 95
  j_body = json_pack("{sssssss{ss}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", SCHEME3, "value", "code", SCHEME3_VALUE);
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/glwd/auth?response_type=" RESPONSE_TYPE_CODE "&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&nonce=abcdxyz&scope=" SCOPE " openid&g_continue", NULL, NULL, NULL, NULL, 302, NULL, NULL, "code="), 1);

  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/glwd/auth?response_type=" RESPONSE_TYPE_TOKEN "&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&nonce=abcdxyz&scope=" SCOPE " openid&g_continue", NULL, NULL, NULL, NULL, 302, NULL, NULL, "access_token="), 1);

  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/auth/grant/" CLIENT, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST

START_TEST(test_oauth2_scheme_required_scope_delete)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/user/" USER_USERNAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);

  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/scope/" SCOPE, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oauth2 scheme required");
  tc_core = tcase_create("test_oauth2_scheme_required");
  tcase_add_test(tc_core, test_oauth2_scheme_required_scope_set);
  tcase_add_test(tc_core, test_oauth2_scheme_required_auth_flow);
  tcase_add_test(tc_core, test_oauth2_scheme_required_scope_delete);
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
  int res, do_test = 0;
  json_t * j_body;
  char * cookie;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  ulfius_init_request(&admin_req);

  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
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
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  ulfius_clean_request(&admin_req);
  y_close_logs();
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

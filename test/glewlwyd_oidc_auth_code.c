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
#define SCOPE_LIST "scope1+scope2+openid"
#define SCOPE_LIST_POST "scope1 scope2 openid"
#define CLIENT "client1_id"
#define RESPONSE_TYPE "code"
#define REDIRECT_URI_ESCAPED "..%2f..%2ftest-oidc.html%3fparam%3dclient1_cb1"
#define REDIRECT_URI "../../test-oidc.html?param=client1_cb1"

struct _u_request user_req;

START_TEST(test_oidc_auth_invalid_response_type)
{
  const char * url = SERVER_URI "/oidc/auth?response_type=" "invalid" "&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI_ESCAPED "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "unsupported_response_type"), 1);
  url = SERVER_URI "/oidc/auth?response_type=" "&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI_ESCAPED "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "response_type+missing"), 1);
  url = SERVER_URI "/oidc/auth?response_type=" "invalid" "&g_continue&client_id=" "error" "&redirect_uri=" REDIRECT_URI_ESCAPED "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_auth_invalid_parameters)
{
  const char * url = SERVER_URI "/oidc/auth?g_continue&response_type=code&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI_ESCAPED "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "login.html"), 1);

  // client_id
  url = SERVER_URI "/oidc/auth?g_continue&response_type=code&redirect_uri=" REDIRECT_URI_ESCAPED "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  url = SERVER_URI "/oidc/auth?g_continue&response_type=code&client_id=&redirect_uri=" REDIRECT_URI_ESCAPED "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);

  // redirect_uri
  url = SERVER_URI "/oidc/auth?g_continue&response_type=code&client_id=" CLIENT "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  url = SERVER_URI "/oidc/auth?g_continue&response_type=code&client_id=" CLIENT "&redirect_uri=&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);

  // scope
  url = SERVER_URI "/oidc/auth?g_continue&response_type=code&client_id=&redirect_uri=" REDIRECT_URI_ESCAPED "&state=xyzabcd&nonce=nonce1234";
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  url = SERVER_URI "/oidc/auth?g_continue&response_type=code&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI_ESCAPED "&state=xyzabcd&nonce=nonce1234&scope=";
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_auth_code_state_ok)
{
  const char * url = SERVER_URI "/oidc/auth?response_type=" RESPONSE_TYPE "&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI_ESCAPED "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "state=xyzabcd");
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_auth_code_ok_redirect_login)
{
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/oidc/auth?response_type=" RESPONSE_TYPE "&client_id=client1_id&redirect_uri="REDIRECT_URI_ESCAPED"&state=xyz&nonce=nonce1234&scope=" SCOPE_LIST, NULL, NULL, NULL, NULL, 302, NULL, NULL, "login.html"), 1);
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/oidc/auth?response_type=" RESPONSE_TYPE "&client_id=client1_id&redirect_uri="REDIRECT_URI_ESCAPED"&state=xyzabcd&nonce=nonce1234&g_continue&scope=" SCOPE_LIST, NULL, NULL, NULL, NULL, 302, NULL, NULL, "login.html"), 1);
}
END_TEST

START_TEST(test_oidc_auth_code_client_invalid)
{
  const char * url = SERVER_URI "/oidc/auth?response_type=" RESPONSE_TYPE "&g_continue&client_id=" "client_error" "&redirect_uri=" REDIRECT_URI_ESCAPED "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  url = SERVER_URI "/oidc/auth?response_type=" RESPONSE_TYPE "&g_continue&client_id=" "&redirect_uri=" REDIRECT_URI_ESCAPED "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_auth_code_uri_invalid)
{
  const char * url = SERVER_URI "/oidc/auth?response_type=" RESPONSE_TYPE "&g_continue&client_id=" CLIENT "&redirect_uri=" "..%2f..%2ftest-oidc.html%3fparam%3derror" "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  url = SERVER_URI "/oidc/auth?response_type=" RESPONSE_TYPE "&g_continue&client_id=" CLIENT "&redirect_uri=" "https%3a%2f%2ferror.org" "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  url = SERVER_URI "/oidc/auth?response_type=" RESPONSE_TYPE "&g_continue&client_id=" CLIENT "&redirect_uri=" "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_auth_code_scope_invalid)
{
  const char * url = SERVER_URI "/oidc/auth?response_type=" RESPONSE_TYPE "&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI_ESCAPED "&state=xyzabcd&nonce=nonce1234&scope=" "scope4";
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "invalid_scope");
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_auth_code_ok_redirect_cb_with_code)
{
  const char * url = SERVER_URI "/oidc/auth?response_type=" RESPONSE_TYPE "&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI_ESCAPED "&state=xyzabcd&nonce=nonce1234&scope=" SCOPE_LIST;
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "code="), 1);
}
END_TEST

START_TEST(test_oidc_auth_code_ok_redirect_cb_with_code_post)
{
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/oidc/auth", SERVER_URI);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("POST");
  u_map_put(user_req.map_post_body, "response_type", RESPONSE_TYPE);
  u_map_put(user_req.map_post_body, "client_id", CLIENT);
  u_map_put(user_req.map_post_body, "redirect_uri", REDIRECT_URI);
  u_map_put(user_req.map_post_body, "state", "xyzabcd");
  u_map_put(user_req.map_post_body, "nonce", "nonce1234");
  u_map_put(user_req.map_post_body, "scope", SCOPE_LIST_POST);
  u_map_put(user_req.map_post_body, "g_continue", "true");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);

  ulfius_clean_response(&resp);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc auth_code");
  tc_core = tcase_create("test_oidc_auth_code");
  tcase_add_test(tc_core, test_oidc_auth_invalid_response_type);
  tcase_add_test(tc_core, test_oidc_auth_invalid_parameters);
  tcase_add_test(tc_core, test_oidc_auth_code_state_ok);
  tcase_add_test(tc_core, test_oidc_auth_code_ok_redirect_login);
  tcase_add_test(tc_core, test_oidc_auth_code_client_invalid);
  tcase_add_test(tc_core, test_oidc_auth_code_uri_invalid);
  tcase_add_test(tc_core, test_oidc_auth_code_scope_invalid);
  tcase_add_test(tc_core, test_oidc_auth_code_ok_redirect_cb_with_code);
  tcase_add_test(tc_core, test_oidc_auth_code_ok_redirect_cb_with_code_post);
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

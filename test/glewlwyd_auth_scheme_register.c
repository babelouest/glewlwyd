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
#define SCHEME_TYPE "mock"
#define SCHEME_NAME "mock_scheme_42"
#define SCHEME_DISPLAY_NAME "Mock 42"
#define SCHEME_VALUE "42"
#define SCOPE_LIST "scope1"

struct _u_request user_req;

START_TEST(test_glwd_auth_scheme_register_error_parameters)
{
  json_t * j_register;
  
  j_register = json_pack("{ssssssss}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "register");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
  j_register = json_pack("{sssisss{so}}", "username", USERNAME, "scheme_type", 42, "scheme_name", SCHEME_NAME, "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
  j_register = json_pack("{sssssis{so}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", 42, "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
  j_register = json_pack("{sssssss{so}}", "username", "user2", "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
  j_register = json_pack("{sssss{so}}", "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
  j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
}
END_TEST

START_TEST(test_glwd_auth_scheme_register_success)
{
  json_t * j_body, * j_expected;
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_verb);
  o_free(user_req.http_url);
  user_req.http_verb = o_strdup("GET");
  user_req.http_url = msprintf("%s/auth/scheme/?scope=%s", SERVER_URI, SCOPE_LIST);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ulfius_clean_response(&resp);
  j_expected = json_pack("{sssssssoso}", "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "scheme_display_name", SCHEME_DISPLAY_NAME, "scheme_authenticated", json_false(), "scheme_registered", json_false());
  ck_assert_int_eq(json_equal(json_array_get(json_object_get(json_object_get(json_object_get(j_body, "scope1"), "schemes"), "mock_group_1"), 0), j_expected), 1);
  json_decref(j_body);
  json_decref(j_expected);
  
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "code", SCHEME_VALUE);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{ssssss}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{ssssss}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ulfius_clean_response(&resp);
  j_expected = json_pack("{sssssssoso}", "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "scheme_display_name", SCHEME_DISPLAY_NAME, "scheme_authenticated", json_false(), "scheme_registered", json_true());
  ck_assert_int_eq(json_equal(json_array_get(json_object_get(json_object_get(json_object_get(j_body, "scope1"), "schemes"), "mock_group_1"), 0), j_expected), 1);
  json_decref(j_body);
  json_decref(j_expected);
  
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "code", SCHEME_VALUE);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ulfius_clean_response(&resp);
  j_expected = json_pack("{sssssssoso}", "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "scheme_display_name", SCHEME_DISPLAY_NAME, "scheme_authenticated", json_true(), "scheme_registered", json_true());
  ck_assert_int_eq(json_equal(json_array_get(json_object_get(json_object_get(json_object_get(j_body, "scope1"), "schemes"), "mock_group_1"), 0), j_expected), 1);
  json_decref(j_body);
  json_decref(j_expected);
  
}
END_TEST

START_TEST(test_glwd_auth_scheme_deregister_success)
{
  json_t * j_body, * j_expected;
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_verb);
  o_free(user_req.http_url);
  user_req.http_verb = o_strdup("GET");
  user_req.http_url = msprintf("%s/auth/scheme/?scope=%s", SERVER_URI, SCOPE_LIST);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ulfius_clean_response(&resp);
  j_expected = json_pack("{sssssssoso}", "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "scheme_display_name", SCHEME_DISPLAY_NAME, "scheme_authenticated", json_true(), "scheme_registered", json_true());
  ck_assert_int_eq(json_equal(json_array_get(json_object_get(json_object_get(json_object_get(j_body, "scope1"), "schemes"), "mock_group_1"), 0), j_expected), 1);
  json_decref(j_body);
  json_decref(j_expected);
  
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "code", SCHEME_VALUE);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "register", json_false());
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ulfius_clean_response(&resp);
  j_expected = json_pack("{sssssssoso}", "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "scheme_display_name", SCHEME_DISPLAY_NAME, "scheme_authenticated", json_false(), "scheme_registered", json_false());
  ck_assert_int_eq(json_equal(json_array_get(json_object_get(json_object_get(json_object_get(j_body, "scope1"), "schemes"), "mock_group_1"), 0), j_expected), 1);
  json_decref(j_body);
  json_decref(j_expected);
  
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "code", SCHEME_VALUE);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd scheme register");
  tc_core = tcase_create("test_glwd_auth_scheme_register");
  tcase_add_test(tc_core, test_glwd_auth_scheme_register_error_parameters);
  tcase_add_test(tc_core, test_glwd_auth_scheme_register_success);
  tcase_add_test(tc_core, test_glwd_auth_scheme_deregister_success);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req, scope_req;
  struct _u_response auth_resp, scope_resp;
  json_t * j_body;
  int res, do_test = 0, i;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
  ulfius_init_request(&scope_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_response(&scope_resp);
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
      o_free(cookie);
    }
    do_test = 1;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
  }
  ulfius_clean_response(&auth_resp);

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    j_body = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "register", json_false());
    run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
    json_decref(j_body);
  }
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&user_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

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
#define USERNAME_ERROR_USE "user2"
#define SCHEME_TYPE "mock"
#define SCHEME_NAME "mock_scheme_42"

START_TEST(test_glwd_auth_scheme_trigger_error_parameters)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body = NULL;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);

  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/scheme/trigger/", SERVER_URI);

  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  j_body = json_pack("{sssss{ss}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "value", "data", "grut");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  j_body = json_pack("{sssss{ss}}", "username", USERNAME, "scheme_name", SCHEME_NAME, "value", "data", "grut");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  j_body = json_pack("{sssss{ss}}", "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "data", "grut");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_glwd_auth_scheme_trigger_error_login)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body = NULL;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);

  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/scheme/trigger/", SERVER_URI);

  j_body = json_pack("{sssssss{ss}}", "username", USERNAME_ERROR_USE, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "data", "grut");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_glwd_auth_scheme_trigger_success)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body = NULL;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);

  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/scheme/trigger/", SERVER_URI);

  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "data", "grut");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd auth scheme trigger");
  tc_core = tcase_create("test_glwd_auth_scheme_trigger");
  tcase_add_test(tc_core, test_glwd_auth_scheme_trigger_error_parameters);
  tcase_add_test(tc_core, test_glwd_auth_scheme_trigger_error_login);
  tcase_add_test(tc_core, test_glwd_auth_scheme_trigger_success);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req, user_req;
  struct _u_response auth_resp;
  json_t * j_body;
  int res, do_test = 0, i;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200 && auth_resp.nb_cookies) {
    for (i=0; i<auth_resp.nb_cookies; i++) {
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(user_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    
    j_body = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "register", json_true());
    run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
    json_decref(j_body);

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

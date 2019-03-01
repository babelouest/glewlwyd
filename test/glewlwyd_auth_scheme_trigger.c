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

  j_body = json_pack("{sssss{ss}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "value", "data", "grut");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);

  j_body = json_pack("{sssss{ss}}", "username", USERNAME, "scheme_name", SCHEME_NAME, "value", "data", "grut");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);

  j_body = json_pack("{sssss{ss}}", "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "data", "grut");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
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
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd scheme trigger");
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
  int number_failed;
  Suite *s;
  SRunner *sr;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  s = glewlwyd_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

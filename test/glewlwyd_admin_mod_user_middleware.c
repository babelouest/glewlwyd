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
#define USERNAME "admin"
#define PASSWORD "password"
#define MODULE_MODULE "mock"
#define MODULE_NAME "test_middleware"
#define MODULE_NAME_WITH_ERRORS "test_middleware_with_errors"
#define MODULE_DISPLAY_NAME "test_middleware name"

struct _u_request admin_req;

START_TEST(test_glwd_admin_get_mod_user_middleware_get_list)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/mod/user_middleware/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_user_middleware_add_error_json)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/user_middleware/", NULL, NULL, NULL, NULL, 400, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_user_middleware_add_error_param)
{
  json_t * j_parameters = json_pack("{ss}", "error", "error");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/user_middleware/", NULL, NULL, NULL, NULL, 400, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/user_middleware/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssssis{ss}}", "module", "error", "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "order_rank", 0, "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/user_middleware/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssisssis{ss}}", "module", MODULE_MODULE, "name", 42, "display_name", MODULE_DISPLAY_NAME, "order_rank", 0, "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/user_middleware/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssisis{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", 42, "order_rank", 0, "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/user_middleware/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssssss{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "order_rank", "error", "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/user_middleware/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssssis{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "order_rank", -42, "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/user_middleware/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssssiss}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "order_rank", 0, "parameters", "error");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/user_middleware/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_user_middleware_add_OK)
{
  json_t * j_parameters = json_pack("{sssssssis{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "order_rank", 0, "parameters", "mock-value", MODULE_NAME);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/user_middleware/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);

  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/mod/user_middleware/" MODULE_NAME, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_user_middleware_get)
{
  json_t * j_parameters = json_pack("{sssssssis{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "order_rank", 0, "parameters", "mock-value", MODULE_NAME);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/mod/user_middleware/" MODULE_NAME, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/mod/user_middleware/error", NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_user_middleware_set_error_param)
{
  json_t * j_parameters = json_pack("{ss}", "error", "error");
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sis{ss}}", "display_name", 42, "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssis{ss}}", "display_name", MODULE_DISPLAY_NAME, "order_rank", -42, "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssss{ss}}", "display_name", MODULE_DISPLAY_NAME, "order_rank", json_false(), "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssiss}", "display_name", MODULE_DISPLAY_NAME, "order_rank", 0, "parameters", "error");
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_user_middleware_set_OK)
{
  json_t * j_parameters = json_pack("{sssis{ss}}", "display_name", MODULE_DISPLAY_NAME, "order_rank", 0, "parameters", "mock-value", MODULE_NAME);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/mod/user_middleware/" MODULE_NAME, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_user_middleware_action)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME "/disable", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME "/disable", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME "/enable", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME "/enable", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME "/error", NULL, NULL, NULL, NULL, 400, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_user_middleware_delete_error)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/user_middleware/error", NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_user_middleware_delete_OK)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/user_middleware/" MODULE_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_admin_mod_user_middleware_with_errors)
{  
  json_t * j_parameters = json_pack("{sssssssis{so}}", "module", MODULE_MODULE, "name", MODULE_NAME_WITH_ERRORS, "display_name", MODULE_DISPLAY_NAME, "order_rank", 1, "parameters", "middleware", json_true());
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/user_middleware/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/mod/user_middleware/" MODULE_NAME_WITH_ERRORS, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME_WITH_ERRORS "/enable", NULL, NULL, NULL, NULL, 400, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/user_middleware/" MODULE_NAME_WITH_ERRORS, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd admin module user_middleware");
  tc_core = tcase_create("test_glwd_admin_mod_user_middleware");
  tcase_add_test(tc_core, test_glwd_admin_get_mod_user_middleware_get_list);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_user_middleware_add_error_json);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_user_middleware_add_error_param);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_user_middleware_add_OK);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_user_middleware_get);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_user_middleware_set_error_param);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_user_middleware_set_OK);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_user_middleware_action);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_user_middleware_delete_error);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_user_middleware_delete_OK);
  tcase_add_test(tc_core, test_glwd_admin_mod_user_middleware_with_errors);
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
  int res, do_test = 0, i;
  json_t * j_body;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&admin_req);
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
      u_map_put(admin_req.map_header, "Cookie", cookie);
      o_free(cookie);
      do_test = 1;
    }
    ulfius_clean_response(&auth_resp);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
  }
  ulfius_clean_request(&auth_req);
  
  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  ulfius_clean_request(&admin_req);
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

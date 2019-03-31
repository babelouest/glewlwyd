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
#define MODULE_NAME "test"
#define MODULE_DISPLAY_NAME "test name"

struct _u_request admin_req;

START_TEST(test_glwd_admin_get_mod_plugin_get_list)
{
  char * url = msprintf("%s/mod/plugin/", SERVER_URI);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_plugin_add_error_json)
{
  char * url = msprintf("%s/mod/plugin/", SERVER_URI);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, NULL, NULL, 400, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_plugin_add_error_param)
{
  char * url = msprintf("%s/mod/plugin/", SERVER_URI);
  json_t * j_parameters = json_pack("{ss}", "error", "error");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, NULL, NULL, 400, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssss{ss}}", "module", "error", "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssisss{ss}}", "module", MODULE_MODULE, "name", 42, "display_name", MODULE_DISPLAY_NAME, "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssis{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", 42, "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{ssssssss}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "parameters", "error");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  o_free(url);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_plugin_add_OK)
{
  char * url = msprintf("%s/mod/plugin/", SERVER_URI);
  json_t * j_parameters = json_pack("{sssssss{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "parameters", "mock-value", MODULE_NAME);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
  
  url = msprintf("%s/mod/plugin/%s", SERVER_URI, MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_plugin_get)
{
  char * url = msprintf("%s/mod/plugin/%s", SERVER_URI, MODULE_NAME), * url_404 = msprintf("%s/mod/plugin/error", SERVER_URI);
  json_t * j_parameters = json_pack("{sssssss{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "parameters", "mock-value", MODULE_NAME);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url_404, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_plugin_set_error_param)
{
  char * url = msprintf("%s/mod/plugin/%s", SERVER_URI, MODULE_NAME);
  json_t * j_parameters = json_pack("{ss}", "error", "error");
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sis{ss}}", "display_name", 42, "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{ssss}", "display_name", MODULE_DISPLAY_NAME, "parameters", "error");
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  o_free(url);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_plugin_set_OK)
{
  char * url = msprintf("%s/mod/plugin/%s", SERVER_URI, MODULE_NAME);
  json_t * j_parameters = json_pack("{sss{ss}}", "display_name", MODULE_DISPLAY_NAME, "parameters", "mock-value", MODULE_NAME);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  
  url = msprintf("%s/mod/plugin/%s", SERVER_URI, MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_plugin_action)
{
  char * url = msprintf("%s/mod/plugin/%s/disable", SERVER_URI, MODULE_NAME);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, NULL, NULL, 400, NULL, NULL, NULL), 1);
  o_free(url);
  
  url = msprintf("%s/mod/plugin/%s/enable", SERVER_URI, MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, NULL, NULL, 400, NULL, NULL, NULL), 1);
  o_free(url);
  
  url = msprintf("%s/mod/plugin/%s/error", SERVER_URI, MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, NULL, NULL, 400, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_plugin_delete_error)
{
  char * url = msprintf("%s/mod/plugin/error", SERVER_URI);

  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_admin_get_mod_plugin_delete_OK)
{
  char * url = msprintf("%s/mod/plugin/%s", SERVER_URI, MODULE_NAME);

  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd admin module plugin");
  tc_core = tcase_create("test_glwd_admin_mod_plugin");
  tcase_add_test(tc_core, test_glwd_admin_get_mod_plugin_get_list);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_plugin_add_error_json);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_plugin_add_error_param);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_plugin_add_OK);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_plugin_get);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_plugin_set_error_param);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_plugin_set_OK);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_plugin_action);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_plugin_delete_error);
  tcase_add_test(tc_core, test_glwd_admin_get_mod_plugin_delete_OK);
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

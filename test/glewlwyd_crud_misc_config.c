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
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define USER_USERNAME "user1"
#define USER_PASSWORD "password"

#define CONFIG_NAME_1 "config1"
#define CONFIG_TYPE_1 "type1"
#define CONFIG_STR "value"
#define CONFIG_INT 42

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_glwd_crud_misc_config_add_ok)
{
  json_t * j_body = json_pack("{sss{sssi}}", "type", CONFIG_TYPE_1, "value", "str_value", CONFIG_STR, "int_value", CONFIG_INT);
  ck_assert_ptr_ne(NULL, j_body);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "PUT", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
}
END_TEST

START_TEST(test_glwd_crud_misc_config_get_ok)
{
  json_t * j_body = json_pack("{sss{sssi}}", "type", CONFIG_TYPE_1, "value", "str_value", CONFIG_STR, "int_value", CONFIG_INT);
  ck_assert_ptr_ne(NULL, j_body);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/misc/", NULL, NULL, NULL, NULL, 200, j_body, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, NULL, NULL, 200, j_body, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/misc/" "error", NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/misc/", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/misc/" "error", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/misc/", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/misc/" "error", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
}
END_TEST

START_TEST(test_glwd_crud_misc_config_set_ok)
{
  json_t * j_body = json_pack("{sss{sssi}}", "type", CONFIG_TYPE_1, "value", "str_value", CONFIG_STR, "int_value", CONFIG_INT),
         * j_body2 = json_pack("{sss{sssi}}", "type", CONFIG_TYPE_1, "value", "str_value", CONFIG_STR "-more", "int_value", CONFIG_INT+1);
  ck_assert_ptr_ne(NULL, j_body);
  ck_assert_ptr_ne(NULL, j_body2);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/misc/", NULL, NULL, NULL, NULL, 200, j_body, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, j_body2, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/misc/", NULL, NULL, NULL, NULL, 200, j_body2, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  json_decref(j_body2);
}
END_TEST

START_TEST(test_glwd_crud_misc_config_delete_ok)
{
  json_t * j_body = json_pack("{sss{sssi}}", "type", CONFIG_TYPE_1, "value", "str_value", CONFIG_STR, "int_value", CONFIG_INT);
  ck_assert_ptr_ne(NULL, j_body);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/misc/", NULL, NULL, NULL, NULL, 200, j_body, NULL, NULL), 1);

  ck_assert_int_eq(run_simple_test(&user_req, "DELETE", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "DELETE", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/misc/" "error", NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/misc/" CONFIG_NAME_1, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
  json_decref(j_body);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd CRUD misc config");
  tc_core = tcase_create("test_glwd_crud_misc_config");
  tcase_add_test(tc_core, test_glwd_crud_misc_config_add_ok);
  tcase_add_test(tc_core, test_glwd_crud_misc_config_get_ok);
  tcase_add_test(tc_core, test_glwd_crud_misc_config_set_ok);
  tcase_add_test(tc_core, test_glwd_crud_misc_config_delete_ok);
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
  char * cookie;
  json_t * j_body;

  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");

  ulfius_init_request(&admin_req);
  ulfius_init_request(&user_req);

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
    // Getting a valid session id for authenticated http requests
    ulfius_init_request(&auth_req);
    ulfius_init_response(&auth_resp);
    auth_req.http_verb = strdup("POST");
    auth_req.http_url = msprintf(SERVER_URI "/auth/");
    j_body = json_pack("{ssss}", "username", USER_USERNAME, "password", USER_PASSWORD);
    ulfius_set_json_body_request(&auth_req, j_body);
    json_decref(j_body);
    res = ulfius_send_http_request(&auth_req, &auth_resp);
    if (res == U_OK && auth_resp.status == 200) {
      if (auth_resp.nb_cookies) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "User %s authenticated", USER_USERNAME);
        cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
        u_map_put(user_req.map_header, "Cookie", cookie);
        o_free(cookie);
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

  run_simple_test(&user_req, "DELETE", SERVER_URI "/auth/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  run_simple_test(&admin_req, "DELETE", SERVER_URI "/auth/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);

  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

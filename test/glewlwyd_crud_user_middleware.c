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

#define NEW_USERNAME "test"
#define NEW_NAME "Dave Lopper"
#define NEW_EMAIL "test@glewlwyd"
#define NEW_SCOPE_1 "scope1"
#define NEW_SCOPE_2 "scope2"

#define MODULE_MODULE "mock"
#define MODULE_NAME "test_middleware"
#define MODULE_DISPLAY_NAME "test_middleware name"
#define MODULE_MIDDLEWARE_VALUE "wizard"

struct _u_request admin_req;

START_TEST(test_glwd_admin_mod_user_middleware_add_OK)
{
  json_t * j_parameters = json_pack("{sssssssis{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "order_rank", 0, "parameters", "middleware", MODULE_MIDDLEWARE_VALUE);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/user_middleware/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);

  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_admin_mod_user_middleware_delete_OK)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/user_middleware/" MODULE_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_crud_user_middleware_add_OK)
{
  json_t * j_parameters = json_pack("{sssssss[ss]ss}", "username", NEW_USERNAME, "name", NEW_NAME, "email", NEW_EMAIL, "scope", NEW_SCOPE_1, NEW_SCOPE_2, "middleware", MODULE_MIDDLEWARE_VALUE);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_object_set_new(j_parameters, "middleware", json_string(MODULE_MIDDLEWARE_VALUE "-" NEW_USERNAME));
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_user_middleware_get_list)
{
  json_t * j_parameters = json_pack("{sssssss[ss]ss}", "username", NEW_USERNAME, "name", NEW_NAME, "email", NEW_EMAIL, "scope", NEW_SCOPE_1, NEW_SCOPE_2, "middleware", MODULE_MIDDLEWARE_VALUE "-" NEW_USERNAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/", NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_user_middleware_get)
{
  json_t * j_parameters = json_pack("{sssssss[ss]ss}", "username", NEW_USERNAME, "name", NEW_NAME, "email", NEW_EMAIL, "scope", NEW_SCOPE_1, NEW_SCOPE_2, "middleware", MODULE_MIDDLEWARE_VALUE "-" NEW_USERNAME);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/error", NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_user_middleware_get_profile_impersonate)
{
  json_t * j_parameters = json_pack("{ssss}", "username", USERNAME, "middleware", MODULE_MIDDLEWARE_VALUE "-" USERNAME "-profile");
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/profile_list", NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_user_middleware_set_OK)
{
  json_t * j_parameters = json_pack("{sssss[s]ss}", "name", NEW_NAME "-new", "email", NEW_EMAIL "-new", "scope", NEW_SCOPE_1, "middleware", MODULE_MIDDLEWARE_VALUE);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  
  json_object_set_new(j_parameters, "username", json_string(NEW_USERNAME));
  json_object_set_new(j_parameters, "middleware", json_string(MODULE_MIDDLEWARE_VALUE "-" NEW_USERNAME));
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_user_middleware_set_then_disable_module_OK)
{
  json_t * j_parameters = json_pack("{sssss[s]ss}", "name", NEW_NAME "-new", "email", NEW_EMAIL "-new", "scope", NEW_SCOPE_1, "middleware", MODULE_MIDDLEWARE_VALUE);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  
  json_object_set_new(j_parameters, "username", json_string(NEW_USERNAME));
  json_object_set_new(j_parameters, "middleware", json_string(MODULE_MIDDLEWARE_VALUE "-" NEW_USERNAME));
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME "/disable", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  j_parameters = json_pack("{sssssss[s]ss}", "username", NEW_USERNAME, "name", NEW_NAME "-new", "email", NEW_EMAIL "-new", "scope", NEW_SCOPE_1, "middleware", MODULE_MIDDLEWARE_VALUE);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/mod/user_middleware/" MODULE_NAME "/enable", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  json_object_set_new(j_parameters, "middleware", json_string(MODULE_MIDDLEWARE_VALUE "-" NEW_USERNAME));
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_user_middleware_delete_OK)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd CRUD user");
  tc_core = tcase_create("test_glwd_crud_user_middleware");
  tcase_add_test(tc_core, test_glwd_admin_mod_user_middleware_add_OK);
  tcase_add_test(tc_core, test_glwd_crud_user_middleware_add_OK);
  tcase_add_test(tc_core, test_glwd_crud_user_middleware_get_list);
  tcase_add_test(tc_core, test_glwd_crud_user_middleware_get);
  tcase_add_test(tc_core, test_glwd_crud_user_middleware_get_profile_impersonate);
  tcase_add_test(tc_core, test_glwd_crud_user_middleware_set_OK);
  tcase_add_test(tc_core, test_glwd_crud_user_middleware_set_then_disable_module_OK);
  tcase_add_test(tc_core, test_glwd_crud_user_middleware_delete_OK);
  tcase_add_test(tc_core, test_glwd_admin_mod_user_middleware_delete_OK);
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

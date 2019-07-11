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
#define MODULE_NAME_1 "test1"
#define MODULE_NAME_2 "test2"
#define MODULE_DISPLAY_NAME "test name"
#define MODULE_PREFIX_1 "mock1-"
#define MODULE_PREFIX_2 "mock2-"

struct _u_request admin_req;

START_TEST(test_glwd_crud_user_get_list)
{
  char * url = msprintf("%s/user/", SERVER_URI);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_crud_user_add_error_json)
{
  char * url = msprintf("%s/user/", SERVER_URI);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, NULL, NULL, 400, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_crud_user_add_error_param)
{
  char * url = msprintf("%s/user/", SERVER_URI);
  json_t * j_parameters = json_pack("{ss}", "error", "error");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("[{ss}]", "username", "test");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{si}", "username", 42);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  o_free(url);
}
END_TEST

START_TEST(test_glwd_crud_user_add_OK)
{
  char * url = msprintf("%s/user/", SERVER_URI);
  json_t * j_parameters = json_pack("{sssssss[ss]}", "username", NEW_USERNAME, "name", NEW_NAME, "email", NEW_EMAIL, "scope", NEW_SCOPE_1, NEW_SCOPE_2);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
  
  url = msprintf("%s/user/%s", SERVER_URI, NEW_USERNAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_user_add_already_present)
{
  char * url = msprintf("%s/user/", SERVER_URI);
  json_t * j_parameters = json_pack("{ss}", "username", NEW_USERNAME);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_user_get)
{
  char * url = msprintf("%s/user/%s", SERVER_URI, NEW_USERNAME), * url_404 = msprintf("%s/mod/user/error", SERVER_URI);
  json_t * j_parameters = json_pack("{sssssss[ss]}", "username", NEW_USERNAME, "name", NEW_NAME, "email", NEW_EMAIL, "scope", NEW_SCOPE_1, NEW_SCOPE_2);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url_404, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
  o_free(url);
  o_free(url_404);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_user_set_OK)
{
  char * url = msprintf("%s/user/%s", SERVER_URI, NEW_USERNAME);
  json_t * j_parameters = json_pack("{sssss[s]}", "name", NEW_NAME "-new", "email", NEW_EMAIL "-new", "scope", NEW_SCOPE_1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  
  json_object_set_new(j_parameters, "username", json_string(NEW_USERNAME));
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_user_delete_error)
{
  char * url = msprintf("%s/user/error", SERVER_URI);

  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_crud_user_delete_OK)
{
  char * url = msprintf("%s/user/%s", SERVER_URI, NEW_USERNAME);

  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_crud_user_list_limit)
{
  json_t * j_result;
  int res;
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/user/?offset=2", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 2);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "user2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "username")), "user3");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/user/?limit=2", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 2);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "admin");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "username")), "user1");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/user/?offset=1&limit=2", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 2);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "user1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "username")), "user2");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/user/?offset=3&limit=3", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 1);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "user3");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
}
END_TEST

START_TEST(test_glwd_crud_user_list_pattern)
{
  json_t * j_result;
  int res;
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/user/?pattern=user", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 3);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "user1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "username")), "user2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 2), "username")), "user3");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/user/?pattern=error", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 0);
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/user/?pattern=user&limit=2", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 2);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "user1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "username")), "user2");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
}
END_TEST

START_TEST(test_glwd_crud_user_list_add_user_module_instances)
{
  char * url = msprintf("%s/mod/user/", SERVER_URI);
  json_t * j_parameters = json_pack("{sssssssisos{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME_1, "display_name", MODULE_DISPLAY_NAME, "order_rank", 1, "readonly", json_true(), "parameters", "username-prefix", MODULE_PREFIX_1);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  j_parameters = json_pack("{sssssssisos{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME_2, "display_name", MODULE_DISPLAY_NAME, "order_rank", 2, "readonly", json_true(), "parameters", "username-prefix", MODULE_PREFIX_2);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_user_list_pattern_multiple_source)
{
  json_t * j_result;
  int res;
  struct _u_response resp;

  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/user/?offset=2&limit=4&pattern=user", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 4);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "user3");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "username")), "mock1-user1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 2), "username")), "mock1-user2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 3), "username")), "mock1-user3");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/user/?offset=1&limit=8&pattern=user1", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 2);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "mock1-user1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "username")), "mock2-user1");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_crud_user_list_page_multiple_source)
{
  json_t * j_result;
  int res;
  struct _u_response resp;

  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/user/?offset=3&limit=4", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 4);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "user3");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "username")), "mock1-admin");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 2), "username")), "mock1-user1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 3), "username")), "mock1-user2");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/user/?offset=2&limit=8", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 8);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "user2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "username")), "user3");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 2), "username")), "mock1-admin");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 3), "username")), "mock1-user1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 4), "username")), "mock1-user2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 5), "username")), "mock1-user3");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 6), "username")), "mock2-admin");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 7), "username")), "mock2-user1");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_crud_user_list_delete_user_module_instances)
{
  char * url = msprintf("%s/mod/user/%s", SERVER_URI, MODULE_NAME_1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
  url = msprintf("%s/mod/user/%s", SERVER_URI, MODULE_NAME_2);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd CRUD user");
  tc_core = tcase_create("test_glwd_crud_user");
  tcase_add_test(tc_core, test_glwd_crud_user_get_list);
  tcase_add_test(tc_core, test_glwd_crud_user_add_error_json);
  tcase_add_test(tc_core, test_glwd_crud_user_add_error_param);
  tcase_add_test(tc_core, test_glwd_crud_user_add_OK);
  tcase_add_test(tc_core, test_glwd_crud_user_add_already_present);
  tcase_add_test(tc_core, test_glwd_crud_user_get);
  tcase_add_test(tc_core, test_glwd_crud_user_set_OK);
  tcase_add_test(tc_core, test_glwd_crud_user_delete_error);
  tcase_add_test(tc_core, test_glwd_crud_user_delete_OK);
  tcase_add_test(tc_core, test_glwd_crud_user_list_limit);
  tcase_add_test(tc_core, test_glwd_crud_user_list_pattern);
  tcase_add_test(tc_core, test_glwd_crud_user_list_add_user_module_instances);
  tcase_add_test(tc_core, test_glwd_crud_user_list_page_multiple_source);
  tcase_add_test(tc_core, test_glwd_crud_user_list_pattern_multiple_source);
  tcase_add_test(tc_core, test_glwd_crud_user_list_delete_user_module_instances);
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

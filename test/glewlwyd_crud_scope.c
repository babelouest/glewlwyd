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
#define SCOPE "test-scope"
#define NAME "My New Scope"
#define DESCRIPTION "Description for test-scope"
#define GROUP1 "group1"
#define GROUP1_DESC "Group1 description"
#define GROUP2 "group2"
#define GROUP2_DESC "Group2 description"
#define SCHEME1 "mock_scheme_42"
#define SCHEME2 "mock_scheme_88"
#define SCHEME3 "mock_scheme_95"

struct _u_request admin_req;

START_TEST(test_glwd_crud_scope_get_list)
{
  char * url = msprintf("%s/scope/", SERVER_URI);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_crud_scope_add_error_json)
{
  char * url = msprintf("%s/scope/", SERVER_URI);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, NULL, NULL, 400, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_crud_scope_add_error_param)
{
  char * url = msprintf("%s/scope/", SERVER_URI);
  json_t * j_parameters = json_pack("{ss}", "error", "error");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("[{ss}]", "name", SCOPE);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{si}", "name", 42);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssi}", "name", SCOPE, "display_name", 42);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssi}", "name", SCOPE, "display_name", NAME, "description", 42);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssi}", "name", SCOPE, "display_name", NAME, "description", DESCRIPTION, "password_required", 42);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{ss ss ss so s[]}", "name", SCOPE, "display_name", NAME, "description", DESCRIPTION, "password_required", json_true(), "scheme");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{ss ss ss so s{s{}}}", "name", SCOPE, "display_name", NAME, "description", DESCRIPTION, "password_required", json_true(), "scheme", GROUP1);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{ss ss ss so s{s[]}}", "name", SCOPE, "display_name", NAME, "description", DESCRIPTION, "password_required", json_true(), "scheme", GROUP1);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{ss ss ss so s{s[{ss}]}}", "name", SCOPE, "display_name", NAME, "description", DESCRIPTION, "password_required", json_true(), "scheme", GROUP1, "scheme_name", "error");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  o_free(url);
}
END_TEST

START_TEST(test_glwd_crud_scope_add_OK)
{
  char * url = msprintf("%s/scope/", SERVER_URI);
  json_t * j_parameters = json_pack("{ss ss ss so s{s[{ssssss}]}}", "name", SCOPE, "display_name", NAME, "description", DESCRIPTION, "password_required", json_true(), "scheme", GROUP1, "scheme_name", SCHEME1, "scheme_display_name", "Mock 42", "scheme_type", "mock");
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
  
  url = msprintf("%s/scope/%s", SERVER_URI, SCOPE);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_scope_add_already_present)
{
  char * url = msprintf("%s/scope/", SERVER_URI);
  json_t * j_parameters = json_pack("{ss}", "scope", SCOPE);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_scope_get)
{
  char * url = msprintf("%s/scope/%s", SERVER_URI, SCOPE), * url_404 = msprintf("%s/mod/scope/error", SERVER_URI);
  json_t * j_parameters = json_pack("{ss ss ss so s{s[{ssssss}]}}", "name", SCOPE, "display_name", NAME, "description", DESCRIPTION, "password_required", json_true(), "scheme", GROUP1, "scheme_name", SCHEME1, "scheme_display_name", "Mock 42", "scheme_type", "mock");
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url_404, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
  o_free(url);
  o_free(url_404);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_scope_set_OK)
{
  char * url = msprintf("%s/scope/%s", SERVER_URI, SCOPE);
  json_t * j_parameters = json_pack("{ss ss so s{s[{ss}]s[{ss}{ss}]}}", "display_name", NAME "-new", "description", DESCRIPTION "-new", "password_required", json_false(), "scheme", GROUP1 "-new", "scheme_name", SCHEME1, GROUP2, "scheme_name", SCHEME2, "scheme_name", SCHEME3);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  
  json_object_set_new(j_parameters, "name", json_string(SCOPE));
  json_object_set_new(j_parameters, "scheme", json_pack("{s[{ssssss}]s[{ssssss}{ssssss}]}", GROUP1 "-new", "scheme_name", SCHEME1, "scheme_type", "mock", "scheme_display_name", "Mock 42", GROUP2, "scheme_name", SCHEME2, "scheme_type", "mock", "scheme_display_name", "Mock 88", "scheme_name", SCHEME3, "scheme_type", "mock", "scheme_display_name", "Mock 95"));
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_crud_scope_delete_error)
{
  char * url = msprintf("%s/scope/error", SERVER_URI);

  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_crud_scope_delete_OK)
{
  char * url = msprintf("%s/scope/%s", SERVER_URI, SCOPE);

  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_crud_scope_list_pattern)
{
  json_t * j_result;
  int res;
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/scope/?pattern=scope1", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 1);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "name")), "scope1");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/scope/?limit=2&pattern=scope", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 2);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "name")), "scope1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "name")), "scope2");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/scope/?pattern=error", SERVER_URI);
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
  admin_req.http_url = msprintf("%s/scope/?pattern=scope&limit=2&offset=1", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 2);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "name")), "scope2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "name")), "scope3");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
}
END_TEST

START_TEST(test_glwd_crud_scope_list_limit)
{
  json_t * j_result;
  int res;
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/scope/?offset=1", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 4);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "name")), "g_profile");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "name")), "scope1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 2), "name")), "scope2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 3), "name")), "scope3");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/scope/?limit=2", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 2);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "name")), "g_admin");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "name")), "g_profile");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/scope/?offset=1&limit=1", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 1);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "name")), "g_profile");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
  ulfius_init_response(&resp);
  admin_req.http_url = msprintf("%s/scope/?offset=2&limit=3", SERVER_URI);
  admin_req.http_verb = o_strdup("GET");
  res = ulfius_send_http_request(&admin_req, &resp);
  ck_assert_int_eq(res, U_OK);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_result), 3);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "name")), "scope1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "name")), "scope2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 2), "name")), "scope3");
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = NULL;
  admin_req.http_verb = NULL;
  ulfius_clean_response(&resp);
  json_decref(j_result);
  
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd CRUD user");
  tc_core = tcase_create("test_glwd_crud_scope");
  tcase_add_test(tc_core, test_glwd_crud_scope_get_list);
  tcase_add_test(tc_core, test_glwd_crud_scope_add_error_json);
  tcase_add_test(tc_core, test_glwd_crud_scope_add_error_param);
  tcase_add_test(tc_core, test_glwd_crud_scope_add_OK);
  tcase_add_test(tc_core, test_glwd_crud_scope_add_already_present);
  tcase_add_test(tc_core, test_glwd_crud_scope_get);
  tcase_add_test(tc_core, test_glwd_crud_scope_set_OK);
  tcase_add_test(tc_core, test_glwd_crud_scope_delete_error);
  tcase_add_test(tc_core, test_glwd_crud_scope_delete_OK);
  tcase_add_test(tc_core, test_glwd_crud_scope_list_limit);
  tcase_add_test(tc_core, test_glwd_crud_scope_list_pattern);
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

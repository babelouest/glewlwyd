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
#define PASSWORD "MyAdminPassword2016!"
#define SCOPE_LIST "g_admin"

struct _u_request user_req;

START_TEST(test_glwd_crud_resource_list)
{
  char * url = msprintf("%s/resource/", SERVER_URI);
  json_t * j_resource1 = json_string("resource1");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_resource1, NULL, NULL);
  free(url);
  json_decref(j_resource1);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_resource_get)
{
  char * url = msprintf("%s/resource/resource1", SERVER_URI);
  json_t * j_resource1 = json_string("resource1");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_resource1, NULL, NULL);
  free(url);
  json_decref(j_resource1);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_resource_get_not_found)
{
  char * url = msprintf("%s/resource/not_found", SERVER_URI);
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL);
  free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_resource_add_ok)
{
  json_t * json_body;
  char * url = msprintf("%s/resource/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssssss[ss]}", "description", "New resource description", "name", "new_resource", "uri", "http://new_resource.domain", "scope", "scope1", "scope2");
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_resource_add_invalid)
{
  json_t * json_body;
  char * url = msprintf("%s/resource/", SERVER_URI);
  int res;
  
  json_body = json_pack("{si}", "description", 22);
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 400, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_resource_get_new)
{
  char * url = msprintf("%s/resource/new_resource", SERVER_URI);
  json_t * j_new_resource = json_string("New resource description");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_resource, NULL, NULL);
  free(url);
  json_decref(j_new_resource);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_resource_set_new)
{
  char * url = msprintf("%s/resource/new_resource", SERVER_URI);
  json_t * json_body = json_pack("{sssss[ss]}", "description", "New new resource description", "uri", "http://new_resource.domain", "scope", "scope1", "scope2");
  
  int res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  free(url);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_resource_get_new_updated)
{
  char * url = msprintf("%s/resource/new_resource", SERVER_URI);
  json_t * j_new_resource = json_string("New new resource description");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_resource, NULL, NULL);
  free(url);
  json_decref(j_new_resource);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_resource_delete_new)
{
  char * url = msprintf("%s/resource/new_resource", SERVER_URI);
  
  int res = run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd resource CRUD");
  tc_core = tcase_create("test_glwd_crud_resource");
  tcase_add_test(tc_core, test_glwd_crud_resource_list);
  tcase_add_test(tc_core, test_glwd_crud_resource_get);
  tcase_add_test(tc_core, test_glwd_crud_resource_get_not_found);
  tcase_add_test(tc_core, test_glwd_crud_resource_add_ok);
  tcase_add_test(tc_core, test_glwd_crud_resource_add_invalid);
  tcase_add_test(tc_core, test_glwd_crud_resource_get_new);
  tcase_add_test(tc_core, test_glwd_crud_resource_set_new);
  tcase_add_test(tc_core, test_glwd_crud_resource_get_new_updated);
  tcase_add_test(tc_core, test_glwd_crud_resource_delete_new);
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
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/token/", SERVER_URI);
  u_map_put(auth_req.map_post_body, "grant_type", "password");
  u_map_put(auth_req.map_post_body, "username", USERNAME);
  u_map_put(auth_req.map_post_body, "password", PASSWORD);
  u_map_put(auth_req.map_post_body, "scope", SCOPE_LIST);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK) {
    json_t * json_body = ulfius_get_json_body_response(&auth_resp, NULL);
    char * bearer_token = msprintf("Bearer %s", (json_string_value(json_object_get(json_body, "access_token"))));
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);
    u_map_put(user_req.map_header, "Authorization", bearer_token);
    free(bearer_token);
    json_decref(json_body);
    do_test = 1;
  }
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
  
  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  ulfius_clean_request(&user_req);
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

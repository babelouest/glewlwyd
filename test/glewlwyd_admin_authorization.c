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

START_TEST(test_glwd_admin_authorization_list)
{
  char * url = msprintf("%s/authorization/", SERVER_URI);
  json_t * j_authorization_code = json_string("authorization_code");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_authorization_code, NULL, NULL);
  free(url);
  json_decref(j_authorization_code);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_admin_authorization_authorization_code)
{
  char * url = msprintf("%s/authorization/authorization_code", SERVER_URI);
  json_t * j_authorization_code = json_string("authorization_code");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_authorization_code, NULL, NULL);
  free(url);
  json_decref(j_authorization_code);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_admin_authorization_not_found)
{
  char * url = msprintf("%s/authorization/not_found", SERVER_URI);
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL);
  free(url);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_admin_authorization_update_authorization_code_ok)
{
  json_t * res_body, * json_body;
  char * url = msprintf("%s/authorization/authorization_code", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssb}", "description", "updated description", "enabled", 0);
  res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  json_decref(json_body);
	ck_assert_int_eq(res, 1);
  
  res_body = json_string("updated description");
  res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, res_body, NULL, NULL);
  json_decref(res_body);
	ck_assert_int_eq(res, 1);
  
  json_body = json_pack("{sssb}", "description", "Authorization Code Grant - Access token: https://tools.ietf.org/html/rfc6749#section-4.1", "enabled", 1);
  res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  json_decref(json_body);
	ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_admin_authorization_update_authorization_code_invalid)
{
  json_t * json_body;
  char * url = msprintf("%s/authorization/authorization_code", SERVER_URI);
  int res;
  
  json_body = json_pack("{siss}", "description", 1, "enabled", "invalid");
  res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 400, NULL, NULL, NULL);
  json_decref(json_body);
	ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Glewlwyd admin authorization");
	tc_core = tcase_create("test_glwd_admin_authorization");
	tcase_add_test(tc_core, test_glwd_admin_authorization_list);
	tcase_add_test(tc_core, test_glwd_admin_authorization_authorization_code);
	tcase_add_test(tc_core, test_glwd_admin_authorization_not_found);
	tcase_add_test(tc_core, test_glwd_admin_authorization_update_authorization_code_ok);
	tcase_add_test(tc_core, test_glwd_admin_authorization_update_authorization_code_invalid);
	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req;
  struct _u_response auth_resp;
  int res;
  
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
  }
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
  
  s = glewlwyd_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  ulfius_clean_request(&user_req);
  
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

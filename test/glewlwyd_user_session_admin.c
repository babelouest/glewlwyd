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
#define ADMIN_LOGIN "admin"
#define ADMIN_PASSWORD "MyAdminPassword2016!"
#define ADMIN_SCOPE_LIST "g_admin"
#define USER_LOGIN "user1"
#define USER_PASSWORD "MyUser1Password!"

struct _u_request admin_req;

START_TEST(test_glwd_user_session_list_all_admin)
{
  char * url = msprintf("%s/user/%s/session", SERVER_URI, USER_LOGIN);
  
  int res = run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_user_session_list_enabled_admin)
{
  char * url = msprintf("%s/user/%s/session?valid=true", SERVER_URI, USER_LOGIN);
  
  int res = run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_user_session_revoke_not_found_admin)
{
  char * url = msprintf("%s/user/%s/session/", SERVER_URI, USER_LOGIN);
  json_t * json_body = json_pack("{ss}", "session_hash", "not_found");
  
  ulfius_set_json_body_request(&admin_req, json_body);
  int res = run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL);
  free(url);
  json_decref(json_body);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_user_session_revoke_ok_admin)
{
  char * url;
  struct _u_response list_resp;
  int res;
  struct _u_map body;
  json_t * json_resp_body;
  
  u_map_init(&body);
  ulfius_init_response(&list_resp);
  admin_req.http_url = msprintf("%s/user/%s/session/?valid=true", SERVER_URI, USER_LOGIN);
  res = ulfius_send_http_request(&admin_req, &list_resp);
  if (res == U_OK) {
    json_resp_body = ulfius_get_json_body_response(&list_resp, NULL);
    json_t * json_body = json_pack("{ss}", "session_hash", json_string_value(json_object_get(json_array_get(json_resp_body, 0), "session_hash")));
    u_map_put(admin_req.map_header, "Content-Type", "application/x-www-form-urlencoded");
    ulfius_set_json_body_request(&admin_req, json_body);
    json_decref(json_body);
    json_decref(json_resp_body);
  }
  
  url = msprintf("%s/user/%s/session/", SERVER_URI, USER_LOGIN);
  res = run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, &body, 200, NULL, NULL, NULL);
  free(url);
  u_map_clean(&body);
  ulfius_clean_response(&list_resp);
	ck_assert_int_eq(res, 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Glewlwyd user session management admin");
	tc_core = tcase_create("test_glwd_user_session");
	tcase_add_test(tc_core, test_glwd_user_session_list_all_admin);
	tcase_add_test(tc_core, test_glwd_user_session_list_enabled_admin);
	tcase_add_test(tc_core, test_glwd_user_session_revoke_not_found_admin);
	tcase_add_test(tc_core, test_glwd_user_session_revoke_ok_admin);
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
  
  // Set at least one session
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", USER_LOGIN);
  u_map_put(auth_req.map_post_body, "password", USER_PASSWORD);
  ulfius_send_http_request(&auth_req, &auth_resp);
  if (auth_resp.status == 200) {
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USER_LOGIN);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "User %s error", USER_LOGIN);
  }

  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&admin_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/token/", SERVER_URI);
  u_map_put(auth_req.map_post_body, "grant_type", "password");
  u_map_put(auth_req.map_post_body, "username", ADMIN_LOGIN);
  u_map_put(auth_req.map_post_body, "password", ADMIN_PASSWORD);
  u_map_put(auth_req.map_post_body, "scope", ADMIN_SCOPE_LIST);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK) {
    json_t * json_body = ulfius_get_json_body_response(&auth_resp, NULL);
    char * bearer_token = msprintf("Bearer %s", (json_string_value(json_object_get(json_body, "access_token"))));
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", ADMIN_LOGIN);
    u_map_put(admin_req.map_header, "Authorization", bearer_token);
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
  
  ulfius_clean_request(&admin_req);
  
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

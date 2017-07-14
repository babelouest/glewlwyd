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
#define USER_LOGIN "user1"
#define USER_PASSWORD "MyUser1Password!"
#define USER_SCOPE_LIST "scope1 g_profile"

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_glwd_user_refresh_token_list_all_user)
{
  char * url = msprintf("%s/profile/refresh_token", SERVER_URI);
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_user_refresh_token_list_enabled_user)
{
  char * url = msprintf("%s/profile/refresh_token?valid=true", SERVER_URI);
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_user_refresh_token_revoke_not_found_user)
{
  char * url = msprintf("%s/profile/refresh_token", SERVER_URI);
  
  json_t * json_body = json_pack("{ss}", "token_hash", "not_found");
  ulfius_set_json_body_request(&user_req, json_body);
  int res = run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL);
  free(url);
  json_decref(json_body);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_user_refresh_token_revoke_ok_user)
{
  struct _u_response list_resp, del_resp;
  int res;
  json_t * json_body, * json_resp_body;
  
  ulfius_init_response(&list_resp);
  ulfius_init_response(&del_resp);
  user_req.http_url = msprintf("%s/profile/refresh_token/?valid=true", SERVER_URI);
  res = ulfius_send_http_request(&user_req, &list_resp);
  if (res == U_OK) {
    json_resp_body = ulfius_get_json_body_response(&list_resp, NULL);
    json_body = json_pack("{ss}", "token_hash", json_string_value(json_object_get(json_array_get(json_resp_body, 0), "token_hash")));
    u_map_put(user_req.map_header, "Content-Type", "application/x-www-form-urlencoded");
    ulfius_set_json_body_request(&user_req, json_body);
    json_decref(json_body);
    json_decref(json_resp_body);
  }
  
  user_req.http_url = msprintf("%s/profile/refresh_token/", SERVER_URI);
  user_req.http_verb = strdup("DELETE");
  ulfius_send_http_request(&user_req, &del_resp);
	ck_assert_int_eq(del_resp.status, 200);
  
  ulfius_clean_response(&list_resp);
  ulfius_clean_response(&del_resp);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Glewlwyd user refresh_token management user");
	tc_core = tcase_create("test_glwd_user_refresh_token");
	tcase_add_test(tc_core, test_glwd_user_refresh_token_list_all_user);
	tcase_add_test(tc_core, test_glwd_user_refresh_token_list_enabled_user);
	tcase_add_test(tc_core, test_glwd_user_refresh_token_revoke_not_found_user);
	tcase_add_test(tc_core, test_glwd_user_refresh_token_revoke_ok_user);
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
  int res, i;
  char * cookie;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a refresh_token
  ulfius_init_request(&auth_req);
  ulfius_init_request(&admin_req);
  ulfius_init_request(&user_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/token/", SERVER_URI);
  u_map_put(auth_req.map_post_body, "grant_type", "password");
  u_map_put(auth_req.map_post_body, "username", USER_LOGIN);
  u_map_put(auth_req.map_post_body, "password", USER_PASSWORD);
  u_map_put(auth_req.map_post_body, "scope", USER_SCOPE_LIST);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK) {
    json_t * json_body = ulfius_get_json_body_response(&auth_resp, NULL);
    char * bearer_token = msprintf("Bearer %s", (json_string_value(json_object_get(json_body, "access_token"))));
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USER_LOGIN);
    u_map_put(user_req.map_header, "Authorization", bearer_token);
    free(bearer_token);
    json_decref(json_body);
  }
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", USER_LOGIN);
  u_map_put(auth_req.map_post_body, "password", USER_PASSWORD);
  ulfius_send_http_request(&auth_req, &auth_resp);
  ulfius_send_http_request(&auth_req, &auth_resp);
  if (auth_resp.status == 200) {
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USER_LOGIN);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "User %s error", USER_LOGIN);
  }
  for (i=0; i<auth_resp.nb_cookies; i++) {
    cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
    u_map_put(user_req.map_header, "Cookie", cookie);
  }
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);

  s = glewlwyd_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

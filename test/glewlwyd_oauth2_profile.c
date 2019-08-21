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
#define USERNAME "user1"
#define PASSWORD "password"
#define SCOPE_LIST "g_profile"

char * bearer_token;

START_TEST(test_oauth2_profile_no_token)
{
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/glwd/profile", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oauth2_profile_token_invalid)
{
  struct _u_request user_req;
  char * invalid_token = o_strndup(bearer_token, o_strlen(bearer_token)-2);
  
  ulfius_init_request(&user_req);
  u_map_put(user_req.map_header, "Authorization", invalid_token);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/glwd/profile", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  o_free(invalid_token);
  ulfius_clean_request(&user_req);
}
END_TEST

START_TEST(test_oauth2_profile_ok)
{
  struct _u_request user_req;
  json_t * j_body = json_pack("{ss}", "username", USERNAME);
  
  ulfius_init_request(&user_req);
  u_map_put(user_req.map_header, "Authorization", bearer_token);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/glwd/profile", NULL, NULL, NULL, NULL, 200, j_body, NULL, NULL), 1);
  json_decref(j_body);
  ulfius_clean_request(&user_req);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oauth2 profile");
  tc_core = tcase_create("test_oauth2_profile");
  tcase_add_test(tc_core, test_oauth2_profile_no_token);
  tcase_add_test(tc_core, test_oauth2_profile_token_invalid);
  tcase_add_test(tc_core, test_oauth2_profile_ok);
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
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/glwd/token/", SERVER_URI);
  u_map_put(auth_req.map_post_body, "grant_type", "password");
  u_map_put(auth_req.map_post_body, "username", USERNAME);
  u_map_put(auth_req.map_post_body, "password", PASSWORD);
  u_map_put(auth_req.map_post_body, "scope", SCOPE_LIST);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    json_t * json_body = ulfius_get_json_body_response(&auth_resp, NULL);
    bearer_token = msprintf("Bearer %s", json_string_value(json_object_get(json_body, "access_token")));
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);
    json_decref(json_body);
  }
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
  
  s = glewlwyd_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  o_free(bearer_token);
  
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

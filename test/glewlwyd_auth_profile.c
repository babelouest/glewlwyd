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

#define SERVER_URI "http://localhost:4593/api/"
#define USERNAME "user1"
#define PASSWORD "password"
#define NAME "Dave Lopper1"
#define EMAIL "user1@glewlwyd"

struct _u_request user_req;

START_TEST(test_glwd_auth_profile_get_error)
{
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "profile_list/", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_auth_profile_get)
{
  json_t * j_result = json_string(USERNAME);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "profile_list/", NULL, NULL, NULL, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_auth_update_error)
{
  json_t * j_profile = json_pack("[{ss}]", "name", NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "profile/", NULL, NULL, j_profile, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_profile);
}
END_TEST

START_TEST(test_glwd_auth_update_ok)
{
  json_t * j_profile = json_pack("{ssss}", "name", NAME "-new", "email", EMAIL "-new");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "profile/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  j_profile = json_pack("{ssssss}", "username", USERNAME, "name", NAME "-new", "email", EMAIL "-new");
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "profile_list/", NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd auth profile");
  tc_core = tcase_create("test_glwd_auth_profile");
  tcase_add_test(tc_core, test_glwd_auth_profile_get_error);
  tcase_add_test(tc_core, test_glwd_auth_profile_get);
  tcase_add_test(tc_core, test_glwd_auth_update_error);
  tcase_add_test(tc_core, test_glwd_auth_update_ok);
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
  json_t * j_body;
  int res, do_test = 0, i;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200 && auth_resp.nb_cookies) {
    for (i=0; i<auth_resp.nb_cookies; i++) {
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(user_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    do_test = 1;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
  }
  ulfius_clean_response(&auth_resp);

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&user_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

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
#define SCOPE_LIST "g_admin"
#define USERNAME_IMPERSONATE "user1"
#define NAME "Dave Lopper1"
#define EMAIL "user1@glewlwyd"
#define PROFILE_PASSWORD "password"
#define PROFILE_NEW_PASSWORD "newpassword"

struct _u_request admin_req;

START_TEST(test_glwd_auth_profile_impersonate_get_scheme_available_error_auth)
{
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/delegate/" USERNAME_IMPERSONATE "/profile/scheme/", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_auth_profile_impersonate_update_ok)
{
  json_t * j_profile = json_pack("{ssss}", "name", NAME "-new", "email", EMAIL "-new");
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/delegate/" USERNAME_IMPERSONATE "/profile", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  j_profile = json_pack("{ssssss}", "username", USERNAME_IMPERSONATE, "name", NAME "-new", "email", EMAIL "-new");
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" USERNAME_IMPERSONATE, NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
}
END_TEST

START_TEST(test_glwd_auth_profile_impersonate_profile_get_scheme_available_success)
{
  json_t * j_expected = json_pack("{ssssss}", "module", "mock", "name", "mock_scheme_42", "display_name", "Mock 42");
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/delegate/" USERNAME_IMPERSONATE "/profile/scheme", NULL, NULL, NULL, NULL, 200, j_expected, NULL, NULL), 1);
  json_decref(j_expected);
}
END_TEST

START_TEST(test_glwd_auth_profile_admin_profile_get_scheme_available_empty_success)
{
  json_t * j_response;
  struct _u_request req;
  struct _u_response resp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  
  ck_assert_int_eq(ulfius_copy_request(&req, &admin_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET", U_OPT_HTTP_URL, SERVER_URI "/delegate/" USERNAME_IMPERSONATE "/profile/scheme", U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_response = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_int_eq(3, json_array_size(j_response));
  
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_glwd_auth_profile_impersonate_session_manage_list)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/delegate/" USERNAME_IMPERSONATE "/profile/session", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd auth profile impersonate");
  tc_core = tcase_create("test_glwd_auth_profile_impersonate");
  tcase_add_test(tc_core, test_glwd_auth_profile_impersonate_get_scheme_available_error_auth);
  tcase_add_test(tc_core, test_glwd_auth_profile_impersonate_update_ok);
  tcase_add_test(tc_core, test_glwd_auth_profile_impersonate_profile_get_scheme_available_success);
  tcase_add_test(tc_core, test_glwd_auth_profile_admin_profile_get_scheme_available_empty_success);
  tcase_add_test(tc_core, test_glwd_auth_profile_impersonate_session_manage_list);
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

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
#define SCOPE_LIST "scope1 scope2"
#define CLIENT "client1_id"

struct _u_request user_req;

START_TEST(test_glwd_auth_grant_error_parameters)
{
  struct _u_response resp;
  json_t * j_body = NULL;

  ulfius_init_response(&resp);

  user_req.http_verb = strdup("PUT");
  user_req.http_url = msprintf("%s/auth/grant/error", SERVER_URI);

  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ulfius_set_json_body_request(&user_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 404);
  ck_assert_int_eq(resp.nb_cookies, 0);
  ulfius_clean_response(&resp);
  
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);

  ulfius_init_response(&resp);
  j_body = json_pack("{s[]}", "scope");
  ulfius_set_json_body_request(&user_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_int_eq(resp.nb_cookies, 0);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  j_body = json_pack("{ss}", "scope", "error");
  ulfius_set_json_body_request(&user_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ck_assert_int_eq(resp.nb_cookies, 0);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_glwd_auth_grant_success)
{
  struct _u_response resp;
  json_t * j_body = NULL;

  ulfius_init_response(&resp);
  
  user_req.http_verb = strdup("PUT");
  user_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);

  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ulfius_set_json_body_request(&user_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 0);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_glwd_auth_grant_remove_success)
{
  struct _u_response resp;
  json_t * j_body = NULL;

  ulfius_init_response(&resp);
  
  user_req.http_verb = strdup("PUT");
  user_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);

  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&user_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 0);
  ulfius_clean_response(&resp);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd auth grant");
  tc_core = tcase_create("test_glwd_auth_grant");
  tcase_add_test(tc_core, test_glwd_auth_grant_error_parameters);
  tcase_add_test(tc_core, test_glwd_auth_grant_success);
  tcase_add_test(tc_core, test_glwd_auth_grant_remove_success);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req, scope_req;
  struct _u_response auth_resp, scope_resp;
  json_t * j_body;
  int res, do_test = 0, i;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
  ulfius_init_request(&scope_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_response(&scope_resp);
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

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&scope_req);
  ulfius_clean_response(&auth_resp);
  ulfius_clean_response(&scope_resp);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

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
#define USERNAME2 "user2"
#define PASSWORD "password"

START_TEST(test_glwd_auth_password_error_parameters)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body = NULL;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);

  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);

  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_int_eq(resp.nb_cookies, 0);

  j_body = json_pack("{}");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_int_eq(resp.nb_cookies, 0);

  j_body = json_pack("{ss}", "username", USERNAME);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ck_assert_int_eq(resp.nb_cookies, 0);

  j_body = json_pack("{ss}", "username", "");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_int_eq(resp.nb_cookies, 0);

  j_body = json_pack("{ss}", "password", PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_int_eq(resp.nb_cookies, 0);

  j_body = json_pack("{sisi}", "username", 42, "password", 84);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_int_eq(resp.nb_cookies, 0);

  j_body = json_pack("{ssss}", "username", "", "password", "");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_int_eq(resp.nb_cookies, 0);
}
END_TEST

START_TEST(test_glwd_auth_password_error_login)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body = NULL;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);

  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);

  j_body = json_pack("{ssss}", "username", USERNAME, "password", "error");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ck_assert_int_eq(resp.nb_cookies, 0);

  j_body = json_pack("{ssss}", "username", "error", "password", PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ck_assert_int_eq(resp.nb_cookies, 0);

  j_body = json_pack("{ssss}", "username", "error", "password", "error");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ck_assert_int_eq(resp.nb_cookies, 0);
}
END_TEST

START_TEST(test_glwd_auth_password_login_success)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body = NULL;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);

  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);

  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);
}
END_TEST

START_TEST(test_glwd_auth_password_login_multiple)
{
  struct _u_request req, auth_req;
  struct _u_response resp, auth_resp;
  json_t * j_body = NULL;
  char * cookie;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);

  auth_req.http_url = msprintf("%s/profile/", SERVER_URI);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 401);
  ulfius_clean_response(&auth_resp);

  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);

  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);

  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  u_map_put(req.map_header, "Cookie", cookie);
  u_map_put(auth_req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_response(&resp);

  ulfius_init_response(&auth_resp);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  j_body = ulfius_get_json_body_response(&auth_resp, NULL);
  ck_assert_int_eq(json_array_size(j_body), 1);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_body, 0), "username")), USERNAME);
  json_decref(j_body);
  ulfius_clean_response(&auth_resp);

  ulfius_init_response(&resp);
  j_body = json_pack("{ssss}", "username", USERNAME2, "password", PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);
  ulfius_clean_response(&resp);
  
  sleep(2);
  ulfius_init_response(&auth_resp);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  j_body = ulfius_get_json_body_response(&auth_resp, NULL);
  ck_assert_int_eq(json_array_size(j_body), 2);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_body, 0), "username")), USERNAME2);
  json_decref(j_body);
  ulfius_clean_response(&auth_resp);
}
END_TEST

START_TEST(test_glwd_auth_password_login_multiple_toggle_current_user)
{
  struct _u_request req, auth_req;
  struct _u_response resp, auth_resp;
  json_t * j_body = NULL;
  char * cookie;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_init_request(&auth_req);

  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);

  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);

  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  u_map_put(req.map_header, "Cookie", cookie);
  u_map_put(auth_req.map_header, "Cookie", cookie);
  o_free(cookie);

  j_body = json_pack("{ssss}", "username", USERNAME2, "password", PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);

  ulfius_init_response(&auth_resp);
  auth_req.http_url = msprintf("%s/profile/", SERVER_URI);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  j_body = ulfius_get_json_body_response(&auth_resp, NULL);
  ck_assert_int_eq(json_array_size(j_body), 2);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_body, 0), "username")), USERNAME2);
  json_decref(j_body);
  ulfius_clean_response(&auth_resp);

  sleep(1);
  j_body = json_pack("{ss}", "username", USERNAME);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);

  ulfius_init_response(&auth_resp);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  j_body = ulfius_get_json_body_response(&auth_resp, NULL);
  ck_assert_int_eq(json_array_size(j_body), 2);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_body, 0), "username")), USERNAME);
  json_decref(j_body);
  ulfius_clean_response(&auth_resp);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd delete token");
  tc_core = tcase_create("test_glwd_auth_password");
  tcase_add_test(tc_core, test_glwd_auth_password_error_parameters);
  tcase_add_test(tc_core, test_glwd_auth_password_error_login);
  tcase_add_test(tc_core, test_glwd_auth_password_login_success);
  tcase_add_test(tc_core, test_glwd_auth_password_login_multiple);
  tcase_add_test(tc_core, test_glwd_auth_password_login_multiple_toggle_current_user);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  s = glewlwyd_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

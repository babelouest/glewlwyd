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
#define USERNAME_ADMIN "admin"
#define PASSWORD "password"
#define PASSWORD_ADMIN "password"
#define SCOPE_MAX_AGE "g_profile"

struct _u_request admin_req;

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
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  j_body = json_pack("{}");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_int_eq(resp.nb_cookies, 0);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  j_body = json_pack("{ss}", "username", USERNAME);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ck_assert_int_eq(resp.nb_cookies, 0);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  j_body = json_pack("{ss}", "username", "");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_int_eq(resp.nb_cookies, 0);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  j_body = json_pack("{ss}", "password", PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_int_eq(resp.nb_cookies, 0);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  j_body = json_pack("{sisi}", "username", 42, "password", 84);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_int_eq(resp.nb_cookies, 0);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  j_body = json_pack("{ssss}", "username", "", "password", "");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_int_eq(resp.nb_cookies, 0);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
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

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
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

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
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

  auth_req.http_url = msprintf("%s/profile_list/", SERVER_URI);
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
  
  ulfius_clean_request(&req);
  ulfius_clean_request(&auth_req);
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
  auth_req.http_url = msprintf("%s/profile_list/", SERVER_URI);
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
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&auth_req);
}
END_TEST

START_TEST(test_glwd_auth_password_max_age_scope_set_OK)
{
  char * url = msprintf("%s/scope/%s", SERVER_URI, SCOPE_MAX_AGE);
  json_t * j_parameters = json_pack("{ss ss ss so si}", "name", SCOPE_MAX_AGE, "display_name", "Glewlwyd profile", "description", "Access to the user's profile API", "password_required", json_true(), "password_max_age", 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
  
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_auth_password_max_age)
{
  struct _u_request req, scope_req;
  struct _u_response resp, scope_resp;
  json_t * j_body = NULL;
  char * cookie;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_init_request(&scope_req);
  ulfius_init_response(&scope_resp);

  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);

  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);

  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  u_map_put(scope_req.map_header, "Cookie", cookie);
  o_free(cookie);

  // First check for scope 3, password_authenticated should be true
  scope_req.http_verb = strdup("GET");
  scope_req.http_url = msprintf("%s/auth/scheme/?scope=%s", SERVER_URI, SCOPE_MAX_AGE);
  ck_assert_int_eq(ulfius_send_http_request(&scope_req, &scope_resp), U_OK);
  ck_assert_int_eq(scope_resp.status, 200);
  ck_assert_ptr_ne(j_body = ulfius_get_json_body_response(&scope_resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(json_object_get(j_body, SCOPE_MAX_AGE), "password_authenticated"), json_true());
  json_decref(j_body);
  ulfius_clean_response(&scope_resp);
  
  sleep(2);
  
  // Second check for scope 3, password_authenticated should be false
  ulfius_init_response(&scope_resp);
  ck_assert_int_eq(ulfius_send_http_request(&scope_req, &scope_resp), U_OK);
  ck_assert_int_eq(scope_resp.status, 200);
  ck_assert_ptr_ne(j_body = ulfius_get_json_body_response(&scope_resp, NULL), NULL);
  ck_assert_ptr_eq(json_object_get(json_object_get(j_body, SCOPE_MAX_AGE), "password_authenticated"), json_false());
  json_decref(j_body);
  ulfius_clean_response(&scope_resp);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&scope_req);
}
END_TEST

START_TEST(test_glwd_auth_password_max_age_scope_reset_OK)
{
  char * url = msprintf("%s/scope/%s", SERVER_URI, SCOPE_MAX_AGE);
  json_t * j_parameters = json_pack("{ss ss ss so si}", "name", SCOPE_MAX_AGE, "display_name", "Glewlwyd profile", "description", "Access to the user's profile API", "password_required", json_true(), "password_max_age", 600);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
  
  json_decref(j_parameters);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd auth password");
  tc_core = tcase_create("test_glwd_auth_password");
  tcase_add_test(tc_core, test_glwd_auth_password_error_parameters);
  tcase_add_test(tc_core, test_glwd_auth_password_error_login);
  tcase_add_test(tc_core, test_glwd_auth_password_login_success);
  tcase_add_test(tc_core, test_glwd_auth_password_login_multiple);
  tcase_add_test(tc_core, test_glwd_auth_password_login_multiple_toggle_current_user);
  tcase_add_test(tc_core, test_glwd_auth_password_max_age_scope_set_OK);
  tcase_add_test(tc_core, test_glwd_auth_password_max_age);
  tcase_add_test(tc_core, test_glwd_auth_password_max_age_scope_reset_OK);
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
  int res, do_test = 0, i;
  json_t * j_body;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  ulfius_init_request(&auth_req);
  ulfius_init_request(&admin_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME_ADMIN, "password", PASSWORD_ADMIN);
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

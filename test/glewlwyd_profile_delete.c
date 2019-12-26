/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>


#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define USERNAME "admin"
#define PASSWORD "password"

#define NEW_USERNAME "semias"
#define NEW_NAME "Semias from somewhere"
#define NEW_PASSWORD "password"
#define NEW_EMAIL "esras@glewlwyd.tld"
#define NEW_SCOPE "g_profile"
#define SCHEME_TYPE "mock"
#define SCHEME_NAME_42 "mock_scheme_42"
#define SCHEME_NAME_88 "mock_scheme_88"
#define SCHEME_NAME_95 "mock_scheme_95"
#define SCHEME_VALUE_42 "42"

struct _u_request admin_req;

START_TEST(test_glwd_profile_delete_add_user)
{
  json_t * j_parameters = json_pack("{sssssssos[s]}", "username", NEW_USERNAME, "name", NEW_NAME, "email", NEW_EMAIL, "enabled", json_true(), "scope", NEW_SCOPE);
  ck_assert_ptr_ne(j_parameters, NULL);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_profile_delete_delete_user)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_profile_delete_register_schemes)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  char * cookie;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", NEW_USERNAME, "password", NEW_PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_gt(resp.nb_cookies, 0);
  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  ck_assert_ptr_ne(cookie, NULL);
  ck_assert_int_eq(u_map_put(req.map_header, "Cookie", cookie), U_OK);
  o_free(cookie);
  ulfius_clean_response(&resp);
  
  j_body = json_pack("{ssssss}", "username", NEW_USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME_42);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{sssssss{so}}", "username", NEW_USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME_42, "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{ssssss}", "username", NEW_USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME_42);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{ssssss}", "username", NEW_USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME_88);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{sssssss{so}}", "username", NEW_USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME_88, "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{ssssss}", "username", NEW_USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME_88);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{ssssss}", "username", NEW_USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME_95);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{sssssss{so}}", "username", NEW_USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME_95, "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{ssssss}", "username", NEW_USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME_95);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_profile_delete_delete_profile_unavailable)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  char * cookie;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", NEW_USERNAME, "password", NEW_PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_gt(resp.nb_cookies, 0);
  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  ck_assert_ptr_ne(cookie, NULL);
  ck_assert_int_eq(u_map_put(req.map_header, "Cookie", cookie), U_OK);
  o_free(cookie);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(run_simple_test(&req, "DELETE", SERVER_URI "/profile/", NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_profile_delete_delete_profile_delete)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  char * cookie;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", NEW_USERNAME, "password", NEW_PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_gt(resp.nb_cookies, 0);
  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  ck_assert_ptr_ne(cookie, NULL);
  ck_assert_int_eq(u_map_put(req.map_header, "Cookie", cookie), U_OK);
  o_free(cookie);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(run_simple_test(&req, "DELETE", SERVER_URI "/profile/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&req, "GET", SERVER_URI "/profile_list/", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  ulfius_clean_request(&req);

  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_profile_delete_delete_profile_disable)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  char * cookie;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", NEW_USERNAME, "password", NEW_PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_gt(resp.nb_cookies, 0);
  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  ck_assert_ptr_ne(cookie, NULL);
  ck_assert_int_eq(u_map_put(req.map_header, "Cookie", cookie), U_OK);
  o_free(cookie);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(run_simple_test(&req, "DELETE", SERVER_URI "/profile/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&req, "GET", SERVER_URI "/profile_list/", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  ulfius_clean_request(&req);

  j_body = json_pack("{sssssssos[s]}", "username", NEW_USERNAME, "name", NEW_NAME, "email", NEW_EMAIL, "enabled", json_false(), "scope", NEW_SCOPE);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, NULL, NULL, 200, j_body, NULL, NULL), 1);
  json_decref(j_body);
}
END_TEST

START_TEST(test_glwd_profile_delete_auth_unavailable)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", NEW_USERNAME, "password", NEW_PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ck_assert_int_eq(resp.nb_cookies, 0);

  j_body = json_pack("{sssssss{ss}}", "username", NEW_USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME_42, "value", "code", SCHEME_VALUE_42);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ck_assert_int_eq(resp.nb_cookies, 0);

  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
}
END_TEST

static Suite *glewlwyd_suite_no(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd profile delete - no");
  tc_core = tcase_create("test_glwd_profile_delete_no");
  tcase_add_test(tc_core, test_glwd_profile_delete_add_user);
  tcase_add_test(tc_core, test_glwd_profile_delete_register_schemes);
  tcase_add_test(tc_core, test_glwd_profile_delete_delete_profile_unavailable);
  tcase_add_test(tc_core, test_glwd_profile_delete_delete_user);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

static Suite *glewlwyd_suite_delete(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd profile delete - delete");
  tc_core = tcase_create("test_glwd_profile_delete_delete");
  tcase_add_test(tc_core, test_glwd_profile_delete_add_user);
  tcase_add_test(tc_core, test_glwd_profile_delete_register_schemes);
  tcase_add_test(tc_core, test_glwd_profile_delete_delete_profile_delete);
  tcase_add_test(tc_core, test_glwd_profile_delete_auth_unavailable);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

static Suite *glewlwyd_suite_disable(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd profile delete - disable");
  tc_core = tcase_create("test_glwd_profile_delete_disable");
  tcase_add_test(tc_core, test_glwd_profile_delete_add_user);
  tcase_add_test(tc_core, test_glwd_profile_delete_register_schemes);
  tcase_add_test(tc_core, test_glwd_profile_delete_delete_profile_disable);
  tcase_add_test(tc_core, test_glwd_profile_delete_auth_unavailable);
  tcase_add_test(tc_core, test_glwd_profile_delete_delete_user);
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
    if (argc > 1 && 0 == o_strcmp("delete", argv[1])) {
      s = glewlwyd_suite_delete();
    } else if (argc > 1 && 0 == o_strcmp("disable", argv[1])) {
      s = glewlwyd_suite_disable();
    } else {
      s = glewlwyd_suite_no();
    }
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  ulfius_clean_request(&admin_req);
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

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
#define USER_LOGIN "new_user"
#define USER_PASSWORD "password"
#define USER_PASSWORD_UPDATED "password_updated"
#define USER_PASSWORD_RESET "password_reset"
#define USER_EMAIL "user@glewlwyd.domain"
#define SCOPE_LIST "g_admin"

struct _u_request admin_req;
struct _u_request user_req;
char token[129] = {0}, * cookie;

START_TEST(test_glwd_update_user_profile_add_user_database)
{
  json_t * json_body;
  char * url = msprintf("%s/user/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssssssssss[ss]}", "source", "database", "login", USER_LOGIN, "name", "New User", "password", USER_PASSWORD, "email", USER_EMAIL, "scope", "scope1", "scope2");
  res = run_simple_test(&admin_req, "POST", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_update_user_profile_add_user_ldap)
{
  json_t * json_body;
  char * url = msprintf("%s/user/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssssssssss[ss]}", "source", "ldap", "login", USER_LOGIN, "name", "New User", "password", USER_PASSWORD, "email", USER_EMAIL, "scope", "scope1", "scope2");
  res = run_simple_test(&admin_req, "POST", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_update_user_connect_user_success)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", USER_LOGIN);
  u_map_put(auth_req.map_post_body, "password", USER_PASSWORD);
  ulfius_send_http_request(&auth_req, &auth_resp);
  ck_assert_int_eq(auth_resp.status, 200);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST
  
START_TEST(test_glwd_update_user_profile_update_fail)
{
  json_t * json_body = json_pack("{si}", "name", 1);
  char * url = msprintf("%s/profile/", SERVER_URI);
  int res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 400, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
}
END_TEST
  
START_TEST(test_glwd_update_user_profile_update_success)
{
  json_t * json_body = json_pack("{ss}", "name", "new new user");
  char * url = msprintf("%s/profile/", SERVER_URI);
  int res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
}
END_TEST
  
START_TEST(test_glwd_update_user_profile_update_password_success)
{
  json_t * json_body = json_pack("{ssss}", "old_password", USER_PASSWORD, "new_password", USER_PASSWORD_UPDATED);
  char * url = msprintf("%s/profile/", SERVER_URI);
  int res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
}
END_TEST
  
START_TEST(test_glwd_update_user_profile_connect_user_update_success)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", USER_LOGIN);
  u_map_put(auth_req.map_post_body, "password", USER_PASSWORD_UPDATED);
  ulfius_send_http_request(&auth_req, &auth_resp);
  ck_assert_int_eq(auth_resp.status, 200);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST
  
START_TEST(test_glwd_update_user_profile_update_password_fail)
{
  json_t * json_body = json_pack("{ssss}", "old_password", USER_PASSWORD, "new_password", "short");
  char * url = msprintf("%s/profile/", SERVER_URI);
  int res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 400, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  free(url);
}
END_TEST
  
START_TEST(test_glwd_update_user_profile_connect_user_update_fail)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", USER_LOGIN);
  u_map_put(auth_req.map_post_body, "password", USER_PASSWORD);
  ulfius_send_http_request(&auth_req, &auth_resp);
  ck_assert_int_eq(auth_resp.status, 403);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST

START_TEST(test_glwd_update_user_profile_send_reset_password)
{
  int res;
  char * url;

  url = msprintf("%s/profile/reset_password/%s", SERVER_URI, USER_LOGIN);
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_update_user_profile_reset_password_token_error)
{
  struct _u_request reset_req;
  struct _u_response reset_resp;
  ulfius_init_request(&reset_req);
  ulfius_init_response(&reset_resp);
  reset_req.http_verb = strdup("PUT");
  reset_req.http_url = msprintf("%s/profile/reset_password/%s", SERVER_URI, USER_LOGIN);

  u_map_put(reset_req.map_post_body, "token", "error");
  u_map_put(reset_req.map_post_body, "password", USER_PASSWORD_RESET);
  ulfius_send_http_request(&reset_req, &reset_resp);
  ck_assert_int_eq(reset_resp.status, 404);
  
  ulfius_clean_request(&reset_req);
  ulfius_clean_response(&reset_resp);
}
END_TEST
  
START_TEST(test_glwd_update_user_profile_reset_password_password_error)
{
  struct _u_request reset_req;
  struct _u_response reset_resp;
  ulfius_init_request(&reset_req);
  ulfius_init_response(&reset_resp);
  reset_req.http_verb = strdup("PUT");
  reset_req.http_url = msprintf("%s/profile/reset_password/%s", SERVER_URI, USER_LOGIN);

  u_map_put(reset_req.map_post_body, "token", token);
  u_map_put(reset_req.map_post_body, "password", "short");
  ulfius_send_http_request(&reset_req, &reset_resp);
  ck_assert_int_eq(reset_resp.status, 400);
  
  ulfius_clean_request(&reset_req);
  ulfius_clean_response(&reset_resp);
}
END_TEST

START_TEST(test_glwd_update_user_profile_reset_password_success)
{
  struct _u_request reset_req;
  struct _u_response reset_resp;
  ulfius_init_request(&reset_req);
  ulfius_init_response(&reset_resp);
  reset_req.http_verb = strdup("PUT");
  reset_req.http_url = msprintf("%s/profile/reset_password/%s", SERVER_URI, USER_LOGIN);

  u_map_put(reset_req.map_post_body, "token", token);
  u_map_put(reset_req.map_post_body, "password", USER_PASSWORD_RESET);
  ulfius_send_http_request(&reset_req, &reset_resp);
  ck_assert_int_eq(reset_resp.status, 200);
  
  ulfius_clean_request(&reset_req);
  ulfius_clean_response(&reset_resp);
}
END_TEST
  
START_TEST(test_glwd_update_user_profile_reset_password_connect_old_password_error)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", USER_LOGIN);
  u_map_put(auth_req.map_post_body, "password", USER_PASSWORD);
  ulfius_send_http_request(&auth_req, &auth_resp);
  ck_assert_int_eq(auth_resp.status, 403);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST
  
START_TEST(test_glwd_update_user_profile_reset_password_connect_new_password_success)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", USER_LOGIN);
  u_map_put(auth_req.map_post_body, "password", USER_PASSWORD_RESET);
  ulfius_send_http_request(&auth_req, &auth_resp);
  ck_assert_int_eq(auth_resp.status, 200);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST

START_TEST(test_glwd_update_user_profile_delete_user)
{
  char * url = msprintf("%s/user/%s", SERVER_URI, USER_LOGIN);
  
  int res = run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

static Suite *glewlwyd_suite0(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd tests user profile");
  tc_core = tcase_create("test_glwd_update_user_profile");
  tcase_add_test(tc_core, test_glwd_update_user_profile_add_user_database);
  tcase_add_test(tc_core, test_glwd_update_user_connect_user_success);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

static Suite *glewlwyd_suite1(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd tests update user profile");
  tc_core = tcase_create("test_glwd_update_user_profile");
  tcase_add_test(tc_core, test_glwd_update_user_profile_update_fail);
  tcase_add_test(tc_core, test_glwd_update_user_profile_update_success);
  tcase_add_test(tc_core, test_glwd_update_user_profile_update_password_success);
  tcase_add_test(tc_core, test_glwd_update_user_profile_connect_user_update_success);
  tcase_add_test(tc_core, test_glwd_update_user_profile_update_password_fail);
  tcase_add_test(tc_core, test_glwd_update_user_profile_connect_user_update_fail);
  tcase_add_test(tc_core, test_glwd_update_user_profile_send_reset_password);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

static Suite *glewlwyd_suite2(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd tests reset password");
  tc_core = tcase_create("test_glwd_update_user_profile");
  tcase_add_test(tc_core, test_glwd_update_user_profile_reset_password_success);
  tcase_add_test(tc_core, test_glwd_update_user_profile_reset_password_token_error);
  tcase_add_test(tc_core, test_glwd_update_user_profile_reset_password_password_error);
  tcase_add_test(tc_core, test_glwd_update_user_profile_reset_password_connect_old_password_error);
  tcase_add_test(tc_core, test_glwd_update_user_profile_reset_password_connect_new_password_success);
  tcase_add_test(tc_core, test_glwd_update_user_profile_delete_user);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

static Suite *glewlwyd_suite3(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd tests: new user");
  tc_core = tcase_create("test_glwd_update_user_profile");
  tcase_add_test(tc_core, test_glwd_update_user_profile_add_user_ldap);
  tcase_add_test(tc_core, test_glwd_update_user_connect_user_success);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

static Suite *glewlwyd_suite4(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd tests: update user profile");
  tc_core = tcase_create("test_glwd_update_user_profile");
  tcase_add_test(tc_core, test_glwd_update_user_profile_update_fail);
  tcase_add_test(tc_core, test_glwd_update_user_profile_update_success);
  tcase_add_test(tc_core, test_glwd_update_user_profile_update_password_success);
  tcase_add_test(tc_core, test_glwd_update_user_profile_connect_user_update_success);
  tcase_add_test(tc_core, test_glwd_update_user_profile_update_password_fail);
  tcase_add_test(tc_core, test_glwd_update_user_profile_connect_user_update_fail);
  tcase_add_test(tc_core, test_glwd_update_user_profile_send_reset_password);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd tests: reset password");
  tc_core = tcase_create("test_glwd_update_user_profile");
  tcase_add_test(tc_core, test_glwd_update_user_profile_reset_password_success);
  tcase_add_test(tc_core, test_glwd_update_user_profile_reset_password_token_error);
  tcase_add_test(tc_core, test_glwd_update_user_profile_reset_password_password_error);
  tcase_add_test(tc_core, test_glwd_update_user_profile_reset_password_connect_old_password_error);
  tcase_add_test(tc_core, test_glwd_update_user_profile_reset_password_connect_new_password_success);
  tcase_add_test(tc_core, test_glwd_update_user_profile_delete_user);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s0, *s1, *s2, *s3, *s4, *s5;
  SRunner *sr0, *sr1, *sr2, *sr3, *sr4, *sr5;
  struct _u_request auth_req;
  struct _u_response auth_resp;
  int res, i;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&admin_req);
  ulfius_init_request(&user_req);
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/token/", SERVER_URI);
  u_map_put(auth_req.map_post_body, "grant_type", "password");
  u_map_put(auth_req.map_post_body, "username", ADMIN_LOGIN);
  u_map_put(auth_req.map_post_body, "password", ADMIN_PASSWORD);
  u_map_put(auth_req.map_post_body, "scope", SCOPE_LIST);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK) {
    char * bearer_token = msprintf("Bearer %s", (json_string_value(json_object_get(auth_resp.json_body, "access_token"))));
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", ADMIN_LOGIN);
    u_map_put(admin_req.map_header, "Authorization", bearer_token);
    free(bearer_token);
  }
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
  
  s0 = glewlwyd_suite0();
  sr0 = srunner_create(s0);

  srunner_run_all(sr0, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr0);
  srunner_free(sr0);

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", USER_LOGIN);
  u_map_put(auth_req.map_post_body, "password", USER_PASSWORD);
  ulfius_send_http_request(&auth_req, &auth_resp);
  for (i=0; i<auth_resp.nb_cookies; i++) {
    cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
    u_map_put(user_req.map_header, "Cookie", cookie);
  }
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
  
  s1 = glewlwyd_suite1();
  sr1 = srunner_create(s1);

  srunner_run_all(sr1, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr1);
  srunner_free(sr1);
  
  y_log_message(Y_LOG_LEVEL_INFO, "Please enter token sent by email and press <ENTER>");
  fgets(token, 128, stdin);
  token[strlen(token) - 1] = '\0';
  
  s2 = glewlwyd_suite2();
  sr2 = srunner_create(s2);

  srunner_run_all(sr2, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr2);
  srunner_free(sr2);
  
  s3 = glewlwyd_suite3();
  sr3 = srunner_create(s3);

  srunner_run_all(sr3, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr3);
  srunner_free(sr3);

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", USER_LOGIN);
  u_map_put(auth_req.map_post_body, "password", USER_PASSWORD);
  ulfius_send_http_request(&auth_req, &auth_resp);
  for (i=0; i<auth_resp.nb_cookies; i++) {
    cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
    u_map_put(user_req.map_header, "Cookie", cookie);
  }
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
  
  s4 = glewlwyd_suite4();
  sr4 = srunner_create(s4);

  srunner_run_all(sr4, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr4);
  srunner_free(sr4);
  
  y_log_message(Y_LOG_LEVEL_INFO, "Please enter token sent by email and press <ENTER>");
  fgets(token, 128, stdin);
  token[strlen(token) - 1] = '\0';
  
  s5 = glewlwyd_suite();
  sr5 = srunner_create(s5);

  srunner_run_all(sr5, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr5);
  srunner_free(sr5);
  
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

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

#define SERVER_URI "http://localhost:4593/glewlwyd"
#define USERNAME "admin"
#define PASSWORD "MyAdminPassword2016!"
#define SCOPE_LIST "g_admin"

struct _u_request user_req;

START_TEST(test_glwd_crud_user_list)
{
  char * url = msprintf("%s/user/", SERVER_URI);
  json_t * j_user1 = json_string("user1");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_user1, NULL, NULL);
  free(url);
  json_decref(j_user1);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_get)
{
  char * url = msprintf("%s/user/user1", SERVER_URI);
  json_t * j_user1 = json_string("user1");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_user1, NULL, NULL);
  free(url);
  json_decref(j_user1);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_get_not_found)
{
  char * url = msprintf("%s/user/not_found", SERVER_URI);
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL);
  free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_add_ok_database)
{
  json_t * json_body;
  char * url = msprintf("%s/user/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssssssssss[ss]}", "source", "database", "login", "new_user", "name", "New User", "password", "password", "email", "test@glewlwyd.domain", "scope", "scope1", "scope2");
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_user_add_invalid_database)
{
  json_t * json_body;
  char * url = msprintf("%s/user/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssisss[s]}", "source", "database", "login", 4, "email", "test@glewlwyd.domain", "scope", "scope_invalid");
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 400, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_user_get_new_database)
{
  char * url = msprintf("%s/user/new_user?source=database", SERVER_URI);
  json_t * j_new_user = json_string("test@glewlwyd.domain");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_user, NULL, NULL);
  free(url);
  json_decref(j_new_user);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_set_new_database)
{
  char * url = msprintf("%s/user/new_user?source=database", SERVER_URI);
  json_t * json_body = json_pack("{ss}", "email", "test_new@glewlwyd.domain");
  
  int res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  free(url);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_get_new_updated_database)
{
  char * url = msprintf("%s/user/new_user?source=database", SERVER_URI);
  json_t * j_new_user = json_string("test_new@glewlwyd.domain");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_user, NULL, NULL);
  free(url);
  json_decref(j_new_user);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_connect_success_new)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", "new_user");
  u_map_put(auth_req.map_post_body, "password", "password");
  ulfius_send_http_request(&auth_req, &auth_resp);
  ck_assert_int_eq(auth_resp.status, 200);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST

START_TEST(test_glwd_crud_user_delete_new_database)
{
  char * url = msprintf("%s/user/new_user?source=database", SERVER_URI);
  
  int res = run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_connect_fail_new)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", "new_user");
  u_map_put(auth_req.map_post_body, "password", "password");
  ulfius_send_http_request(&auth_req, &auth_resp);
  ck_assert_int_eq(auth_resp.status, 403);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST

START_TEST(test_glwd_crud_user_add_ok_ldap)
{
  json_t * json_body;
  char * url = msprintf("%s/user/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssssssssss[ss]}", "source", "ldap", "login", "new_user", "name", "New User", "password", "password", "email", "test@glewlwyd.domain", "scope", "scope1", "scope2");
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_user_add_invalid_ldap)
{
  json_t * json_body;
  char * url = msprintf("%s/user/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssisss[s]}", "source", "ldap", "login", 4, "email", "test@glewlwyd.domain", "scope", "scope_invalid");
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 400, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_user_get_new_ldap)
{
  char * url = msprintf("%s/user/new_user?source=ldap", SERVER_URI);
  json_t * j_new_user = json_string("test@glewlwyd.domain");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_user, NULL, NULL);
  free(url);
  json_decref(j_new_user);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_set_new_ldap)
{
  char * url = msprintf("%s/user/new_user?source=ldap", SERVER_URI);
  json_t * json_body = json_pack("{ss}", "email", "test_new@glewlwyd.domain");
  
  int res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  free(url);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_get_new_updated_ldap)
{
  char * url = msprintf("%s/user/new_user?source=ldap", SERVER_URI);
  json_t * j_new_user = json_string("test_new@glewlwyd.domain");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_user, NULL, NULL);
  free(url);
  json_decref(j_new_user);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_delete_new_ldap)
{
  char * url = msprintf("%s/user/new_user?source=ldap", SERVER_URI);
  
  int res = run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_add_ok_no_source)
{
  json_t * json_body;
  char * url = msprintf("%s/user/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssssssss[ss]}", "login", "new_user", "name", "New User", "password", "password", "email", "test@glewlwyd.domain", "scope", "scope1", "scope2");
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_user_add_invalid_no_source)
{
  json_t * json_body;
  char * url = msprintf("%s/user/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sisss[s]}", "login", 4, "email", "test@glewlwyd.domain", "scope", "scope_invalid");
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 400, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_user_get_new_no_source)
{
  char * url = msprintf("%s/user/new_user", SERVER_URI);
  json_t * j_new_user = json_string("test@glewlwyd.domain");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_user, NULL, NULL);
  free(url);
  json_decref(j_new_user);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_set_new_no_source)
{
  char * url = msprintf("%s/user/new_user", SERVER_URI);
  json_t * json_body = json_pack("{ss}", "email", "test_new@glewlwyd.domain");
  
  int res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  free(url);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_get_new_updated_no_source)
{
  char * url = msprintf("%s/user/new_user", SERVER_URI);
  json_t * j_new_user = json_string("test_new@glewlwyd.domain");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_user, NULL, NULL);
  free(url);
  json_decref(j_new_user);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_user_delete_new_no_source)
{
  char * url = msprintf("%s/user/new_user", SERVER_URI);
  
  int res = run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

static Suite *libjwt_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd user CRUD");
  tc_core = tcase_create("test_glwd_crud_user");
  tcase_add_test(tc_core, test_glwd_crud_user_list);
  tcase_add_test(tc_core, test_glwd_crud_user_get);
  tcase_add_test(tc_core, test_glwd_crud_user_get_not_found);
  tcase_add_test(tc_core, test_glwd_crud_user_add_ok_database);
  tcase_add_test(tc_core, test_glwd_crud_user_add_invalid_database);
  tcase_add_test(tc_core, test_glwd_crud_user_get_new_database);
  tcase_add_test(tc_core, test_glwd_crud_user_set_new_database);
  tcase_add_test(tc_core, test_glwd_crud_user_get_new_updated_database);
  tcase_add_test(tc_core, test_glwd_crud_user_connect_success_new);
  tcase_add_test(tc_core, test_glwd_crud_user_delete_new_database);
  tcase_add_test(tc_core, test_glwd_crud_user_connect_fail_new);
  tcase_add_test(tc_core, test_glwd_crud_user_add_ok_ldap);
  tcase_add_test(tc_core, test_glwd_crud_user_add_invalid_ldap);
  tcase_add_test(tc_core, test_glwd_crud_user_get_new_ldap);
  tcase_add_test(tc_core, test_glwd_crud_user_set_new_ldap);
  tcase_add_test(tc_core, test_glwd_crud_user_get_new_updated_ldap);
  tcase_add_test(tc_core, test_glwd_crud_user_connect_success_new);
  tcase_add_test(tc_core, test_glwd_crud_user_delete_new_ldap);
  tcase_add_test(tc_core, test_glwd_crud_user_connect_fail_new);
  tcase_add_test(tc_core, test_glwd_crud_user_add_ok_no_source);
  tcase_add_test(tc_core, test_glwd_crud_user_add_invalid_no_source);
  tcase_add_test(tc_core, test_glwd_crud_user_get_new_no_source);
  tcase_add_test(tc_core, test_glwd_crud_user_set_new_no_source);
  tcase_add_test(tc_core, test_glwd_crud_user_get_new_updated_no_source);
  tcase_add_test(tc_core, test_glwd_crud_user_connect_success_new);
  tcase_add_test(tc_core, test_glwd_crud_user_delete_new_no_source);
  tcase_add_test(tc_core, test_glwd_crud_user_connect_fail_new);
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
  ulfius_init_request(&user_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/token/", SERVER_URI);
  u_map_put(auth_req.map_post_body, "grant_type", "password");
  u_map_put(auth_req.map_post_body, "username", USERNAME);
  u_map_put(auth_req.map_post_body, "password", PASSWORD);
  u_map_put(auth_req.map_post_body, "scope", SCOPE_LIST);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK) {
    char * bearer_token = msprintf("Bearer %s", (json_string_value(json_object_get(auth_resp.json_body, "access_token"))));
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);
    u_map_put(user_req.map_header, "Authorization", bearer_token);
    free(bearer_token);
  }
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
  
  s = libjwt_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  ulfius_clean_request(&user_req);
  
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

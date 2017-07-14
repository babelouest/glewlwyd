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
#define PASSWORD "MyAdminPassword2016!"
#define SCOPE_LIST "g_admin"
#define NEW_CLIENT_SCOPE_LIST "scope1 scope2"

struct _u_request user_req;

START_TEST(test_glwd_crud_client_list)
{
  char * url = msprintf("%s/client/", SERVER_URI);
  json_t * j_client1 = json_string("client1_id");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_client1, NULL, NULL);
  free(url);
  json_decref(j_client1);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_search_success)
{
  char * url = msprintf("%s/client/?search=new_client", SERVER_URI);
  json_t * j_client1 = json_string("new_client");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_client1, NULL, NULL);
  free(url);
  json_decref(j_client1);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_get)
{
  char * url = msprintf("%s/client/client1_id", SERVER_URI);
  json_t * j_client1 = json_string("client1_id");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_client1, NULL, NULL);
  free(url);
  json_decref(j_client1);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_get_not_found)
{
  char * url = msprintf("%s/client/not_found", SERVER_URI);
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL);
  free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_add_ok_database)
{
  json_t * json_body;
  char * url = msprintf("%s/client/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssssssssssosos[ss]s[ss]s[{ssss}{ssss}]}", 
                        "source", "database", 
                        "name", "new_client", 
                        "client_id", "new_client", 
                        "description", "New Client", 
                        "password", "password", 
                        "enabled", json_true(),
                        "confidential", json_true(),
                        "scope", 
                          "scope1", "scope2",
                        "authorization_type",
                          "code",
                          "client_credentials",
                        "redirect_uri",
                          "name", "uri1",
                          "uri", "http://example1.com/",
                          "name", "uri2",
                          "uri", "https://example2.com/");
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_client_add_invalid_database)
{
  json_t * json_body;
  char * url = msprintf("%s/client/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssisss[s]}", "source", "database", "client_id", 4, "name", "invalid_client", "scope", "scope_invalid");
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 400, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_client_get_new_database)
{
  char * url = msprintf("%s/client/new_client?source=database", SERVER_URI);
  json_t * j_new_client = json_string("new_client");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_client, NULL, NULL);
  free(url);
  json_decref(j_new_client);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_set_new_database)
{
  json_t * json_body;
  char * url = msprintf("%s/client/new_client?source=database", SERVER_URI);
  json_body = json_pack("{sssssosos[ss]s[ss]s[{ssss}{ssss}]}", 
                        "name", "new_client", 
                        "description", "New Description", 
                        "enabled", json_true(),
                        "confidential", json_true(),
                        "scope", 
                          "scope1", "scope2",
                        "authorization_type",
                          "code",
                          "client_credentials",
                        "redirect_uri",
                          "name", "uri1",
                          "uri", "http://example1.com/",
                          "name", "uri2",
                          "uri", "https://example2.com/");
  
  int res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  free(url);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_get_new_updated_database)
{
  char * url = msprintf("%s/client/new_client?source=database", SERVER_URI);
  json_t * j_new_client = json_string("New Description");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_client, NULL, NULL);
  free(url);
  json_decref(j_new_client);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_connect_success)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", "scope1");
  
  int res = run_simple_test(NULL, "POST", url, "new_client", "password", NULL, &body, 200, NULL, "access_token", NULL);
  free(url);
  u_map_clean(&body);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_delete_new_database)
{
  char * url = msprintf("%s/client/new_client?source=database", SERVER_URI);
  
  int res = run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_connect_fail)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", NEW_CLIENT_SCOPE_LIST);
  
  int res = run_simple_test(NULL, "POST", url, "new_client", "password", NULL, &body, 403, NULL, NULL, NULL);
  free(url);
  u_map_clean(&body);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_add_ok_ldap)
{
  json_t * json_body;
  char * url = msprintf("%s/client/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssssssssssosos[ss]s[ss]s[{ssss}]}", 
                        "source", "ldap", 
                        "name", "New Client", 
                        "client_id", "new_client", 
                        "description", "New Client", 
                        "password", "password", 
                        "enabled", json_true(),
                        "confidential", json_true(),
                        "scope", 
                          "scope1", "scope2",
                        "authorization_type",
                          "code",
                          "client_credentials",
                        "redirect_uri",
                          "name", "uri1",
                          "uri", "http://example1.com/",
                          "name", "uri2",
                          "uri", "https://example2.com/");
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_client_add_invalid_ldap)
{
  json_t * json_body;
  char * url = msprintf("%s/client/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssisss[s]}", "source", "ldap", "client_id", 4, "name", "invalid_client", "scope", "scope_invalid");
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 400, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_client_get_new_ldap)
{
  char * url = msprintf("%s/client/new_client?source=ldap", SERVER_URI);
  json_t * j_new_client = json_string("new_client");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_client, NULL, NULL);
  free(url);
  json_decref(j_new_client);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_set_new_ldap)
{
  json_t * json_body;
  char * url = msprintf("%s/client/new_client?source=ldap", SERVER_URI);
  json_body = json_pack("{sssssosos[ss]s[ss]s[{ssss}]}", 
                        "name", "New Client", 
                        "description", "New Description", 
                        "enabled", json_true(),
                        "confidential", json_true(),
                        "scope", 
                          "scope1", "scope2",
                        "authorization_type",
                          "code",
                          "client_credentials",
                        "redirect_uri",
                          "name", "uri1",
                          "uri", "http://example1.com/",
                          "name", "uri2",
                          "uri", "https://example2.com/");
  
  int res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  free(url);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_get_new_updated_ldap)
{
  char * url = msprintf("%s/client/new_client?source=ldap", SERVER_URI);
  json_t * j_new_client = json_string("New Description");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_client, NULL, NULL);
  free(url);
  json_decref(j_new_client);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_delete_new_ldap)
{
  char * url = msprintf("%s/client/new_client?source=ldap", SERVER_URI);
  
  int res = run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_add_ok_no_source)
{
  json_t * json_body;
  char * url = msprintf("%s/client/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sssssssssosos[ss]s[ss]s[{ssss}{ssss}]}", 
                        "name", "New Client", 
                        "client_id", "new_client", 
                        "description", "New Client", 
                        "password", "password", 
                        "enabled", json_true(),
                        "confidential", json_true(),
                        "scope", 
                          "scope1", "scope2",
                        "authorization_type",
                          "code",
                          "client_credentials",
                        "redirect_uri",
                          "name", "uri1",
                          "uri", "http://example1.com/",
                          "name", "uri2",
                          "uri", "https://example2.com/");
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_client_add_invalid_no_source)
{
  json_t * json_body;
  char * url = msprintf("%s/client/", SERVER_URI);
  int res;
  
  json_body = json_pack("{sisss[s]}", "client_id", 4, "name", "invalid_client", "scope", "scope_invalid");
  res = run_simple_test(&user_req, "POST", url, NULL, NULL, json_body, NULL, 400, NULL, NULL, NULL);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
  
  free(url);
}
END_TEST

START_TEST(test_glwd_crud_client_get_new_no_source)
{
  char * url = msprintf("%s/client/new_client", SERVER_URI);
  json_t * j_new_client = json_string("new_client");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_client, NULL, NULL);
  free(url);
  json_decref(j_new_client);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_set_new_no_source)
{
  json_t * json_body;
  char * url = msprintf("%s/client/new_client", SERVER_URI);
  json_body = json_pack("{sssssosos[ss]s[ss]s[{ssss}{ssss}]}", 
                        "name", "New Client", 
                        "description", "New Description", 
                        "enabled", json_true(),
                        "confidential", json_true(),
                        "scope", 
                          "scope1", "scope2",
                        "authorization_type",
                          "code",
                          "client_credentials",
                        "redirect_uri",
                          "name", "uri1",
                          "uri", "http://example1.com/",
                          "name", "uri2",
                          "uri", "https://example2.com/");
  
  int res = run_simple_test(&user_req, "PUT", url, NULL, NULL, json_body, NULL, 200, NULL, NULL, NULL);
  free(url);
  json_decref(json_body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_get_new_updated_no_source)
{
  char * url = msprintf("%s/client/new_client", SERVER_URI);
  json_t * j_new_client = json_string("New Description");
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_new_client, NULL, NULL);
  free(url);
  json_decref(j_new_client);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_crud_client_delete_new_no_source)
{
  char * url = msprintf("%s/client/new_client", SERVER_URI);
  
  int res = run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd client CRUD");
  tc_core = tcase_create("test_glwd_crud_client");
  tcase_add_test(tc_core, test_glwd_crud_client_list);
  tcase_add_test(tc_core, test_glwd_crud_client_get);
  tcase_add_test(tc_core, test_glwd_crud_client_get_not_found);
  tcase_add_test(tc_core, test_glwd_crud_client_add_ok_database);
  tcase_add_test(tc_core, test_glwd_crud_client_search_success);
  tcase_add_test(tc_core, test_glwd_crud_client_add_invalid_database);
  tcase_add_test(tc_core, test_glwd_crud_client_get_new_database);
  tcase_add_test(tc_core, test_glwd_crud_client_set_new_database);
  tcase_add_test(tc_core, test_glwd_crud_client_get_new_updated_database);
  tcase_add_test(tc_core, test_glwd_crud_client_connect_success);
  tcase_add_test(tc_core, test_glwd_crud_client_delete_new_database);
  tcase_add_test(tc_core, test_glwd_crud_client_connect_fail);
  tcase_add_test(tc_core, test_glwd_crud_client_add_ok_ldap);
  tcase_add_test(tc_core, test_glwd_crud_client_search_success);
  tcase_add_test(tc_core, test_glwd_crud_client_add_invalid_ldap);
  tcase_add_test(tc_core, test_glwd_crud_client_get_new_ldap);
  tcase_add_test(tc_core, test_glwd_crud_client_set_new_ldap);
  tcase_add_test(tc_core, test_glwd_crud_client_get_new_updated_ldap);
  tcase_add_test(tc_core, test_glwd_crud_client_connect_success);
  tcase_add_test(tc_core, test_glwd_crud_client_delete_new_ldap);
  tcase_add_test(tc_core, test_glwd_crud_client_connect_fail);
  tcase_add_test(tc_core, test_glwd_crud_client_add_ok_no_source);
  tcase_add_test(tc_core, test_glwd_crud_client_search_success);
  tcase_add_test(tc_core, test_glwd_crud_client_add_invalid_no_source);
  tcase_add_test(tc_core, test_glwd_crud_client_get_new_no_source);
  tcase_add_test(tc_core, test_glwd_crud_client_set_new_no_source);
  tcase_add_test(tc_core, test_glwd_crud_client_get_new_updated_no_source);
  tcase_add_test(tc_core, test_glwd_crud_client_connect_success);
  tcase_add_test(tc_core, test_glwd_crud_client_delete_new_no_source);
  tcase_add_test(tc_core, test_glwd_crud_client_connect_fail);
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
    json_t * json_body = ulfius_get_json_body_response(&auth_resp, NULL);
    char * bearer_token = msprintf("Bearer %s", (json_string_value(json_object_get(json_body, "access_token"))));
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);
    u_map_put(user_req.map_header, "Authorization", bearer_token);
    free(bearer_token);
    json_decref(json_body);
  }
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
  
  s = glewlwyd_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  ulfius_clean_request(&user_req);
  
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

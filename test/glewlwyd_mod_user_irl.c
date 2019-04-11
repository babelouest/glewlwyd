/* Public domain, no copyright. Use at your own risk. */

/**
 * This test is used to validate one user backend module that will be created upon start and deleted after
 * The user backend must be in write mode and empty
 * This backend must have the following data-format available:
 *
 * data-format: {
 *   data1: {multiple: false, read: true, write: true, profile-read: false, profile-write: false}
 *   data2: {multiple: true, read: true, write: true, profile-read: true, profile-write: false}
 *   data3: {multiple: false, read: false, write: false, profile-read: true, profile-write: true}
 *   data4: {multiple: true, read: false, write: false, profile-read: true, profile-write: true}
 * }
 */

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
#include "../src/glewlwyd-common.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define PROFILE_USERNAME "new_user_irl"
#define PROFILE_PASSWORD "password"

struct _u_request admin_req;
char * module_name = NULL;

START_TEST(test_glwd_mod_user_irl_admin_add)
{
  json_t * j_user;
  char * url;
  
  url = msprintf("%s/user?source=", SERVER_URI, module_name);
  j_user = json_pack("{si}", "username", 42);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_user, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_user);
  
  j_user = json_pack("{ssss}", "username", PROFILE_USERNAME, "password", PROFILE_PASSWORD);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_user, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_user);
  
  o_free(url);
  
  url = msprintf("%s/user/%s", SERVER_URI, PROFILE_USERNAME, module_name);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_admin_update)
{
  json_t * j_user;
  char * url;
  
  url = msprintf("%s/user?source=", SERVER_URI, module_name);
  j_user = json_pack("{sssssssssos[s]sss[ss]}", "username", PROFILE_USERNAME, "password", PROFILE_PASSWORD, "name", "Dave Lopper", "email", "dave@glewlwyd", "enabled", json_false(), "scope", "g_profile", "data1", "value1", "data2", "value2", "value3");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_user, NULL, 200, NULL, NULL, NULL), 1);
  
  o_free(url);
  json_decref(j_user);
  j_user = json_pack("{sssssssos[s]sss[ss]}", "username", PROFILE_USERNAME, "name", "Dave Lopper", "email", "dave@glewlwyd", "enabled", json_false(), "scope", "g_profile", "data1", "value1", "data2", "value2", "value3");
  url = msprintf("%s/user/%s?source=", SERVER_URI, PROFILE_USERNAME, module_name);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_user, NULL, NULL), 1);
  json_decref(j_user);
  
  o_free(url);
  json_decref(j_user);
  j_user = json_pack("{sisssos[ss]sss[s]}", "name", 42, "email", "davenew@glewlwyd", "enabled", json_false(), "scope", "g_profile", "scope1", "data1", "value1new", "data2", "value2new");
  url = msprintf("%s/user/%s?source=", SERVER_URI, PROFILE_USERNAME, module_name);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_user, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_user);
  
  o_free(url);
  json_decref(j_user);
  j_user = json_pack("{sssssos[s]sss[s]sss[s]}", "name", "Dave Lopper", "email", "daven@glewlwyd", "enabled", json_true(), "scope", "g_profile", "data1", "value1new", "data2", "value2new", "data3", "value3", "data4", "value4");
  url = msprintf("%s/user/%s?source=", SERVER_URI, PROFILE_USERNAME, module_name);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_user, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_user);
  
  o_free(url);
  json_decref(j_user);
  j_user = json_pack("{sssssos[s]sss[s]}", "name", "Dave Lopper", "email", "daven@glewlwyd", "enabled", json_true(), "scope", "g_profile", "data1", "value1new", "data2", "value2new");
  url = msprintf("%s/user/%s?source=", SERVER_URI, PROFILE_USERNAME, module_name);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_user, NULL, NULL), 1);
  json_decref(j_user);
  
  o_free(url);
  json_decref(j_user);
  j_user = json_pack("{sssssos[ss]sss[s]}", "name", "Dave Lopper new", "email", "davenew@glewlwyd", "enabled", json_false(), "scope", "g_profile", "scope1", "data1", "value1new", "data2", "value2new");
  url = msprintf("%s/user/%s?source=", SERVER_URI, PROFILE_USERNAME, module_name);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_user, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_user);
  
  o_free(url);
  json_decref(j_user);
  j_user = json_pack("{sssssos[ss]sss[s]}", "name", "Dave Lopper new", "email", "davenew@glewlwyd", "enabled", json_false(), "scope", "g_profile", "scope1", "data1", "value1new", "data2", "value2new");
  url = msprintf("%s/user/%s?source=", SERVER_URI, PROFILE_USERNAME, module_name);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_user, NULL, NULL), 1);
  json_decref(j_user);
  
  o_free(url);
  
  url = msprintf("%s/user/%s", SERVER_URI, PROFILE_USERNAME, module_name);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_admin_update_profile)
{
  struct _u_request user_req, auth_req;
  struct _u_response auth_resp;
  json_t * j_user, * j_body;
  char * url;
  
  url = msprintf("%s/user?source=", SERVER_URI, module_name);
  j_user = json_pack("{sssssssssos[s]sss[ss]}", "username", PROFILE_USERNAME, "password", PROFILE_PASSWORD, "name", "Dave Lopper", "email", "dave@glewlwyd", "enabled", json_false(), "scope", "g_profile", "data1", "value1", "data2", "value2", "value3");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_user, NULL, 200, NULL, NULL, NULL), 1);
  
  ulfius_init_request(&user_req);
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", PROFILE_USERNAME, "password", ADMIN_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  for (i=0; i<auth_resp.nb_cookies; i++) {
    char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
    u_map_put(user_req.map_header, "Cookie", cookie);
    o_free(cookie);
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);
  
  o_free(url);
  json_decref(j_user);
  j_user = json_pack("{sisssos[ss]sss[s]}", "name", 42, "email", "davenew@glewlwyd", "enabled", json_true(), "scope", "g_profile", "scope1", "data1", "value1new", "data2", "value2new");
  url = msprintf("%s/user/%s?source=", SERVER_URI, PROFILE_USERNAME, module_name);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", url, NULL, NULL, j_user, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_user);
  
  o_free(url);
  json_decref(j_user);
  j_user = json_pack("{sssssos[ss]sss[s]sss[ss]}", "name", "Dave Lopper new", "email", "davenew@glewlwyd", "enabled", json_false(), "scope", "g_profile", "scope1", "data1", "value1new", "data2", "value2new", "data3", "value3", "data4", "value4", "value5");
  url = msprintf("%s/user/%s?source=", SERVER_URI, PROFILE_USERNAME, module_name);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", url, NULL, NULL, j_user, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_user);
  
  o_free(url);
  json_decref(j_user);
  j_user = json_pack("{sssss[s]s[ss]sss[ss]}", "name", "Dave Lopper new", "email", "dave@glewlwyd", "scope", "g_profile", "data2", "value2", "value3", "data3", "value3", "data4", "value4", "value5");
  url = msprintf("%s/user/%s?source=", SERVER_URI, PROFILE_USERNAME, module_name);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_user, NULL, NULL), 1);
  json_decref(j_user);
  
  o_free(url);
  json_decref(j_user);
  j_user = json_pack("{sssss[s]s[ss]}", "name", "Dave Lopper new", "email", "dave@glewlwyd", "scope", "g_profile", "data2", "value2", "value3");
  url = msprintf("%s/user/%s?source=", SERVER_URI, PROFILE_USERNAME, module_name);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_user, NULL, NULL), 1);
  json_decref(j_user);
  
  o_free(url);
  
  url = msprintf("%s/user/%s?source=", SERVER_URI, PROFILE_USERNAME, module_name);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  
  o_free(url);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd delete token");
  tc_core = tcase_create("test_glwd_mod_user_irl");
  tcase_add_test(tc_core, test_glwd_mod_user_irl_admin_add);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_admin_update);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_admin_update_profile);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_admin_get);
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
  json_t * j_body, * j_parameters = NULL;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&admin_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", ADMIN_USERNAME, "password", ADMIN_PASSWORD);
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
    
    if (do_test && argc > 2) {
      // Add module using the JSON object given in argv[1]
      if ((j_parameters = json_loads(argv[1], JSON_DECODE_ANY, NULL)) != NULL) {
        if (!run_simple_test(&admin_req, "POST", (SERVER_URI "/mod/user/"), NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "Add error");
          do_test = 0;
        } else {
          module_name = o_strdup(json_string_value(json_object_get(j_parameters, "name")));
        }
        json_decref(j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Input parameters invalid");
        do_test = 0;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "No input parameters");
      do_test = 0;
    }

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
  o_free(module_name);
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

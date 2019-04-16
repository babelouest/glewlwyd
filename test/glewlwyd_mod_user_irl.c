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
#define MOD_NAME "mod_irl"
#define PROFILE_PASSWORD "password"
#define PROFILE_NEW_PASSWORD "newpassword"
#define PROFILE_NAME "Dave Lopper"
#define PROFILE_MAIL "dev@glewlwyd"
#define PROFILE_SCOPE_1 "g_profile"
#define PROFILE_SCOPE_2 "scope1"

struct _u_request admin_req;
json_t * j_params;
char * username = NULL, * username_pattern = NULL;

START_TEST(test_glwd_mod_user_irl_module_add)
{
  char * url = SERVER_URI "/mod/user";
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_add_error_param)
{
  char * url = msprintf("%s/user?source=" MOD_NAME, SERVER_URI);
  json_t * j_parameters = json_pack("{ss}", "error", "error");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("[{ss}]", "username", "test");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{si}", "username", 42);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_add)
{
  json_t * j_user = json_pack("{sssssssss[ss]}", "username", username, "password", PROFILE_PASSWORD, "name", PROFILE_NAME, "email", PROFILE_MAIL, "scope", PROFILE_SCOPE_1, PROFILE_SCOPE_2);
  char * url = SERVER_URI "/user?source=" MOD_NAME;
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_user, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_user);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_add_already_present)
{
  char * url = msprintf("%s/user?source=" MOD_NAME, SERVER_URI);
  json_t * j_parameters = json_pack("{sssssssss[ss]}", "username", username, "password", PROFILE_PASSWORD, "name", PROFILE_NAME, "email", PROFILE_MAIL, "scope", PROFILE_SCOPE_1, PROFILE_SCOPE_2);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_delete_error)
{
  char * url = msprintf("%s/user/error?source=" MOD_NAME, SERVER_URI);

  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_get_list)
{
  json_t * j_user = json_pack("{sssssssss[ss]}", "username", username, "name", PROFILE_NAME, "email", PROFILE_MAIL, "source", MOD_NAME, "scope", PROFILE_SCOPE_1, PROFILE_SCOPE_2);
  char * url = SERVER_URI "/user?source=" MOD_NAME;
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_user, NULL, NULL), 1);
  json_decref(j_user);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_get)
{
  json_t * j_user = json_pack("{sssssssss[ss]}", "username", username, "name", PROFILE_NAME, "email", PROFILE_MAIL, "source", MOD_NAME, "scope", PROFILE_SCOPE_1, PROFILE_SCOPE_2);
  char * url = msprintf(SERVER_URI "/user/%s?source=" MOD_NAME, username);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_user, NULL, NULL), 1);
  json_decref(j_user);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_auth)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  json_t * j_body, * j_register;
  char * cookie;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", username, "password", PROFILE_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_gt(auth_resp.nb_cookies, 0);
  ck_assert_ptr_ne((cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value)), NULL);
  ck_assert_int_eq(u_map_put(auth_req.map_header, "Cookie", cookie), U_OK);
  
  ulfius_clean_response(&auth_resp);
  
  ulfius_init_response(&auth_resp);
  
  j_register = json_pack("{sssssss{so}}", "username", username, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/auth/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
  j_register = json_pack("{sssssss{so}}", "username", username, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/auth/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
  j_body = json_pack("{sssssss{ss}}", "username", username, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  
  ulfius_clean_response(&auth_resp);
  ulfius_init_response(&auth_resp);
  
  j_body = json_pack("{sssssss{ss}}", "username", username, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  
  j_register = json_pack("{sssssss{so}}", "username", username, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_false());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/auth/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
  j_register = json_pack("{sssssss{so}}", "username", username, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_false());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/auth/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);
  o_free(cookie);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_update_profile)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  json_t * j_body, * j_profile;
  char * cookie;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", username, "password", PROFILE_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_gt(auth_resp.nb_cookies, 0);
  ck_assert_ptr_ne((cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value)), NULL);
  ck_assert_int_eq(u_map_put(auth_req.map_header, "Cookie", cookie), U_OK);
  
  ulfius_clean_response(&auth_resp);
  
  ulfius_init_response(&auth_resp);
  
  j_profile = json_pack("{sssssssss[ss]}", "username", username, "name", PROFILE_NAME, "email", PROFILE_MAIL, "source", MOD_NAME, "scope", PROFILE_SCOPE_1, PROFILE_SCOPE_2);
  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/profile/", NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ss}", "name", PROFILE_NAME " Profile Updated");
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/profile/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{sssssssss[ss]}", "username", username, "name", PROFILE_NAME " Profile Updated", "email", PROFILE_MAIL, "source", MOD_NAME, "scope", PROFILE_SCOPE_1, PROFILE_SCOPE_2);
  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/profile/", NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
  
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);
  o_free(cookie);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_update_password)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  json_t * j_body, * j_profile;
  char * cookie;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", username, "password", PROFILE_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_gt(auth_resp.nb_cookies, 0);
  ck_assert_ptr_ne((cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value)), NULL);
  ck_assert_int_eq(u_map_put(auth_req.map_header, "Cookie", cookie), U_OK);
  
  ulfius_clean_response(&auth_resp);
  
  j_profile = json_pack("{ssss}", "username", username, "password", PROFILE_NEW_PASSWORD);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", username, "password", PROFILE_PASSWORD);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "old_password", PROFILE_PASSWORD, "password", PROFILE_NEW_PASSWORD);
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/profile/password/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", username, "password", PROFILE_NEW_PASSWORD);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", username, "password", PROFILE_PASSWORD);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  ulfius_clean_request(&auth_req);
  o_free(cookie);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_update)
{
  json_t * j_user = json_pack("{sssss[ss]}", "name", PROFILE_NAME "-updated", "email", PROFILE_MAIL "-updated", "scope", PROFILE_SCOPE_1, PROFILE_SCOPE_2);
  char * url = msprintf(SERVER_URI "/user/%s?source=" MOD_NAME, username);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_user, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_user);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_get_updated)
{
  json_t * j_user = json_pack("{sssssssss[ss]}", "username", username, "name", PROFILE_NAME "-updated", "email", PROFILE_MAIL "-updated", "source", MOD_NAME, "scope", PROFILE_SCOPE_1, PROFILE_SCOPE_2);
  char * url = msprintf(SERVER_URI "/user/%s?source=" MOD_NAME, username);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_user, NULL, NULL), 1);
  json_decref(j_user);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_delete)
{
  char * url = msprintf(SERVER_URI "/user/%s?source=" MOD_NAME, username);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_large_list_add)
{
  int i;
  char * cur_username;
  json_t * j_user;
  
  for (i=0; i < 100; i++) {
    cur_username = msprintf("%s%d", username_pattern, i);
    j_user = json_pack("{sssssssss[ss]}", "username", cur_username, "password", PROFILE_PASSWORD, "name", PROFILE_NAME, "email", PROFILE_MAIL, "scope", PROFILE_SCOPE_1, PROFILE_SCOPE_2);
    ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user?source=" MOD_NAME, NULL, NULL, j_user, NULL, 200, NULL, NULL, NULL), 1);
    json_decref(j_user);
    o_free(cur_username);
  }
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_large_list_get)
{
  json_t * j_user;
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  
  o_free(admin_req.http_verb);
  o_free(admin_req.http_url);
  admin_req.http_verb = strdup("GET");
  admin_req.http_url = msprintf(SERVER_URI "/user?source=" MOD_NAME "&pattern=%s", username_pattern);
  ck_assert_int_eq(ulfius_send_http_request(&admin_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_user = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_user), 100);
  json_decref(j_user);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_large_list_delete)
{
  int i;
  char * url;
  
  for (i=0; i < 100; i++) {
    url = msprintf(SERVER_URI "/user/%s%d?source=" MOD_NAME, username_pattern, i);
    ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
    o_free(url);
  }
}
END_TEST

START_TEST(test_glwd_mod_user_irl_module_delete)
{
  char * url = SERVER_URI "/mod/user/" MOD_NAME;
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd user irl");
  tc_core = tcase_create("test_glwd_mod_user_irl");
  tcase_add_test(tc_core, test_glwd_mod_user_irl_module_add);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_add);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_add_error_param);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_add_already_present);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_delete_error);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_get_list);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_get);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_auth);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_update_profile);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_update_password);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_update);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_get_updated);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_delete);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_large_list_add);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_large_list_get);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_large_list_delete);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_module_delete);
  tcase_set_timeout(tc_core, 90);
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
  int res, do_test = 0;
  json_t * j_body;
  char * cookie;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  srand(time(NULL));
  j_params = json_load_file(argv[1], JSON_DECODE_ANY, NULL);
  ulfius_init_request(&admin_req);
  if (j_params != NULL) {
    // Getting a valid session id for authenticated http requests
    ulfius_init_request(&auth_req);
    ulfius_init_response(&auth_resp);
    auth_req.http_verb = strdup("POST");
    auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
    j_body = json_pack("{ssss}", "username", ADMIN_USERNAME, "password", ADMIN_PASSWORD);
    ulfius_set_json_body_request(&auth_req, j_body);
    json_decref(j_body);
    res = ulfius_send_http_request(&auth_req, &auth_resp);
    if (res == U_OK && auth_resp.status == 200) {
      if (auth_resp.nb_cookies) {
        cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
        u_map_put(admin_req.map_header, "Cookie", cookie);
        o_free(cookie);
        username = msprintf("user_irl%d", (rand()%1000));
        username_pattern = msprintf("user_irl_list_%d_", (rand()%1000));
        do_test = 1;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
    }
    ulfius_clean_response(&auth_resp);
    ulfius_clean_request(&auth_req);
    
    if (do_test) {
      s = glewlwyd_suite();
      sr = srunner_create(s);

      srunner_run_all(sr, CK_VERBOSE);
      number_failed = srunner_ntests_failed(sr);
      srunner_free(sr);
    }
    
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error reading parameters file %s", argv[1]);
  }
  json_decref(j_params);
  ulfius_clean_request(&admin_req);
  y_close_logs();
  o_free(username);
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

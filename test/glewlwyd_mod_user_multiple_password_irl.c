/* Public domain, no copyright. Use at your own risk. */

/**
 *
 * This test is used to validate one user backend module that will be created upon start and deleted after
 * The user backend must be in write mode
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"
#include "../src/glewlwyd-common.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define MOD_NAME "mod_mp"
#define NAME "Dave Lopper"
#define MAIL "dev@glewlwyd.tld"
#define SCOPE "g_profile"
#define USERNAME "user_mp"
#define PASSWORD1 "password1"
#define PASSWORD2 "password2"
#define PASSWORD3 "password3"

struct _u_request admin_req;
json_t * j_params;

START_TEST(test_glwd_mod_user_irl_module_add)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/user", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_add)
{
  json_t * j_user = json_pack("{sss[ss]sssss[s]so}", "username", USERNAME, "password", PASSWORD1, PASSWORD2, "name", NAME, "email", MAIL, "scope", SCOPE, "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user?source=" MOD_NAME, NULL, NULL, j_user, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_user);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_get)
{
  json_t * j_user = json_pack("{sssssssss[s]si}", "username", USERNAME, "name", NAME, "email", MAIL, "source", MOD_NAME, "scope", SCOPE, "password", 2);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" USERNAME "?source=" MOD_NAME, NULL, NULL, NULL, NULL, 200, j_user, NULL, NULL), 1);
  json_decref(j_user);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_auth)
{
  json_t * j_body;
  
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD2);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD3);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
}
END_TEST

START_TEST(test_glwd_mod_user_irl_profile_update_password)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  json_t * j_body, * j_profile;
  char * cookie;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD1);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_gt(auth_resp.nb_cookies, 0);
  ck_assert_ptr_ne((cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value)), NULL);
  ck_assert_int_eq(u_map_put(auth_req.map_header, "Cookie", cookie), U_OK);
  
  ulfius_clean_response(&auth_resp);
  
  j_profile = json_pack("{si}", "password", 2);
  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/profile_list/", NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD3);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "old_password", PASSWORD1, "password", PASSWORD3);
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/profile/password/", NULL, NULL, j_profile, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{sss[ss]}", "old_password", PASSWORD1, "password", PASSWORD1, PASSWORD3);
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/profile/password/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{si}", "password", 2);
  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/profile_list/", NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD3);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{sss[so]}", "old_password", PASSWORD1, "password", "", json_null());
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/profile/password/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{si}", "password", 1);
  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/profile_list/", NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD2);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD3);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{sss[sss]}", "old_password", PASSWORD1, "password", "", PASSWORD2, PASSWORD3);
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/profile/password/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{si}", "password", 3);
  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/profile_list/", NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD2);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD3);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{sss[ssoss]}", "old_password", PASSWORD1, "password", "", "", json_null(), "", "");
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/profile/password/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{si}", "password", 2);
  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/profile_list/", NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD2);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD3);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{sss[ss]}", "old_password", PASSWORD1, "password", PASSWORD1, PASSWORD2);
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/profile/password/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  ulfius_clean_request(&auth_req);
  o_free(cookie);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_admin_update_password)
{
  json_t * j_profile;

  j_profile = json_pack("{si}", "password", 2);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" USERNAME, NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD3);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{s[s]soss}", "scope", SCOPE, "enabled", json_true(), "password", PASSWORD3);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USERNAME, NULL, NULL, j_profile, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{sss[s]sos[ss]}", "name", NAME, "scope", SCOPE, "enabled", json_true(), "password", PASSWORD1, PASSWORD3);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USERNAME, NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{si}", "password", 2);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" USERNAME, NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD3);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{sss[s]sos[so]}", "name", NAME, "scope", SCOPE, "enabled", json_true(), "password", "", json_null());
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USERNAME, NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{si}", "password", 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" USERNAME, NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD2);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD3);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{sss[s]sos[sss]}", "name", NAME, "scope", SCOPE, "enabled", json_true(), "password", "", PASSWORD2, PASSWORD3);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USERNAME, NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{si}", "password", 3);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" USERNAME, NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD2);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD3);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{sss[s]sos[ssoss]}", "name", NAME, "scope", SCOPE, "enabled", json_true(), "password", "", "", json_null(), "", "");
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USERNAME, NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{si}", "password", 2);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/user/" USERNAME, NULL, NULL, NULL, NULL, 200, j_profile, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD2);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD3);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_profile, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
  j_profile = json_pack("{sss[s]sos[ss]}", "name", NAME, "scope", SCOPE, "enabled", json_true(), "password", PASSWORD1, PASSWORD2);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USERNAME, NULL, NULL, j_profile, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_profile);
  
}
END_TEST

START_TEST(test_glwd_mod_user_irl_user_delete)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/user/" USERNAME "?source=" MOD_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_module_delete)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/user/" MOD_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd mod user multiple password irl");
  tc_core = tcase_create("test_glwd_mod_user_multiple_password_irl");
  tcase_add_test(tc_core, test_glwd_mod_user_irl_module_add);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_add);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_get);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_auth);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_profile_update_password);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_admin_update_password);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_user_delete);
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
  
  j_params = json_load_file(argv[1], JSON_DECODE_ANY, NULL);
  ulfius_init_request(&admin_req);
  if (j_params != NULL) {
    // Getting a valid session id for authenticated http requests
    json_object_set_new(j_params, "name", json_string(MOD_NAME));
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
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

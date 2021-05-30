/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <check.h>

#include <orcania.h>
#include <yder.h>
#include <ulfius.h>
#include <rhonabwy.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define USER_USERNAME "user1"
#define USER_PASSWORD "password"

#define MODULE_MODULE "mock"
#define MODULE_NAME "test_mock"
#define MODULE_DISPLAY_NAME "Let's make sure forbidden schemes are forbidden"
#define MODULE_EXPIRATION 600
#define MODULE_MAX_USE 0

#define MOD_TYPE "register"
#define MOD_NAME "register"
#define MOD_DISPLAY_NAME "Register"

#define SESSION_KEY "G_REGISTER_SESSION"
#define SESSION_RESET_CREDENTIALS_KEY "G_CREDENTIALS_SESSION"
#define SESSION_DURATION 3600

#define RESET_CREDENTIALS_CODE_PROPERTY "reset-credentials-code-property"
#define RESET_CREDENTIALS_CODE_LIST_SIZE 4

#define SCOPE "g_profile"
#define SCOPE_NAME "scope2"
#define SCOPE_DISPLAY_NAME "Glewlwyd mock scope without password"
#define SCOPE_DESCRIPTION "Glewlwyd scope 2 scope description"
#define SCOPE_PASSWORD_MAX_AGE 0
#define SCOPE_SCHEME_1_TYPE "mock"
#define SCOPE_SCHEME_1_NAME "mock_scheme_95"

#define NEW_USERNAME "semias"

struct _u_request admin_req;
struct _u_request user_req;

void test_profile_access(int forbid_user_profile) {
  json_t * j_params = json_pack("{ssssss}", 
                               "username", USER_USERNAME, 
                               "scheme_type", MODULE_MODULE, 
                               "scheme_name", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_params, NULL, forbid_user_profile?403:400, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/delegate/" USER_USERNAME "/profile/scheme/register/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);

  j_params = json_pack("{sssssss{so}}", 
                       "username", USER_USERNAME, 
                       "scheme_type", MODULE_MODULE, 
                       "scheme_name", MODULE_NAME,
                       "value",
                         "register", json_true());
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_params, NULL, forbid_user_profile?403:200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  j_params = json_pack("{ssssss}", 
                       "username", USER_USERNAME, 
                       "scheme_type", MODULE_MODULE, 
                       "scheme_name", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_params, NULL, forbid_user_profile?403:200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  j_params = json_pack("{sssssss{so}}", 
                       "username", USER_USERNAME, 
                       "scheme_type", MODULE_MODULE, 
                       "scheme_name", MODULE_NAME,
                       "value",
                         "register", json_false());
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_params, NULL, forbid_user_profile?403:200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  j_params = json_pack("{ssssss}", 
                       "username", USER_USERNAME, 
                       "scheme_type", MODULE_MODULE, 
                       "scheme_name", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_params, NULL, forbid_user_profile?403:400, NULL, NULL, NULL), 1);
  json_decref(j_params);

  j_params = json_pack("{sssssss{so}}", 
                       "username", USER_USERNAME, 
                       "scheme_type", MODULE_MODULE, 
                       "scheme_name", MODULE_NAME,
                       "value",
                         "register", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/delegate/" USER_USERNAME "/profile/scheme/register/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  j_params = json_pack("{ssssss}", 
                       "username", USER_USERNAME, 
                       "scheme_type", MODULE_MODULE, 
                       "scheme_name", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/delegate/" USER_USERNAME "/profile/scheme/register/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  j_params = json_pack("{sssssss{so}}", 
                       "username", USER_USERNAME, 
                       "scheme_type", MODULE_MODULE, 
                       "scheme_name", MODULE_NAME,
                       "value",
                         "register", json_false());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/delegate/" USER_USERNAME "/profile/scheme/register/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  j_params = json_pack("{ssssss}", 
                       "username", USER_USERNAME, 
                       "scheme_type", MODULE_MODULE, 
                       "scheme_name", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/delegate/" USER_USERNAME "/profile/scheme/register/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);
}

void test_register_reset_cred_access(int forbid_user_reset_credential) {
  struct _u_request req;
  struct _u_response resp;
  int res;
  char * cookie;
  json_t * j_body = json_pack("{ss}", "username", NEW_USERNAME), * j_code;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);

  // Registration with the new username
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" MOD_NAME "/register",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_JSON_BODY, j_body,
                                                       U_OPT_NONE), U_OK);
  json_decref(j_body);
  res = ulfius_send_http_request(&req, &resp);
  ck_assert_int_eq(res, U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);
  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  ck_assert_ptr_ne(cookie, NULL);
  u_map_put(req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_response(&resp);

  // Verify get register response is 400 for scheme mock
  j_body = json_pack("{ssssss}", "scheme_name", MODULE_NAME, "scheme_type", MODULE_MODULE, "username", NEW_USERNAME);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/" MOD_NAME "/profile/scheme/register", NULL, NULL, j_body, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_body);
  j_body = json_pack("{ss ss ss s{so}}", "scheme_name", MODULE_NAME, "scheme_type", MODULE_MODULE, "username", NEW_USERNAME, "value", "register", json_true());
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" MOD_NAME "/profile/scheme/register", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  j_body = json_pack("{ssssss}", "scheme_name", MODULE_NAME, "scheme_type", MODULE_MODULE, "username", NEW_USERNAME);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/" MOD_NAME "/profile/scheme/register", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  j_body = json_pack("{sssssss{so}}", "scheme_name", MODULE_NAME, "scheme_type", MODULE_MODULE, "username", NEW_USERNAME, "value", "register", json_false());
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" MOD_NAME "/profile/scheme/register", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  // Cancel registration
  ck_assert_int_eq(run_simple_test(&req, "DELETE", SERVER_URI "/" MOD_NAME "/profile", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);

  ulfius_clean_request(&req);

  // Reset credentials
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  
  ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "PUT", U_OPT_HTTP_URL, SERVER_URI "/" MOD_NAME "/reset-credentials-code", U_OPT_HEADER_PARAMETER, "Cookie", u_map_get(user_req.map_header, "Cookie"), U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_code = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_int_eq(RESET_CREDENTIALS_CODE_LIST_SIZE, json_array_size(j_code));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  j_body = json_pack("{sssO}", "username", USER_USERNAME, "code", json_array_get(j_code, 0));
  ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST", U_OPT_HTTP_URL, SERVER_URI "/" MOD_NAME "/reset-credentials-code", U_OPT_JSON_BODY, j_body, U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  json_decref(j_body);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req);
  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  u_map_put(req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_response(&resp);

  // Test PUT profile/scheme/register endpoint
  j_body = json_pack("{ssssss}", "scheme_name", MODULE_NAME, "scheme_type", MODULE_MODULE, "username", USER_USERNAME);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/" MOD_NAME "/reset-credentials/profile/scheme/register", NULL, NULL, j_body, NULL, forbid_user_reset_credential?403:400, NULL, NULL, NULL), 1);
  json_decref(j_body);
  j_body = json_pack("{sssssss{so}}", "scheme_name", MODULE_NAME, "scheme_type", MODULE_MODULE, "username", USER_USERNAME, "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" MOD_NAME "/reset-credentials/profile/scheme/register", NULL, NULL, j_body, NULL, forbid_user_reset_credential?403:200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  j_body = json_pack("{ssssss}", "scheme_name", MODULE_NAME, "scheme_type", MODULE_MODULE, "username", USER_USERNAME);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/" MOD_NAME "/reset-credentials/profile/scheme/register", NULL, NULL, j_body, NULL, forbid_user_reset_credential?403:200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  j_body = json_pack("{sssssss{so}}", "scheme_name", MODULE_NAME, "scheme_type", MODULE_MODULE, "username", USER_USERNAME, "value", "register", json_false());
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" MOD_NAME "/reset-credentials/profile/scheme/register", NULL, NULL, j_body, NULL, forbid_user_reset_credential?403:200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ulfius_clean_request(&req);
  json_decref(j_code);
}

void add_scheme_mod(int forbid_user_profile, int forbid_user_reset_credential) {
  json_t * j_parameters = json_pack("{sssssssisisosos{ss}}", 
                                    "module", MODULE_MODULE, 
                                    "name", MODULE_NAME, 
                                    "display_name", MODULE_DISPLAY_NAME, 
                                    "expiration", MODULE_EXPIRATION, 
                                    "max_use", MODULE_MAX_USE,
                                    "forbid_user_profile", forbid_user_profile?json_true():json_false(),
                                    "forbid_user_reset_credential", forbid_user_reset_credential?json_true():json_false(),
                                    "parameters", 
                                      "mock-value", MODULE_NAME);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssisos{s[{ssss}{ssss}]}}", 
                           "display_name", SCOPE_DISPLAY_NAME,
                           "description", SCOPE_DESCRIPTION,
                           "password_max_age", SCOPE_PASSWORD_MAX_AGE,
                           "password_required", json_false(),
                           "scheme",
                             "2",
                               "scheme_type", SCOPE_SCHEME_1_TYPE,
                               "scheme_name", SCOPE_SCHEME_1_NAME,
                               "scheme_type", MODULE_MODULE,
                               "scheme_name", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/scope/" SCOPE_NAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);

  json_decref(j_parameters);

  j_parameters = json_pack("{ss ss ss so s{so so so so so si ss ss si  so ss si s[ss] ss s[{ss ss ss ss}]}}",
                           "module", MOD_TYPE,
                           "name", MOD_NAME,
                           "display_name", MOD_DISPLAY_NAME,
                           "enabled", json_true(),
                           "parameters",
                             "registration", json_true(),
                             "update-email", json_false(),
                             "reset-credentials", json_true(),
                             "reset-credentials-email", json_false(),
                             "reset-credentials-code", json_true(),
                             "reset-credentials-session-duration", SESSION_DURATION,
                             "reset-credentials-session-key", SESSION_RESET_CREDENTIALS_KEY,
                             "reset-credentials-code-property", RESET_CREDENTIALS_CODE_PROPERTY,
                             "reset-credentials-code-list-size", RESET_CREDENTIALS_CODE_LIST_SIZE,
                             
                             "verify-email", json_false(),
                             "session-key", SESSION_KEY,
                             "session-duration", SESSION_DURATION,
                             "scope",
                               SCOPE,
                               SCOPE_NAME,
                             "set-password", "no",
                             "schemes",
                               "module", MODULE_MODULE,
                               "name", MODULE_NAME,
                               "register", "always",
                               "display_name", MODULE_DISPLAY_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}

START_TEST(test_glwd_http_forbidden_scheme_scope_set_false_false)
{
  add_scheme_mod(0, 0);
}
END_TEST

START_TEST(test_glwd_http_forbidden_scheme_test_access_false_false)
{
  test_profile_access(0);
  test_register_reset_cred_access(0);
}
END_TEST

START_TEST(test_glwd_http_forbidden_scheme_scope_set_true_false)
{
  add_scheme_mod(1, 0);
}
END_TEST

START_TEST(test_glwd_http_forbidden_scheme_test_access_true_false)
{
  test_profile_access(1);
  test_register_reset_cred_access(0);
}
END_TEST

START_TEST(test_glwd_http_forbidden_scheme_scope_set_false_true)
{
  add_scheme_mod(0, 1);
}
END_TEST

START_TEST(test_glwd_http_forbidden_scheme_test_access_false_true)
{
  test_profile_access(0);
  test_register_reset_cred_access(1);
}
END_TEST

START_TEST(test_glwd_http_forbidden_scheme_scope_set_true_true)
{
  add_scheme_mod(1, 1);
}
END_TEST

START_TEST(test_glwd_http_forbidden_scheme_test_access_true_true)
{
  test_profile_access(1);
  test_register_reset_cred_access(1);
}
END_TEST

START_TEST(test_glwd_http_forbidden_scheme_scope_unset)
{
  json_t * j_parameters = json_pack("{sssssisos{s[{ssss}]}}", 
                                    "display_name", SCOPE_DISPLAY_NAME,
                                    "description", SCOPE_DESCRIPTION,
                                    "password_max_age", SCOPE_PASSWORD_MAX_AGE,
                                    "password_required", json_false(),
                                    "scheme",
                                      "2",
                                        "scheme_type", SCOPE_SCHEME_1_TYPE,
                                        "scheme_name", SCOPE_SCHEME_1_NAME);

  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/scope/" SCOPE_NAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/scheme/" MODULE_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" MOD_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  
  json_decref(j_parameters);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc forbidden scheme");
  tc_core = tcase_create("test_oidc_forbidden_scheme");
  tcase_add_test(tc_core, test_glwd_http_forbidden_scheme_scope_set_false_false);
  tcase_add_test(tc_core, test_glwd_http_forbidden_scheme_test_access_false_false);
  tcase_add_test(tc_core, test_glwd_http_forbidden_scheme_scope_unset);
  tcase_add_test(tc_core, test_glwd_http_forbidden_scheme_scope_set_true_false);
  tcase_add_test(tc_core, test_glwd_http_forbidden_scheme_test_access_true_false);
  tcase_add_test(tc_core, test_glwd_http_forbidden_scheme_scope_unset);
  tcase_add_test(tc_core, test_glwd_http_forbidden_scheme_scope_set_false_true);
  tcase_add_test(tc_core, test_glwd_http_forbidden_scheme_test_access_false_true);
  tcase_add_test(tc_core, test_glwd_http_forbidden_scheme_scope_unset);
  tcase_add_test(tc_core, test_glwd_http_forbidden_scheme_scope_set_true_true);
  tcase_add_test(tc_core, test_glwd_http_forbidden_scheme_test_access_true_true);
  tcase_add_test(tc_core, test_glwd_http_forbidden_scheme_scope_unset);
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
  int res, do_test = 0;
  json_t * j_body;
  char * cookie;

  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");

  ulfius_init_request(&admin_req);
  ulfius_init_request(&user_req);

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
      y_log_message(Y_LOG_LEVEL_DEBUG, "Admin %s authenticated", ADMIN_USERNAME);
      cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
      u_map_put(admin_req.map_header, "Cookie", cookie);
      o_free(cookie);
      do_test = 1;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication admin");
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);

  if (do_test) {
    // Getting a valid session id for authenticated http requests
    ulfius_init_request(&auth_req);
    ulfius_init_response(&auth_resp);
    auth_req.http_verb = strdup("POST");
    auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
    j_body = json_pack("{ssss}", "username", USER_USERNAME, "password", USER_PASSWORD);
    ulfius_set_json_body_request(&auth_req, j_body);
    json_decref(j_body);
    res = ulfius_send_http_request(&auth_req, &auth_resp);
    if (res == U_OK && auth_resp.status == 200) {
      if (auth_resp.nb_cookies) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "User %s authenticated", USER_USERNAME);
        cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
        u_map_put(user_req.map_header, "Cookie", cookie);
        o_free(cookie);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication user");
      do_test = 0;
    }
    ulfius_clean_response(&auth_resp);
    ulfius_clean_request(&auth_req);
  }

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }

  run_simple_test(&user_req, "DELETE", SERVER_URI "/auth/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);

  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

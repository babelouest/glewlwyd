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

#define SERVER_URI "http://localhost:4593/api/"
#define USERNAME "user1"
#define PASSWORD "password"
#define SCHEME_TYPE "mock"
#define SCHEME_NAME "mock_scheme_42"
#define SCHEME_VALUE "42"
#define MODULE_MODULE "mock"
#define MODULE_NAME "test"
#define MODULE_DISPLAY_NAME "test name"
#define NEW_CLIENT_ID "test"
#define NEW_CLIENT_NAME "Client 1"
#define NEW_DESCRIPTION "Description for Client 1"
#define NEW_SCOPE_1 "scope1"
#define NEW_SCOPE_2 "scope2"
#define SCOPE_NAME "My New Scope"
#define DESCRIPTION "Description for test-scope"
#define GROUP1 "group1"
#define GROUP1_DESC "Group1 description"
#define GROUP2 "group2"
#define GROUP2_DESC "Group2 description"
#define SCHEME1 "mock_scheme_42"
#define SCHEME2 "mock_scheme_88"
#define SCHEME3 "mock_scheme_95"
#define NEW_USERNAME "test"
#define NEW_NAME "Dave Lopper"
#define NEW_EMAIL "test@glewlwyd"
#define NEW_SCOPE_1 "scope1"
#define NEW_SCOPE_2 "scope2"

struct _u_request user_req;

START_TEST(test_glwd_admin_check_scope_delegate)
{
  json_t * j_body;
  
  j_body = json_pack("{ss}", "name", "new name");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/delegate/" USERNAME "/profile/", NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/delegate/" USERNAME "/profile/session", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/delegate/" USERNAME "/profile/plugin", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "DELETE", SERVER_URI "/delegate/" USERNAME "/profile/session/my_session", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/delegate/" USERNAME "/profile/scheme", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", SCHEME_TYPE, "scheme_name", SCHEME_NAME, "value", "code", SCHEME_VALUE);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/delegate/" USERNAME "/profile/scheme/register/", NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/delegate/" USERNAME "/profile/scheme/register/", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_admin_check_scope_mod_user)
{
  json_t * j_body;
  
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/mod/user", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/mod/user/mock", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  j_body = json_pack("{sssssssisos{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "order_rank", 0, "readonly", json_false(), "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/mod/user", NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{sssisos{ss}}", "display_name", MODULE_DISPLAY_NAME, "order_rank", 0, "readonly", json_false(), "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/mod/user/" MODULE_NAME, NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ck_assert_int_eq(run_simple_test(&user_req, "DELETE", SERVER_URI "/mod/user/" MODULE_NAME, NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/mod/user/" MODULE_NAME "/enable", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/mod/user/" MODULE_NAME "/disable", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_admin_check_scope_mod_client)
{
  json_t * j_body;
  
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/mod/client", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/mod/client/mock", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  j_body = json_pack("{sssssssisos{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "order_rank", 0, "readonly", json_false(), "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/mod/client", NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{sssisos{ss}}", "display_name", MODULE_DISPLAY_NAME, "order_rank", 0, "readonly", json_false(), "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/mod/client/" MODULE_NAME, NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ck_assert_int_eq(run_simple_test(&user_req, "DELETE", SERVER_URI "/mod/client/" MODULE_NAME, NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/mod/client/" MODULE_NAME "/enable", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/mod/client/" MODULE_NAME "/disable", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_admin_check_scope_mod_scheme)
{
  json_t * j_body;
  
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/mod/scheme", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/mod/scheme/mock", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  j_body = json_pack("{sssssssisisos{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "expiration", 600, "max_use", 0, "allow_user_register", json_true(), "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/mod/scheme", NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{sssisisos{ss}}", "display_name", MODULE_DISPLAY_NAME, "expiration", 600, "max_use", 0, "allow_user_register", json_true(), "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/mod/scheme/" MODULE_NAME, NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ck_assert_int_eq(run_simple_test(&user_req, "DELETE", SERVER_URI "/mod/scheme/" MODULE_NAME, NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/mod/scheme/" MODULE_NAME "/enable", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/mod/scheme/" MODULE_NAME "/disable", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_admin_check_scope_mod_plugin)
{
  json_t * j_body;
  
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/mod/plugin", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/mod/plugin/mock", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  j_body = json_pack("{sssssss{ss}}", "module", MODULE_MODULE, "name", MODULE_NAME, "display_name", MODULE_DISPLAY_NAME, "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/mod/plugin", NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{sss{ss}}", "display_name", MODULE_DISPLAY_NAME, "parameters", "mock-value", MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/mod/plugin/" MODULE_NAME, NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ck_assert_int_eq(run_simple_test(&user_req, "DELETE", SERVER_URI "/mod/plugin/" MODULE_NAME, NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/mod/plugin/" MODULE_NAME "/enable", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/mod/plugin/" MODULE_NAME "/disable", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_admin_check_scope_user)
{
  json_t * j_body;
  
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/user", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/user/user1", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  j_body = json_pack("{sssssss[ss]}", "username", NEW_USERNAME, "name", NEW_NAME, "email", NEW_EMAIL, "scope", NEW_SCOPE_1, NEW_SCOPE_2);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/user", NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{sssss[ss]}", "name", NEW_NAME, "email", NEW_EMAIL, "scope", NEW_SCOPE_1, NEW_SCOPE_2);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ck_assert_int_eq(run_simple_test(&user_req, "DELETE", SERVER_URI "/user/" NEW_USERNAME, NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_admin_check_scope_client)
{
  json_t * j_body;
  
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/user", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/user/user1", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  j_body = json_pack("{ssssss}", "client_id", NEW_CLIENT_ID, "name", NEW_CLIENT_NAME, "description", NEW_DESCRIPTION);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/user", NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{ssss}", "name", NEW_CLIENT_NAME, "description", NEW_DESCRIPTION);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/user/" NEW_CLIENT_ID, NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ck_assert_int_eq(run_simple_test(&user_req, "DELETE", SERVER_URI "/user/" NEW_CLIENT_ID, NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_admin_check_scope_scope)
{
  json_t * j_body;
  
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/scope", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/scope/scope1", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  j_body = json_pack("{ss ss ss so s{s[{ssssss}]}}", "name", SCOPE_NAME, "display_name", SCOPE_NAME, "description", DESCRIPTION, "password_required", json_true(), "scheme", GROUP1, "scheme_name", SCHEME1, "scheme_display_name", "Mock 42", "scheme_type", "mock");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/scope", NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  j_body = json_pack("{ss ss so s{s[{ssssss}]}}", "display_name", SCOPE_NAME, "description", DESCRIPTION, "password_required", json_true(), "scheme", GROUP1, "scheme_name", SCHEME1, "scheme_display_name", "Mock 42", "scheme_type", "mock");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/scope/" SCOPE_NAME, NULL, NULL, j_body, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ck_assert_int_eq(run_simple_test(&user_req, "DELETE", SERVER_URI "/scope/" SCOPE_NAME, NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd admin check scope credentials");
  tc_core = tcase_create("test_glwd_admin_check_scope");
  tcase_add_test(tc_core, test_glwd_admin_check_scope_delegate);
  tcase_add_test(tc_core, test_glwd_admin_check_scope_mod_user);
  tcase_add_test(tc_core, test_glwd_admin_check_scope_mod_client);
  tcase_add_test(tc_core, test_glwd_admin_check_scope_mod_scheme);
  tcase_add_test(tc_core, test_glwd_admin_check_scope_mod_plugin);
  tcase_add_test(tc_core, test_glwd_admin_check_scope_user);
  tcase_add_test(tc_core, test_glwd_admin_check_scope_client);
  tcase_add_test(tc_core, test_glwd_admin_check_scope_scope);
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
  json_t * j_body;
  int res, do_test = 0, i;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200 && auth_resp.nb_cookies) {
    for (i=0; i<auth_resp.nb_cookies; i++) {
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(user_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    do_test = 1;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
  }
  ulfius_clean_response(&auth_resp);

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&user_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

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

struct _u_request admin_req;
json_t * j_params;

START_TEST(test_oauth2_irl_user_module_add)
{
  char * url = SERVER_URI "/mod/user";
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, json_object_get(j_params, "user_mod"), NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oauth2_irl_client_module_add)
{
  char * url = SERVER_URI "/mod/client";
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, json_object_get(j_params, "client_mod"), NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oauth2_irl_user_add)
{
  if (json_object_get(j_params, "user_add") == json_true()) {
    char * url = msprintf(SERVER_URI "/user?source=%s", json_string_value(json_object_get(json_object_get(j_params, "user_mod"), "name")));
    ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, json_object_get(j_params, "user"), NULL, 200, NULL, NULL, NULL), 1);
    o_free(url);
  }
}
END_TEST

START_TEST(test_oauth2_irl_client_add)
{
  if (json_object_get(j_params, "client_add") == json_true()) {
    char * url = msprintf(SERVER_URI "/client?source=%s", json_string_value(json_object_get(json_object_get(j_params, "client_mod"), "name")));
    ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, json_object_get(j_params, "client"), NULL, 200, NULL, NULL, NULL), 1);
    o_free(url);
  }
}
END_TEST

START_TEST(test_oauth2_irl_run_workflow)
{
  struct _u_request auth_req;
  struct _u_response auth_resp, resp;
  struct _u_map body;
  json_t * j_body, * j_register, * j_element;
  char * cookie;
  size_t index;
  const char * username = json_string_value(json_object_get(json_object_get(j_params, "user"), "username")),
             * password = json_string_value(json_object_get(json_object_get(j_params, "user"), "password")),
             * client_id = json_string_value(json_object_get(json_object_get(j_params, "client"), "client_id")),
             * client_password = json_string_value(json_object_get(json_object_get(j_params, "client"), "password"));
  char * url, * redirect_uri_encoded, * scope = NULL, * code;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", username, "password", password);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_gt(auth_resp.nb_cookies, 0);
  ck_assert_ptr_ne((cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value)), NULL);
  ck_assert_int_eq(u_map_put(auth_req.map_header, "Cookie", cookie), U_OK);
  
  ulfius_clean_response(&auth_resp);
  
  json_array_foreach(json_object_get(j_params, "schemes"), index, j_element) {
    j_register = json_pack("{ss ss ss sO}", 
                          "username", username, 
                          "scheme_type", json_string_value(json_object_get(j_element, "scheme_type")), 
                          "scheme_name", json_string_value(json_object_get(j_element, "scheme_name")), 
                          "value", json_object_get(j_element, "register"));
    ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
    json_decref(j_register);
  }

  json_array_foreach(json_object_get(j_params, "schemes"), index, j_element) {
    j_register = json_pack("{ss ss ss sO}", 
                          "username", username, 
                          "scheme_type", json_string_value(json_object_get(j_element, "scheme_type")), 
                          "scheme_name", json_string_value(json_object_get(j_element, "scheme_name")), 
                          "value", json_object_get(j_element, "value"));
    ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/auth/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
    json_decref(j_register);
  }

  json_array_foreach(json_object_get(json_object_get(j_params, "user"), "scope"), index, j_element) {
    if (scope == NULL) {
      scope = o_strdup(json_string_value(j_element));
    } else {
      scope = mstrcatf(scope, " %s", json_string_value(j_element));
    }
  }
  
  url = msprintf("%s/auth/grant/%s", SERVER_URI, json_string_value(json_object_get(json_object_get(j_params, "client"), "client_id")));
  j_body = json_pack("{ss}", "scope", scope);
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", url, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  o_free(url);

  // Test implicit framework
  redirect_uri_encoded = ulfius_url_encode(json_string_value(json_array_get(json_object_get(json_object_get(j_params, "client"), "redirect_uri"), 0)));
  url = msprintf("%s/glwd/auth?response_type=token&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&scope=%s", SERVER_URI, json_string_value(json_object_get(json_object_get(j_params, "client"), "client_id")), redirect_uri_encoded, scope);
  ck_assert_int_eq(run_simple_test(&auth_req, "GET", url, client_id, client_password, NULL, NULL, 302, NULL, NULL, "token="), 1);
  o_free(url);
  
  // Test code framework
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_url = msprintf("%s/glwd/auth?response_type=code&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&scope=%s", SERVER_URI, json_string_value(json_object_get(json_object_get(j_params, "client"), "client_id")), redirect_uri_encoded, scope);
  auth_req.http_verb = o_strdup("GET");
  auth_req.auth_basic_user = o_strdup(client_id);
  auth_req.auth_basic_password = o_strdup(client_password);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  url = msprintf("%s/glwd/token/", SERVER_URI);
  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "client_id", json_string_value(json_object_get(json_object_get(j_params, "client"), "client_id")));
  u_map_put(&body, "redirect_uri", json_string_value(json_array_get(json_object_get(json_object_get(j_params, "client"), "redirect_uri"), 0)));
  u_map_put(&body, "code", code);

  ck_assert_int_eq(run_simple_test(NULL, "POST", url, client_id, client_password, NULL, &body, 200, NULL, "refresh_token", NULL), 1);
  u_map_clean(&body);
  ulfius_clean_response(&resp);
  o_free(url);

  // Test password framework
  url = msprintf("%s/glwd/token/", SERVER_URI);
  u_map_init(&body);
  u_map_put(&body, "grant_type", "password");
  u_map_put(&body, "scope", scope);
  u_map_put(&body, "username", username);
  u_map_put(&body, "password", password);

  ck_assert_int_eq(run_simple_test(NULL, "POST", url, client_id, client_password, NULL, &body, 200, NULL, NULL, NULL), 1);
  u_map_clean(&body);

  o_free(code);
  o_free(url);
  o_free(redirect_uri_encoded);
  o_free(scope);
  
  json_array_foreach(json_object_get(j_params, "schemes"), index, j_element) {
    j_register = json_pack("{ss ss ss sO}", 
                          "username", username, 
                          "scheme_type", json_string_value(json_object_get(j_element, "scheme_type")), 
                          "scheme_name", json_string_value(json_object_get(j_element, "scheme_name")), 
                          "value", json_object_get(j_element, "deregister"));
    ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
    json_decref(j_register);
  }
  
  ulfius_clean_request(&auth_req);
  o_free(cookie);
}
END_TEST

START_TEST(test_oauth2_irl_user_delete)
{
  if (json_object_get(j_params, "user_add") == json_true()) {
    char * url = msprintf(SERVER_URI "/user/%s?source=%s", json_string_value(json_object_get(json_object_get(j_params, "user"), "username")), json_string_value(json_object_get(json_object_get(j_params, "user_mod"), "name")));
    ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
    o_free(url);
  }
}
END_TEST

START_TEST(test_oauth2_irl_client_delete)
{
  if (json_object_get(j_params, "user_add") == json_true()) {
    char * url = msprintf(SERVER_URI "/client/%s?source=%s", json_string_value(json_object_get(json_object_get(j_params, "client"), "client_id")), json_string_value(json_object_get(json_object_get(j_params, "client_mod"), "name")));
    ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
    o_free(url);
  }
}
END_TEST

START_TEST(test_oauth2_irl_user_module_delete)
{
  char * url = msprintf(SERVER_URI "/mod/user/%s", json_string_value(json_object_get(json_object_get(j_params, "user_mod"), "name")));
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_oauth2_irl_client_module_delete)
{
  char * url = msprintf(SERVER_URI "/mod/client/%s", json_string_value(json_object_get(json_object_get(j_params, "client_mod"), "name")));
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oauth2 irl");
  tc_core = tcase_create("test_oauth2_irl");
  tcase_add_test(tc_core, test_oauth2_irl_user_module_add);
  tcase_add_test(tc_core, test_oauth2_irl_client_module_add);
  tcase_add_test(tc_core, test_oauth2_irl_user_add);
  tcase_add_test(tc_core, test_oauth2_irl_client_add);
  tcase_add_test(tc_core, test_oauth2_irl_run_workflow);
  tcase_add_test(tc_core, test_oauth2_irl_user_delete);
  tcase_add_test(tc_core, test_oauth2_irl_client_delete);
  tcase_add_test(tc_core, test_oauth2_irl_user_module_delete);
  tcase_add_test(tc_core, test_oauth2_irl_client_module_delete);
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
    ulfius_init_request(&auth_req);
    ulfius_init_response(&auth_resp);
    auth_req.http_verb = strdup("POST");
    auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
    j_body = json_pack("{ssss}", "username", ADMIN_USERNAME, "password", ADMIN_PASSWORD);
    ulfius_set_json_body_request(&auth_req, j_body);
    json_decref(j_body);
    res = ulfius_send_http_request(&auth_req, &auth_resp);
    if (res == U_OK && auth_resp.status == 200 && auth_resp.nb_cookies) {
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

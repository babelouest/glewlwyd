/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>
#include <jwt.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define CLIENT "client1_id"

#define HOST   "localhost"
#define PORT   2884
#define PREFIX "/auth"

#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define HTTP_USER     "httpuser1"
#define HTTP_PASSWORD "http_user_password"

#define MOD_NAME "mod_irl"

char * host = NULL;

struct _u_request user_req, admin_req;
char * code;

/**
 * Auth function for basic authentication
 */
int auth_basic (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (request->auth_basic_user != NULL && 
      request->auth_basic_password != NULL) {
    if (0 == o_strcmp(request->auth_basic_user, HTTP_USER) && 
        0 == o_strcmp(request->auth_basic_password, HTTP_PASSWORD)) {
      return U_CALLBACK_CONTINUE;
    } else {
      return U_CALLBACK_UNAUTHORIZED;
    }
  } else {
    return U_CALLBACK_UNAUTHORIZED;
  }
}

START_TEST(test_glwd_mod_user_irl_module_add)
{
  char * param_url;
  if (host == NULL) {
    param_url = msprintf("http://%s:%d/auth/", HOST, PORT);
  } else {
    param_url = msprintf("http://%s:%d/auth/", host, PORT);
  }
  json_t * j_params = json_pack("{sssssssis{sssos[ss]}}", "module", "http", "name", "mod_irl", "display_name", "HTTP", "order_rank", 1, "parameters", "url", param_url, "check-server-certificate", json_true(), "default-scope", "g_profile", "scope1");
  char * url = SERVER_URI "/mod/user";
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  o_free(param_url);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_http_auth_success)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  json_t * j_body, * j_register;
  char * cookie;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", HTTP_USER, "password", HTTP_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_gt(auth_resp.nb_cookies, 0);
  ck_assert_ptr_ne((cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value)), NULL);
  ck_assert_int_eq(u_map_put(auth_req.map_header, "Cookie", cookie), U_OK);
  
  ulfius_clean_response(&auth_resp);
  
  ulfius_init_response(&auth_resp);
  
  j_register = json_pack("{sssssss{so}}", "username", HTTP_USER, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
  j_register = json_pack("{sssssss{so}}", "username", HTTP_USER, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
  j_body = json_pack("{sssssss{ss}}", "username", HTTP_USER, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  
  ulfius_clean_response(&auth_resp);
  ulfius_init_response(&auth_resp);
  
  j_body = json_pack("{sssssss{ss}}", "username", HTTP_USER, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  
  j_register = json_pack("{sssssss{so}}", "username", HTTP_USER, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_false());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
  j_register = json_pack("{sssssss{so}}", "username", HTTP_USER, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_false());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);
  
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);
  o_free(cookie);
}
END_TEST

START_TEST(test_glwd_mod_user_irl_http_auth_fail)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  json_t * j_body;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", HTTP_USER, "password", "invalid");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ulfius_send_http_request(&auth_req, &auth_resp);
  ck_assert_int_eq(auth_resp.status, 401);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
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

  s = suite_create("Glewlwyd HTTP Auth");
  tc_core = tcase_create("test_glwd_http_auth");
  tcase_add_test(tc_core, test_glwd_mod_user_irl_module_add);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_http_auth_success);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_http_auth_fail);
  tcase_add_test(tc_core, test_glwd_mod_user_irl_module_delete);
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
  struct _u_instance instance;
  int res, do_test = 0;
  json_t * j_body;
  char * cookie;
  
  if (argc > 1) {
    host = argv[1];
  }
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  if (ulfius_init_instance(&instance, PORT, NULL, "auth_basic_default") != U_OK) {
    y_log_message(Y_LOG_LEVEL_INFO, "Error ulfius_init_instance, abort");
    return(1);
  }
  ulfius_add_endpoint_by_val(&instance, "GET", PREFIX, NULL, 0, &auth_basic, "auth param");
  if (ulfius_start_framework(&instance) == U_OK) {
    y_log_message(Y_LOG_LEVEL_INFO, "Start framework on port %d", instance.port);
  } else {
    y_log_message(Y_LOG_LEVEL_INFO, "Error starting framework");
  }
  
  ulfius_init_request(&admin_req);
  
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
    
  ulfius_clean_request(&admin_req);
  y_close_logs();
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

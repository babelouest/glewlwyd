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
#define USERNAME "user1"
#define PASSWORD "password"
#define USERNAME_ADMIN "admin"
#define PASSWORD_ADMIN "password"
#define SCOPE_LIST "g_profile scope3"
#define CLIENT "client3_id"
#define CLIENT_PASSWORD "password"
#define CLIENT_SECRET "secret"

struct _u_request admin_req;

START_TEST(test_oauth2_client_secret_client_secret_client_set_ok)
{
  json_t * j_parameters = json_pack("{ss}", "client_secret", CLIENT_SECRET);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/client/" CLIENT, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);

  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oauth2_client_secret_resource_owner_pwd_cred_valid_secret)
{
  char * url = msprintf("%s/glwd/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "password");
  u_map_put(&body, "scope", SCOPE_LIST);
  u_map_put(&body, "username", USERNAME);
  u_map_put(&body, "password", PASSWORD);

  ck_assert_int_eq(run_simple_test(NULL, "POST", url, CLIENT, CLIENT_SECRET, NULL, &body, 200, NULL, "refresh_token", NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", url, CLIENT, CLIENT_PASSWORD, NULL, &body, 400, NULL, NULL, NULL), 1);
  o_free(url);
  u_map_clean(&body);
}
END_TEST

START_TEST(test_oauth2_client_secret_resource_owner_pwd_cred_valid_password)
{
  char * url = msprintf("%s/glwd/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "password");
  u_map_put(&body, "scope", SCOPE_LIST);
  u_map_put(&body, "username", USERNAME);
  u_map_put(&body, "password", PASSWORD);

  ck_assert_int_eq(run_simple_test(NULL, "POST", url, CLIENT, CLIENT_PASSWORD, NULL, &body, 200, NULL, "refresh_token", NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", url, CLIENT, CLIENT_SECRET, NULL, &body, 400, NULL, NULL, NULL), 1);
  o_free(url);
  u_map_clean(&body);
}
END_TEST

START_TEST(test_oauth2_client_secret_client_secret_client_disable_ok)
{
  json_t * j_parameters = json_pack("{ss}", "client_secret", "");
  
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/client/" CLIENT, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);

  json_decref(j_parameters);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oauth2 code client confidential");
  tc_core = tcase_create("test_oauth2_client_secret");
  tcase_add_test(tc_core, test_oauth2_client_secret_resource_owner_pwd_cred_valid_password);
  tcase_add_test(tc_core, test_oauth2_client_secret_client_secret_client_set_ok);
  tcase_add_test(tc_core, test_oauth2_client_secret_resource_owner_pwd_cred_valid_secret);
  tcase_add_test(tc_core, test_oauth2_client_secret_client_secret_client_disable_ok);
  tcase_add_test(tc_core, test_oauth2_client_secret_resource_owner_pwd_cred_valid_password);
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
  json_t * j_body;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&admin_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME_ADMIN, "password", PASSWORD_ADMIN);
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
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

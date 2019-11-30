/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <liboath/oath.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api/"
#define USERNAME "user1"
#define PASSWORD "password"
#define SCOPE_LIST "scope1 scope2"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define MODULE_MODULE "retype-password"
#define MODULE_NAME "test_rp"
#define MODULE_DISPLAY_NAME "Retype password scheme for test"
#define MODULE_EXPIRATION 600
#define MODULE_MAX_USE 0

struct _u_request user_req;
struct _u_request admin_req;

START_TEST(test_glwd_scheme_retype_password_irl_module_add)
{
  char * url = msprintf("%s/mod/scheme/", SERVER_URI);
  json_t * j_parameters = json_pack("{sssssssisis{}}", 
                                    "module", MODULE_MODULE, 
                                    "name", MODULE_NAME, 
                                    "display_name", MODULE_DISPLAY_NAME, 
                                    "expiration", MODULE_EXPIRATION, 
                                    "max_use", MODULE_MAX_USE, 
                                    "parameters");
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
  
  url = msprintf("%s/mod/scheme/%s", SERVER_URI, MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_retype_password_irl_authenticate_error)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                 "password", "error");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
}
END_TEST

START_TEST(test_glwd_scheme_retype_password_irl_authenticate_success)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                 "password", PASSWORD);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
}
END_TEST

START_TEST(test_glwd_scheme_retype_password_irl_module_remove)
{
  char * url = msprintf("%s/mod/scheme/%s", SERVER_URI, MODULE_NAME);

  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd scheme retype password");
  tc_core = tcase_create("test_glwd_scheme_retype_password_irl");
  tcase_add_test(tc_core, test_glwd_scheme_retype_password_irl_module_add);
  tcase_add_test(tc_core, test_glwd_scheme_retype_password_irl_authenticate_error);
  tcase_add_test(tc_core, test_glwd_scheme_retype_password_irl_authenticate_success);
  tcase_add_test(tc_core, test_glwd_scheme_retype_password_irl_module_remove);
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
  
  oath_init();
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&user_req);
  ulfius_init_request(&admin_req);
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
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
  ulfius_clean_request(&auth_req);

  ulfius_init_request(&auth_req);
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
    }
    do_test = 1;
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
  
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&admin_req);
  
  y_close_logs();
  oath_done();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

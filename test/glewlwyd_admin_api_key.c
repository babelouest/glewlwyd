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
#define PASSWORD "password"

struct _u_request admin_req;

START_TEST(test_glwd_admin_api_key_add)
{
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/key", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/key", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/key", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/key", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "DELETE", SERVER_URI "/key/fake", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/key/fake", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_admin_api_key_use)
{
  struct _u_request req, req_api;
  struct _u_response resp;
  json_t * j_body;
  char * header;
  
  ulfius_init_request(&req);
  ulfius_init_request(&req_api);
  
  ulfius_copy_request(&req, &admin_req);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST", U_OPT_HTTP_URL, SERVER_URI "/key", U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_body, "key")), 0);
  header = msprintf("token %s", json_string_value(json_object_get(j_body, "key")));
  json_decref(j_body);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_set_request_properties(&req_api, U_OPT_HEADER_PARAMETER, "Authorization", header, U_OPT_NONE), U_OK);
  
  ck_assert_int_eq(run_simple_test(&req_api, "GET", SERVER_URI "/mod/type", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&req_api, "GET", SERVER_URI "/user", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&req_api, "GET", SERVER_URI "/client", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&req_api, "GET", SERVER_URI "/scope", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&req_api, "GET", SERVER_URI "/key", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  
  o_free(header);
  ulfius_clean_request(&req);
  ulfius_clean_request(&req_api);
}
END_TEST

START_TEST(test_glwd_admin_api_key_disable)
{
  struct _u_request req, req_api;
  struct _u_response resp;
  json_t * j_body;
  char * header, * url;
  
  ulfius_init_request(&req);
  ulfius_init_request(&req_api);
  
  ulfius_copy_request(&req, &admin_req);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST", U_OPT_HTTP_URL, SERVER_URI "/key", U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_body, "key")), 0);
  header = msprintf("token %s", json_string_value(json_object_get(j_body, "key")));
  json_decref(j_body);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_set_request_properties(&req_api, U_OPT_HEADER_PARAMETER, "Authorization", header, U_OPT_NONE), U_OK);
  
  ck_assert_int_eq(run_simple_test(&req_api, "GET", SERVER_URI "/mod/type", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  url = msprintf(SERVER_URI "/key/%s", json_string_value(json_object_get(json_array_get(j_body, json_array_size(j_body)-1), "token_hash")));
  ck_assert_int_eq(run_simple_test(&req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&req_api, "GET", SERVER_URI "/mod/type", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_body);
  ulfius_clean_response(&resp);

  o_free(header);
  o_free(url);
  ulfius_clean_request(&req);
  ulfius_clean_request(&req_api);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd admin API key");
  tc_core = tcase_create("test_glwd_admin_api_key");
  tcase_add_test(tc_core, test_glwd_admin_api_key_add);
  tcase_add_test(tc_core, test_glwd_admin_api_key_use);
  tcase_add_test(tc_core, test_glwd_admin_api_key_disable);
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
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
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

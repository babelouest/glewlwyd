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
#define PLUGIN_NAME "oidc_iss_id"
#define SCOPE_LIST "openid"
#define CLIENT_ID "client3_id"
#define CLIENT_SECRET "password"
#define CLIENT_REDIRECT_URI "../../test-oidc.html?param=client3"
#define CLIENT_REDIRECT_URI_ENCODED "..%2F..%2Ftest-oidc.html%3Fparam%3Dclient3"
#define RESPONSE_TYPE_CODE "code"
#define RESPONSE_TYPE_CODE_ID_TOKEN "code+id_token"
#define ISS "https://glewlwyd.tld"
#define ISS_ESCAPED "https%3A%2F%2Fglewlwyd.tld"

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_oidc_auth_iss_id_add_plugin)
{
  json_t * j_param = json_pack("{sssssss{sssosssssssisisisososososososososo}}",
                                "module", "oidc",
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "iss", ISS,
                                  "oauth-as-iss-id", json_true(),
                                  "jwt-type", "sha",
                                  "jwt-key-size", "256",
                                  "key", "secret_" PLUGIN_NAME,
                                  "access-token-duration", 3600,
                                  "refresh-token-duration", 1209600,
                                  "code-duration", 600,
                                  "refresh-token-rolling", json_true(),
                                  "allow-non-oidc", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-code-revoke-replayed", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-id-token-enabled", json_true(),
                                  "auth-type-password-enabled", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_auth_iss_id_add_plugin_no)
{
  json_t * j_param = json_pack("{sssssss{sssosssssssisisisososososososososo}}",
                                "module", "oidc",
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "iss", ISS,
                                  "oauth-as-iss-id", json_false(),
                                  "jwt-type", "sha",
                                  "jwt-key-size", "256",
                                  "key", "secret_" PLUGIN_NAME,
                                  "access-token-duration", 3600,
                                  "refresh-token-duration", 1209600,
                                  "code-duration", 600,
                                  "refresh-token-rolling", json_true(),
                                  "allow-non-oidc", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-code-revoke-replayed", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-id-token-enabled", json_true(),
                                  "auth-type-password-enabled", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_auth_iss_id_delete_plugin)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_auth_iss_id_code)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "GET", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=" RESPONSE_TYPE_CODE "&nonce=nonce1234&client_id=" CLIENT_ID "&redirect_uri=" CLIENT_REDIRECT_URI_ENCODED "&scope=" SCOPE_LIST "&g_continue", 
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "iss=" ISS_ESCAPED), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_auth_iss_id_code_id_token)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "GET", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=" RESPONSE_TYPE_CODE_ID_TOKEN "&nonce=nonce1234&client_id=" CLIENT_ID "&redirect_uri=" CLIENT_REDIRECT_URI_ENCODED "&scope=" SCOPE_LIST "&g_continue", 
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "iss=" ISS_ESCAPED), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_auth_iss_id_response_type_error)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "GET", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=" "error" "&nonce=nonce1234&client_id=" CLIENT_ID "&redirect_uri=" CLIENT_REDIRECT_URI_ENCODED "&scope=" SCOPE_LIST "&g_continue", 
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "iss=" ISS_ESCAPED), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_auth_iss_id_client_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "GET", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=" RESPONSE_TYPE_CODE "&nonce=nonce1234&client_id=" "error" "&redirect_uri=" CLIENT_REDIRECT_URI_ENCODED "&scope=" SCOPE_LIST "&g_continue", 
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_auth_iss_id_redirect_uri_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "GET", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=" RESPONSE_TYPE_CODE "&nonce=nonce1234&client_id=" CLIENT_ID "&redirect_uri=" "https%3a%2f%2ferror.org" "&scope=" SCOPE_LIST "&g_continue", 
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_auth_iss_id_code_iss_no)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
      U_OPT_HTTP_VERB, "GET", 
      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=" RESPONSE_TYPE_CODE "&nonce=nonce1234&client_id=" CLIENT_ID "&redirect_uri=" CLIENT_REDIRECT_URI_ENCODED "&scope=" SCOPE_LIST "&g_continue", 
      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "iss=" ISS_ESCAPED), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc auth iss id");
  tc_core = tcase_create("test_oidc_auth_iss_id");
  tcase_add_test(tc_core, test_oidc_auth_iss_id_add_plugin);
  tcase_add_test(tc_core, test_oidc_auth_iss_id_code);
  tcase_add_test(tc_core, test_oidc_auth_iss_id_code_id_token);
  tcase_add_test(tc_core, test_oidc_auth_iss_id_response_type_error);
  tcase_add_test(tc_core, test_oidc_auth_iss_id_client_invalid);
  tcase_add_test(tc_core, test_oidc_auth_iss_id_redirect_uri_invalid);
  tcase_add_test(tc_core, test_oidc_auth_iss_id_delete_plugin);
  tcase_add_test(tc_core, test_oidc_auth_iss_id_add_plugin_no);
  tcase_add_test(tc_core, test_oidc_auth_iss_id_code_iss_no);
  tcase_add_test(tc_core, test_oidc_auth_iss_id_delete_plugin);
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
      } else {
        do_test = 0;
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

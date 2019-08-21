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

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define USER_USERNAME "user1"
#define USER_PASSWORD "password"
#define PLUGIN_NAME "oidc_cmail_address"
#define SCOPE_LIST "g_profile openid"
#define CLIENT "client1_id"
#define CLIENT_URL "../../test-oidc.html?param=client1_cb1"
#define RESPONSE_TYPE "token id_token"
#define ADDR_FORMATTED "formatted value"
#define ADDR_STREET_ADDRESS "street_address value"
#define ADDR_LOCALITY "locality value"
#define ADDR_REGION "region value"
#define ADDR_POSTAL_CODE "postal_code value"
#define ADDR_COUNTRY "country"

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_oidc_address_claim_add_plugin_public)
{
  json_t * j_param = json_pack("{sssssss{sssssssssisisisosososososososos{ssssssssssssss}}}",
                                "module",
                                "oidc",
                                "name",
                                PLUGIN_NAME,
                                "display_name",
                                PLUGIN_NAME,
                                "parameters",
                                  "iss",
                                  "https://glewlwyd.tld",
                                  "jwt-type",
                                  "sha",
                                  "jwt-key-size",
                                  "256",
                                  "key",
                                  "secret_" PLUGIN_NAME,
                                  "access-token-duration",
                                  3600,
                                  "refresh-token-duration",
                                  1209600,
                                  "code-duration",
                                  600,
                                  "refresh-token-rolling",
                                  json_true(),
                                  "allow-non-oidc",
                                  json_true(),
                                  "auth-type-code-enabled",
                                  json_true(),
                                  "auth-type-token-enabled",
                                  json_true(),
                                  "auth-type-id-token-enabled",
                                  json_true(),
                                  "auth-type-password-enabled",
                                  json_true(),
                                  "auth-type-client-enabled",
                                  json_true(),
                                  "auth-type-refresh-enabled",
                                  json_true(),
                                  "address-claim",
                                    "type",
                                    "mandatory",
                                    "formatted",
                                    "add-formatted",
                                    "street_address",
                                    "add-street_address",
                                    "locality",
                                    "add-locality",
                                    "region",
                                    "add-region",
                                    "postal_code",
                                    "add-postal_code",
                                    "country",
                                    "add-country");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
  
  j_param = json_pack("{ssssssssssss}", "add-formatted", ADDR_FORMATTED, "add-street_address", ADDR_STREET_ADDRESS, "add-locality", ADDR_LOCALITY, "add-region", ADDR_REGION, "add-postal_code", ADDR_POSTAL_CODE, "add-country", ADDR_COUNTRY);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USER_USERNAME, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_address_claim_userinfo)
{
  struct _u_response resp;
  struct _u_request req;
  char * access_token, * bearer;
  json_t * j_result;
  
  ulfius_init_response(&resp);
  ulfius_init_request(&req);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, CLIENT_URL, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  access_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "access_token=") + o_strlen("access_token="));
  if (o_strchr(access_token, '&')) {
    *(o_strchr(access_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  bearer = msprintf("Bearer %s", access_token);
  u_map_put(req.map_header, "Authorization", bearer);

  j_result = json_pack("{s{ssssssssssss}}", "address", "formatted", ADDR_FORMATTED, "street_address", ADDR_STREET_ADDRESS, "locality", ADDR_LOCALITY, "region", ADDR_REGION, "postal_code", ADDR_POSTAL_CODE, "country", ADDR_COUNTRY);
  ck_assert_ptr_ne(j_result, NULL);
  ck_assert_int_eq(run_simple_test(&req, "GET", SERVER_URI "/" PLUGIN_NAME "/userinfo/?claims=address", NULL, NULL, NULL, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_result);
  
  ulfius_clean_request(&req);
  o_free(access_token);
  o_free(bearer);
}
END_TEST

START_TEST(test_oidc_address_claim_delete_plugin_public)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  
  json_t * j_param = json_pack("{sosososososo}", "add-formatted", json_null(), "add-street_address", json_null(), "add-locality", json_null(), "add-region", json_null(), "add-postal_code", json_null(), "add-country", json_null());
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USER_USERNAME, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd subject type");
  tc_core = tcase_create("test_oidc_subject_type");
  tcase_add_test(tc_core, test_oidc_address_claim_add_plugin_public);
  tcase_add_test(tc_core, test_oidc_address_claim_userinfo);
  tcase_add_test(tc_core, test_oidc_address_claim_delete_plugin_public);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req, scope_req;
  struct _u_response auth_resp, scope_resp;
  int res, do_test = 0;
  json_t * j_body;
  char * cookie;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  ulfius_init_request(&admin_req);
  ulfius_init_request(&user_req);

  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&scope_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_response(&scope_resp);
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
        u_map_put(scope_req.map_header, "Cookie", cookie);
        u_map_put(user_req.map_header, "Cookie", cookie);
        o_free(cookie);

        scope_req.http_verb = strdup("PUT");
        scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
        j_body = json_pack("{ss}", "scope", SCOPE_LIST);
        ulfius_set_json_body_request(&scope_req, j_body);
        json_decref(j_body);
        if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK || scope_resp.status != 200) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", SCOPE_LIST, CLIENT);
          do_test = 0;
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope OK");
        }
        ulfius_clean_response(&scope_resp);
        
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication user %s", USER_USERNAME);
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
  
  if (do_test) {
    j_body = json_pack("{ss}", "scope", "");
    ulfius_set_json_body_request(&scope_req, j_body);
    json_decref(j_body);
    o_free(scope_req.http_url);
    scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
    if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
    }
    
    char * url = msprintf("%s/auth/", SERVER_URI);
    run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
    o_free(url);
  }
  
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&scope_req);
  y_close_logs();
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

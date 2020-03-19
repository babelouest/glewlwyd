/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <jwt.h>

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
#define PLUGIN_NAME "oidc_claims"
#define SCOPE_LIST "g_profile openid"
#define CLIENT "client1_id"
#define RESPONSE_TYPE "id_token token"

#define CLAIM_STR "the-str"
#define CLAIM_STR_2 "the-other-str"
#define CLAIM_NUMBER "42"
#define CLAIM_NUMBER_2 "43"
#define CLAIM_BOOL_TRUE "1"
#define CLAIM_BOOL_FALSE "0"
#define CLAIM_MANDATORY "I'm aliiiiive!"

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_oidc_userinfo_add_plugin)
{
  json_t * j_param = json_pack("{sssssss{sssssssssisisisososososososososssss[{sssoss}{sssossss}{sssossssssss}{sssoss}{sssossss}{sssossssssss}{ssssso}]}}",
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
                                  "name-claim",
                                  "mandatory",
                                  "email-claim",
                                  "mandatory",
                                  "claims",
                                    "name",
                                    "claim-str",
                                    "mandatory",
                                    json_true(),
                                    "user-property",
                                    "claim-str",
                                    "name",
                                    "claim-number",
                                    "mandatory",
                                    json_true(),
                                    "type",
                                    "number",
                                    "user-property",
                                    "claim-number",
                                    "name",
                                    "claim-bool",
                                    "mandatory",
                                    json_true(),
                                    "type",
                                    "boolean",
                                    "user-property",
                                    "claim-bool",
                                    "boolean-value-true",
                                    "1",
                                    "boolean-value-false",
                                    "0",
                                    "name",
                                    "claim-array-str",
                                    "mandatory",
                                    json_true(),
                                    "user-property",
                                    "claim-array-str",
                                    "name",
                                    "claim-array-number",
                                    "mandatory",
                                    json_true(),
                                    "type",
                                    "number",
                                    "user-property",
                                    "claim-array-number",
                                    "name",
                                    "claim-array-bool",
                                    "mandatory",
                                    json_true(),
                                    "type",
                                    "boolean",
                                    "user-property",
                                    "claim-array-bool",
                                    "boolean-value-true",
                                    "1",
                                    "boolean-value-false",
                                    "0",
                                    "name",
                                    "claim-mandatory",
                                    "user-property",
                                    "claim-mandatory",
                                    "mandatory",
                                    json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
  
  j_param = json_pack("{sssssssss[ss]s[ss]s[ss]}", "claim-str", CLAIM_STR, "claim-number", CLAIM_NUMBER, "claim-bool", CLAIM_BOOL_TRUE, "claim-mandatory", CLAIM_MANDATORY, "claim-array-str", CLAIM_STR, CLAIM_STR_2, "claim-array-number", CLAIM_NUMBER, CLAIM_NUMBER_2, "claim-array-bool", CLAIM_BOOL_TRUE, CLAIM_BOOL_FALSE);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USER_USERNAME, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_userinfo_noauth)
{
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/" PLUGIN_NAME "/userinfo/", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/userinfo/", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_userinfo)
{
  struct _u_response resp;
  struct _u_request req;
  char * access_token, * bearer;
  json_t * j_result;
  
  ulfius_init_response(&resp);
  ulfius_init_request(&req);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
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

  j_result = json_pack("{sssssssisosss[ss]s[ii]s[oo]}", "name", "Dave Lopper 1", "email", "dev1@glewlwyd", "claim-str", CLAIM_STR, "claim-number", 42, "claim-bool", json_true(), "claim-mandatory", CLAIM_MANDATORY, "claim-array-str", CLAIM_STR, CLAIM_STR_2, "claim-array-number", 42, 43, "claim-array-bool", json_true(), json_false());
  ck_assert_int_eq(run_simple_test(&req, "GET", SERVER_URI "/" PLUGIN_NAME "/userinfo/", NULL, NULL, NULL, NULL, 200, j_result, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/userinfo/", NULL, NULL, NULL, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_result);
  
  ulfius_clean_request(&req);
  o_free(access_token);
  o_free(bearer);
}
END_TEST

START_TEST(test_oidc_userinfo_jwt)
{
  struct _u_response resp;
  struct _u_request req;
  char * access_token, * bearer, * body, * jwt_payload;
  json_t * j_result, * j_payload = NULL;
  jwt_t * jwt;
  
  ulfius_init_response(&resp);
  ulfius_init_request(&req);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
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

  j_result = json_pack("{sssssssisosss[ss]s[ii]s[oo]}", "name", "Dave Lopper 1", "email", "dev1@glewlwyd", "claim-str", CLAIM_STR, "claim-number", 42, "claim-bool", json_true(), "claim-mandatory", CLAIM_MANDATORY, "claim-array-str", CLAIM_STR, CLAIM_STR_2, "claim-array-number", 42, 43, "claim-array-bool", json_true(), json_false());

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/userinfo/?format=jwt");
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_str_eq(u_map_get(resp.map_header, "Content-Type"), "application/jwt");
  body = o_strndup(resp.binary_body, resp.binary_body_length);
  ck_assert_int_eq(jwt_decode(&jwt, body, (unsigned char *)("secret_" PLUGIN_NAME), o_strlen("secret_" PLUGIN_NAME)), 0);
  ck_assert_ptr_ne((jwt_payload = jwt_get_grants_json(jwt, NULL)), NULL);
  ck_assert_ptr_ne((j_payload = json_loads(jwt_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_ptr_ne(json_search(j_payload, j_result), NULL);
  o_free(jwt_payload);
  json_decref(j_payload);
  ulfius_clean_response(&resp);
  o_free(body);
  jwt_free(jwt);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(req.http_url);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/userinfo/");
  u_map_put(req.map_post_body, "format", "jwt");
  req.http_verb = o_strdup("POST");
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_str_eq(u_map_get(resp.map_header, "Content-Type"), "application/jwt");
  body = o_strndup(resp.binary_body, resp.binary_body_length);
  ck_assert_int_eq(jwt_decode(&jwt, body, (unsigned char *)("secret_" PLUGIN_NAME), o_strlen("secret_" PLUGIN_NAME)), 0);
  ck_assert_ptr_ne((jwt_payload = jwt_get_grants_json(jwt, NULL)), NULL);
  ck_assert_ptr_ne((j_payload = json_loads(jwt_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_ptr_ne(json_search(j_payload, j_result), NULL);
  o_free(jwt_payload);
  json_decref(j_payload);
  ulfius_clean_response(&resp);
  o_free(body);
  jwt_free(jwt);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  u_map_remove_from_key(req.map_post_body, "format");
  u_map_put(req.map_header, "Accept", "application/jwt");
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_str_eq(u_map_get(resp.map_header, "Content-Type"), "application/jwt");
  body = o_strndup(resp.binary_body, resp.binary_body_length);
  ck_assert_int_eq(jwt_decode(&jwt, body, (unsigned char *)("secret_" PLUGIN_NAME), o_strlen("secret_" PLUGIN_NAME)), 0);
  ck_assert_ptr_ne((jwt_payload = jwt_get_grants_json(jwt, NULL)), NULL);
  ck_assert_ptr_ne((j_payload = json_loads(jwt_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_ptr_ne(json_search(j_payload, j_result), NULL);
  o_free(jwt_payload);
  json_decref(j_payload);
  ulfius_clean_response(&resp);
  o_free(body);
  jwt_free(jwt);
  
  json_decref(j_result);
  
  ulfius_clean_request(&req);
  o_free(access_token);
  o_free(bearer);
}
END_TEST

START_TEST(test_oidc_userinfo_delete_plugin)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/user/" USER_USERNAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  json_t * j_param = json_pack("{ss ss ss so s[sssss]}", 
                              "username",
                              USER_USERNAME,
                              "name",
                              "Dave Lopper 1",
                              "email",
                              "dev1@glewlwyd",
                              "enabled",
                              json_true(),
                              "scope",
                                "g_profile",
                                "openid",
                                "scope1",
                                "scope2",
                                "scope3");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc userinfo");
  tc_core = tcase_create("test_oidc_userinfo");
  tcase_add_test(tc_core, test_oidc_userinfo_add_plugin);
  tcase_add_test(tc_core, test_oidc_userinfo_noauth);
  tcase_add_test(tc_core, test_oidc_userinfo);
  tcase_add_test(tc_core, test_oidc_userinfo_jwt);
  tcase_add_test(tc_core, test_oidc_userinfo_delete_plugin);
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
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
          do_test = 0;
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope OK");
        }
        ulfius_clean_response(&scope_resp);
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
  
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&scope_req, j_body);
  json_decref(j_body);
  if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
  }
  
  char * url = msprintf("%s/auth/", SERVER_URI);
  run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  o_free(url);
  
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&scope_req);
  y_close_logs();
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

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
#define SCOPE_LIST "openid"
#define CLIENT "client1_id"
#define REDIRECT_URI "..%2f..%2ftest-oidc.html?param=client1_cb1"
#define REDIRECT_URI_DECODED "../../test-oidc.html?param=client1_cb1"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define CODE_CHALLENGE_VALID "V0UN9ToT-UnbxeIx7imQdhFjsAZTmuARpHyuD2ajIIo"
#define CODE_CHALLENGE_VALID_2 "GE8iHoAZ3H6to1ERRDVLx8iJD0XLHF0XjmfxWoAibQE"
#define CODE_CHALLENGE_42 "NfzP48kCM-QfPKoR2p-lJvTAG28TR-FlWXqxp7naU8I"
#define CODE_CHALLENGE_INVALID_CHARSET "Iy8nznHo9PQsgDeabc-fZbPWVFApHSoyRZskN6rH-d0"
#define CODE_VERIFIER_VALID "XvkLR4XIl4DbkFz3RLEZUBStp8yIjvF8UtfRv0nkK8DqmrBtWvHmEuyBL2enyLF9"
#define CODE_VERIFIER_VALID_2 "6nwfKTI6ODJmm89xBbvX0mOLbk0PbLY2sNS2o9vFixHU8hAktkQw3PwJHX1GAf69"
#define CODE_VERIFIER_INVALID_42 "XvkLR4XIl4DbkFz3RLEZUBStp8yIjvF8UtfRv0nkww"
#define CODE_VERIFIER_INVALID_129 "XvkLR4XIl4DbkFz3RLEZUBStp8yIjvF8UtfRv0nkK8DqmrBtWvHmEuyBL2enyLF9XvkLR4XIl4DbkFz3RLEZUBStp8yIjvF8UtfRv0nkK8DqmrBtWvHmEuyBL2enyLF9X"
#define CODE_VERIFIER_INVALID_CHARSET "XvkLR4XIl4DbkFz3RLEZUBStp8yIjvF8UtfRv0nkK8DqmrBt,vHmEuyBL2enyLF9"
#define CODE_CHALLENGE_METHOD_PLAIN "plain"
#define CODE_CHALLENGE_METHOD_S256 "S256"

#define PLUGIN_MODULE "oidc"
#define PLUGIN_NAME "challenge"
#define PLUGIN_DISPLAY_NAME "Challenge test"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_JWT_TYPE "sha"
#define PLUGIN_JWT_KEY_SIZE "256"
#define PLUGIN_KEY "secret"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_ACCESS_TOKEN_DURATION 3600

struct _u_request user_req;
struct _u_request admin_req;

START_TEST(test_oidc_code_code_challenge_add_plugin_with_plain)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisososososososo}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", PLUGIN_JWT_TYPE,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", PLUGIN_KEY,
                                  "code-duration", PLUGIN_CODE_DURATION,
                                  "refresh-token-duration", PLUGIN_REFRESH_TOKEN_DURATION,
                                  "access-token-duration", PLUGIN_ACCESS_TOKEN_DURATION,
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-implicit-enabled", json_true(),
                                  "auth-type-password-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "pkce-allowed", json_true(),
                                  "pkce-method-plain-allowed", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_code_code_challenge_add_plugin_without_plain)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisososososososo}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", PLUGIN_JWT_TYPE,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", PLUGIN_KEY,
                                  "code-duration", PLUGIN_CODE_DURATION,
                                  "refresh-token-duration", PLUGIN_REFRESH_TOKEN_DURATION,
                                  "access-token-duration", PLUGIN_ACCESS_TOKEN_DURATION,
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-implicit-enabled", json_true(),
                                  "auth-type-password-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "pkce-allowed", json_true(),
                                  "pkce-method-plain-allowed", json_false());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_code_code_challenge_remove_plugin)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_code_code_challenge_invalid_code_challenge_method)
{
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&code_challenge=" CODE_CHALLENGE_VALID "&code_challenge_method=error&scope=" SCOPE_LIST, NULL, NULL, NULL, NULL, 302, NULL, NULL, "error=invalid_request"), 1);
}
END_TEST

START_TEST(test_oidc_code_code_challenge_plain_invalid_code_challenge_method)
{
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&code_challenge=" CODE_CHALLENGE_VALID "&code_challenge_method=" CODE_CHALLENGE_METHOD_PLAIN "&scope=" SCOPE_LIST, NULL, NULL, NULL, NULL, 302, NULL, NULL, "error=invalid_request"), 1);
}
END_TEST

START_TEST(test_oidc_code_code_challenge_plain_invalid_length)
{
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&code_challenge=" CODE_VERIFIER_INVALID_42 "&code_challenge_method=" CODE_CHALLENGE_METHOD_PLAIN "&scope=" SCOPE_LIST, NULL, NULL, NULL, NULL, 302, NULL, NULL, "error=invalid_request"), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&code_challenge=" CODE_VERIFIER_INVALID_129 "&code_challenge_method=" CODE_CHALLENGE_METHOD_PLAIN "&scope=" SCOPE_LIST, NULL, NULL, NULL, NULL, 302, NULL, NULL, "error=invalid_request"), 1);
}
END_TEST

START_TEST(test_oidc_code_code_challenge_plain_invalid_charset)
{
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&code_challenge=" CODE_VERIFIER_INVALID_CHARSET "&code_challenge_method=" CODE_CHALLENGE_METHOD_PLAIN "&scope=" SCOPE_LIST, NULL, NULL, NULL, NULL, 302, NULL, NULL, "error=invalid_request"), 1);
}
END_TEST

START_TEST(test_oidc_code_code_challenge_plain_verifier_invalid_value)
{
  struct _u_response resp;
  char * code = NULL;
  struct _u_map body;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&code_challenge=" CODE_VERIFIER_VALID "&code_challenge_method=" CODE_CHALLENGE_METHOD_PLAIN "&scope=" SCOPE_LIST);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);

  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }

  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "code_verifier", CODE_VERIFIER_VALID_2);
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", REDIRECT_URI_DECODED);
  u_map_put(&body, "code", code);
  
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/token", NULL, NULL, NULL, &body, 403, NULL, NULL, NULL), 1);
  u_map_clean(&body);
  ulfius_clean_response(&resp);
  o_free(code);
}
END_TEST

START_TEST(test_oidc_code_code_challenge_plain_verifier_ok)
{
  struct _u_response resp;
  char * code = NULL;
  struct _u_map body;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&code_challenge=" CODE_VERIFIER_VALID "&code_challenge_method=" CODE_CHALLENGE_METHOD_PLAIN "&scope=" SCOPE_LIST);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);

  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }

  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "code_verifier", CODE_VERIFIER_VALID);
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", REDIRECT_URI_DECODED);
  u_map_put(&body, "code", code);
  
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/token", NULL, NULL, NULL, &body, 200, NULL, NULL, NULL), 1);
  u_map_clean(&body);
  ulfius_clean_response(&resp);
  o_free(code);
}
END_TEST

START_TEST(test_oidc_code_code_challenge_s256_invalid_length)
{
  struct _u_response resp;
  char * code = NULL;
  struct _u_map body;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&code_challenge=" CODE_CHALLENGE_42 "&code_challenge_method=" CODE_CHALLENGE_METHOD_S256 "&scope=" SCOPE_LIST);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);

  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }

  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "code_verifier", CODE_VERIFIER_INVALID_42);
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", REDIRECT_URI_DECODED);
  u_map_put(&body, "code", code);
  
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/token", NULL, NULL, NULL, &body, 403, NULL, NULL, NULL), 1);
  u_map_clean(&body);
  ulfius_clean_response(&resp);
  o_free(code);
}
END_TEST

START_TEST(test_oidc_code_code_challenge_s256_invalid_charset)
{
  struct _u_response resp;
  char * code = NULL;
  struct _u_map body;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&code_challenge=" CODE_CHALLENGE_INVALID_CHARSET "&code_challenge_method=" CODE_CHALLENGE_METHOD_S256 "&scope=" SCOPE_LIST);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);

  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }

  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "code_verifier", CODE_VERIFIER_INVALID_CHARSET);
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", REDIRECT_URI_DECODED);
  u_map_put(&body, "code", code);
  
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/token", NULL, NULL, NULL, &body, 403, NULL, NULL, NULL), 1);
  u_map_clean(&body);
  ulfius_clean_response(&resp);
  o_free(code);
}
END_TEST

START_TEST(test_oidc_code_code_challenge_s256_verifier_invalid_value)
{
  struct _u_response resp;
  char * code = NULL;
  struct _u_map body;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&code_challenge=" CODE_CHALLENGE_VALID "&code_challenge_method=" CODE_CHALLENGE_METHOD_S256 "&scope=" SCOPE_LIST);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);

  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }

  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "code_verifier", CODE_VERIFIER_VALID_2);
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", REDIRECT_URI_DECODED);
  u_map_put(&body, "code", code);
  
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/token", NULL, NULL, NULL, &body, 403, NULL, NULL, NULL), 1);
  u_map_clean(&body);
  ulfius_clean_response(&resp);
  o_free(code);
}
END_TEST

START_TEST(test_oidc_code_code_challenge_s256_verifier_ok)
{
  struct _u_response resp;
  char * code = NULL;
  struct _u_map body;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&code_challenge=" CODE_CHALLENGE_VALID "&code_challenge_method=" CODE_CHALLENGE_METHOD_S256 "&scope=" SCOPE_LIST);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);

  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }

  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "code_verifier", CODE_VERIFIER_VALID);
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", REDIRECT_URI_DECODED);
  u_map_put(&body, "code", code);
  
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/" PLUGIN_NAME "/token", NULL, NULL, NULL, &body, 200, NULL, NULL, NULL), 1);
  u_map_clean(&body);
  ulfius_clean_response(&resp);
  o_free(code);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc code_challenge");
  tc_core = tcase_create("test_oidc_code_challenge");
  tcase_add_test(tc_core, test_oidc_code_code_challenge_add_plugin_with_plain);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_invalid_code_challenge_method);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_plain_invalid_length);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_plain_invalid_charset);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_plain_verifier_invalid_value);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_plain_verifier_ok);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_s256_invalid_length);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_s256_invalid_charset);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_s256_verifier_invalid_value);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_s256_verifier_ok);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_remove_plugin);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_add_plugin_without_plain);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_plain_invalid_code_challenge_method);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_s256_invalid_length);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_s256_invalid_charset);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_s256_verifier_invalid_value);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_s256_verifier_ok);
  tcase_add_test(tc_core, test_oidc_code_code_challenge_remove_plugin);
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
    user_req.http_verb = strdup("PUT");
    user_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
    j_body = json_pack("{ss}", "scope", SCOPE_LIST);
    ulfius_set_json_body_request(&user_req, j_body);
    json_decref(j_body);
    if (ulfius_send_http_request(&user_req, NULL) != U_OK) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
    } else {
      do_test = 1;
    }
    
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);
    do_test = 1;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
    do_test = 0;
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
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", ADMIN_USERNAME);
    do_test = 1;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
    do_test = 0;
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
  
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&user_req, j_body);
  json_decref(j_body);
  if (ulfius_send_http_request(&user_req, NULL) != U_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
  }
  
  run_simple_test(&user_req, "DELETE", SERVER_URI "/auth/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&admin_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

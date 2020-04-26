/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <check.h>

#include <orcania.h>
#include <yder.h>
#include <ulfius.h>
#include <rhonabwy.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define USERNAME "user1"
#define PASSWORD "password"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define SCOPE_LIST "openid"
#define NONCE_TEST "nonce5678"
#define STATE_TEST "abcxyz"

#define PLUGIN_MODULE "oidc"
#define PLUGIN_NAME "oidc_session"
#define PLUGIN_DISPLAY_NAME "oidc with session management"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_ACCESS_TOKEN_DURATION 3600

#define CLIENT_ID "client_session"
#define CLIENT_NAME "client with session"
#define CLIENT_ORIGIN "https://client.local"
#define CLIENT_REDIRECT "https://client.local/redirect"
#define CLIENT_REDIRECT_POST_LOGOUT "https://client.local/logout"
#define CLIENT_REDIRECT_POST_LOGOUT_ENC "https%3A%2F%2Fclient.local%2Flogout"
#define CLIENT_ANOTHER_REDIRECT_POST_LOGOUT "https://2Fanotherclient.local/logout"
#define CLIENT_ANOTHER_REDIRECT_POST_LOGOUT_ENC "https%3A%2F%2Fanotherclient.local%2Flogout"

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_oidc_session_management_add_module_ok)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisososososososososo}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", "sha",
                                  "jwt-key-size", "256",
                                  "key", "secret",
                                  "code-duration", PLUGIN_CODE_DURATION,
                                  "refresh-token-duration", PLUGIN_REFRESH_TOKEN_DURATION,
                                  "access-token-duration", PLUGIN_ACCESS_TOKEN_DURATION,
                                  "allow-non-oidc", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-implicit-enabled", json_true(),
                                  "auth-type-password-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "request-parameter-allow", json_true(),
                                  "session-management-allowed", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_session_management_add_client_ok)
{
  json_t * j_parameters = json_pack("{sssss[s]s[s]s[sss]so}",
                                "client_id", CLIENT_ID,
                                "clint_name", CLIENT_NAME,
                                "redirect_uri", CLIENT_REDIRECT,
                                "post_logout_redirect_uris", CLIENT_REDIRECT_POST_LOGOUT,
                                "authorization_type", "code", "token", "id_token",
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_session_management_delete_module)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_session_management_delete_client)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_session_management_session_state)
{
  struct _u_request auth_req;
  struct _u_response auth_resp, resp;
  json_t * j_body;
  char * cookie;
  char * session_state, * session_state_dec, * salt, * intermediate;
  unsigned char hash[32] = {0}, hash_b64[128] = {0};
  size_t hash_len = 32, hash_b64_len = 0;
  gnutls_datum_t data;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_gt(auth_resp.nb_cookies, 0);
  ck_assert_ptr_ne((cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value)), NULL);
  ck_assert_int_eq(u_map_put(auth_req.map_header, "Cookie", cookie), U_OK);
  ulfius_clean_response(&auth_resp);
  
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_url = msprintf("%s/%s/auth?response_type=id_token%%20code&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonceAbcXyz&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  auth_req.http_verb = o_strdup("GET");
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(NULL, o_strstr(u_map_get(resp.map_header, "Location"), "session_state="));
  session_state = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "session_state=")+strlen("session_state="));
  if (strchr(session_state, '&') != NULL) {
    *strchr(session_state, '&') = '\0';
  }
  session_state_dec = ulfius_url_decode(session_state);
  salt = o_strstr(session_state, ".")+1;
  ck_assert_ptr_ne(NULL, salt);
  intermediate = msprintf("%s %s %s %s", CLIENT_ID, CLIENT_ORIGIN, USERNAME, salt);
  data.data = (unsigned char *)intermediate;
  data.size = o_strlen(intermediate);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_DIG_SHA256, &data, hash, &hash_len), GNUTLS_E_SUCCESS);
  ck_assert_int_eq(o_base64_encode(hash, hash_len, hash_b64, &hash_b64_len), 1);
  hash_b64[hash_b64_len] = '\0';
  ck_assert_int_eq(0, o_strncmp((const char *)hash_b64, session_state_dec, hash_b64_len));
  
  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/" PLUGIN_NAME "/check_session_iframe/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  
  ulfius_clean_response(&resp);
  ulfius_clean_request(&auth_req);
  o_free(cookie);
  o_free(session_state);
  o_free(session_state_dec);
  o_free(intermediate);
}
END_TEST

START_TEST(test_oidc_session_management_end_session_no_post_logout)
{
  struct _u_request req;
  struct _u_response resp;
  char * id_token;
  json_t * j_body;
  
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=")+strlen("id_token="));
  if (strchr(id_token, '&') != NULL) {
    *strchr(id_token, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  o_free(req.http_verb);
  o_free(req.http_url);
  req.http_verb = o_strdup("GET");
  req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/end_session?state=stateXyz&id_token_hint=%s", id_token);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), "stateXyz"));
  
  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(id_token);
}
END_TEST

START_TEST(test_oidc_session_management_end_session_invalid_post_logout)
{
  struct _u_request req;
  struct _u_response resp;
  char * id_token;
  json_t * j_body;
  
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&state=stateXyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=")+strlen("id_token="));
  if (strchr(id_token, '&') != NULL) {
    *strchr(id_token, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  o_free(req.http_verb);
  o_free(req.http_url);
  req.http_verb = o_strdup("GET");
  req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/end_session?state=stateXyz&post_logout_redirect_uri=%s&id_token_hint=%s", CLIENT_ANOTHER_REDIRECT_POST_LOGOUT_ENC, id_token);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), "stateXyzabcd"));
  ck_assert_ptr_eq(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), CLIENT_ANOTHER_REDIRECT_POST_LOGOUT));
  
  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(id_token);
}
END_TEST

START_TEST(test_oidc_session_management_end_session_valid_post_logout)
{
  struct _u_request req;
  struct _u_response resp;
  char * id_token;
  json_t * j_body;
  
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&state=stateXyzabcd&nonce=nonce123456&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=")+strlen("id_token="));
  if (strchr(id_token, '&') != NULL) {
    *strchr(id_token, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  o_free(req.http_verb);
  o_free(req.http_url);
  req.http_verb = o_strdup("GET");
  req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/end_session?state=stateXyzabcd123&post_logout_redirect_uri=%s&id_token_hint=%s", CLIENT_REDIRECT_POST_LOGOUT_ENC, id_token);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), "stateXyzabcd123"));
  ck_assert_ptr_ne(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC));
  
  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(id_token);
}
END_TEST

START_TEST(test_oidc_session_management_end_session_no_state)
{
  struct _u_request req;
  struct _u_response resp;
  char * id_token;
  json_t * j_body;
  
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234567&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=")+strlen("id_token="));
  if (strchr(id_token, '&') != NULL) {
    *strchr(id_token, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  o_free(req.http_verb);
  o_free(req.http_url);
  req.http_verb = o_strdup("GET");
  req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/end_session?post_logout_redirect_uri=%s&id_token_hint=%s", CLIENT_REDIRECT_POST_LOGOUT_ENC, id_token);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), "state="));
  ck_assert_ptr_ne(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC));
  
  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(id_token);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc session management");
  tc_core = tcase_create("test_oidc_session_management");
  tcase_add_test(tc_core, test_oidc_session_management_add_module_ok);
  tcase_add_test(tc_core, test_oidc_session_management_add_client_ok);
  tcase_add_test(tc_core, test_oidc_session_management_session_state);
  tcase_add_test(tc_core, test_oidc_session_management_end_session_no_post_logout);
  tcase_add_test(tc_core, test_oidc_session_management_end_session_invalid_post_logout);
  tcase_add_test(tc_core, test_oidc_session_management_end_session_valid_post_logout);
  tcase_add_test(tc_core, test_oidc_session_management_end_session_no_state);
  tcase_add_test(tc_core, test_oidc_session_management_delete_client);
  tcase_add_test(tc_core, test_oidc_session_management_delete_module);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req, scope_req, register_req;
  struct _u_response auth_resp, scope_resp;
  json_t * j_body;
  int res, do_test = 0, i;
  char * url;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  ulfius_init_request(&auth_req);
  ulfius_init_request(&admin_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", ADMIN_USERNAME, "password", ADMIN_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    for (i=0; i<auth_resp.nb_cookies; i++) {
      y_log_message(Y_LOG_LEVEL_INFO, "user %s authenticated", ADMIN_USERNAME);
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(admin_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    do_test = 1;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication admin");
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);

  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
  ulfius_init_request(&scope_req);
  ulfius_init_request(&register_req);
  ulfius_init_response(&scope_resp);
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
      u_map_put(auth_req.map_header, "Cookie", cookie);
      u_map_put(scope_req.map_header, "Cookie", cookie);
      u_map_put(register_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    ulfius_clean_response(&auth_resp);
    ulfius_init_response(&auth_resp);
    
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);

  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error auth password");
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_response(&scope_resp);

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
  }
  
  url = msprintf("%s/auth/", SERVER_URI);
  run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  o_free(url);
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&scope_req);
  ulfius_clean_request(&register_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

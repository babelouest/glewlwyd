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
#define USERNAME "user1"
#define PASSWORD "password"
#define SCOPE_LIST "g_profile"

char * bearer_token;
char * refresh_token;
char user_agent[33];
struct _u_request user_req;

START_TEST(test_oidc_refresh_manage_endpoints_noauth)
{
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/oidc/token/", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "DELETE", SERVER_URI "/oidc/token/test", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_refresh_manage_list)
{
  struct _u_response resp;
  json_t * j_body = NULL;
  
  ulfius_init_response(&resp);
  u_map_put(user_req.map_header, "Authorization", bearer_token);
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/oidc/token/");
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_gt(json_array_size(j_body), 0);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/oidc/token/?limit=1");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  json_decref(j_body);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_eq(json_array_size(j_body), 1);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/oidc/token/?offset=1");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  json_decref(j_body);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/oidc/token/?sort=authorization_type");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  json_decref(j_body);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_gt(json_array_size(j_body), 0);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/oidc/token/?sort=issued_at&desc");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  json_decref(j_body);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_gt(json_array_size(j_body), 0);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/oidc/token/?sort=client_id&desc&limit=1");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  json_decref(j_body);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_eq(json_array_size(j_body), 1);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf(SERVER_URI "/oidc/token/?pattern=%s", user_agent);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  json_decref(j_body);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_gt(json_array_size(j_body), 0);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/oidc/token/?pattern=oidc-oauth2-test-");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  json_decref(j_body);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_gt(json_array_size(j_body), 0);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/oidc/token/?pattern=error");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  json_decref(j_body);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_eq(json_array_size(j_body), 0);

  ulfius_clean_response(&resp);
  json_decref(j_body);
}
END_TEST

START_TEST(test_oidc_refresh_manage_delete_not_found)
{
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  o_free(user_req.http_verb);
  user_req.http_url = o_strdup(SERVER_URI "/oidc/token/error");
  user_req.http_verb = o_strdup("DELETE");
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 404);
  
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_refresh_manage_delete_ok)
{
  char * url = SERVER_URI "/oidc/token/", * token_hash, * token_hash_encoded;
  struct _u_map body;
  struct _u_response resp;
  int res;
  json_t * j_body;
  ulfius_init_response(&resp);
  
  o_free(user_req.http_url);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  user_req.http_url = msprintf(SERVER_URI "/oidc/token/?sort=issued_at&desc&limit=1&pattern=%s", user_agent);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_gt(json_array_size(j_body), 0);
  ck_assert_ptr_ne((token_hash = o_strdup(json_string_value(json_object_get(json_array_get(j_body, 0), "token_hash")))), NULL);
  ck_assert_ptr_ne((token_hash_encoded = url_encode(token_hash)), NULL);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  u_map_init(&body);
  u_map_put(&body, "grant_type", "refresh_token");
  u_map_put(&body, "refresh_token", refresh_token);
  
  res = run_simple_test(NULL, "POST", url, NULL, NULL, NULL, &body, 200, NULL, NULL, NULL);
  ck_assert_int_eq(res, 1);
  
  o_free(user_req.http_url);
  o_free(user_req.http_verb);
  user_req.http_url = msprintf(SERVER_URI "/oidc/token/%s", token_hash_encoded);
  user_req.http_verb = o_strdup("DELETE");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  user_req.http_url = msprintf(SERVER_URI "/oidc/token/?sort=issued_at&desc&limit=1&pattern=%s", user_agent);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  json_decref(j_body);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_gt(json_array_size(j_body), 0);
  ck_assert_ptr_eq(json_object_get(json_array_get(j_body, 0), "enabled"), json_false());

  res = run_simple_test(NULL, "POST", url, NULL, NULL, NULL, &body, 400, NULL, NULL, NULL);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
  
  ulfius_clean_response(&resp);
  o_free(token_hash);
  o_free(token_hash_encoded);
  json_decref(j_body);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd profile");
  tc_core = tcase_create("test_oidc_refresh_manage");
  tcase_add_test(tc_core, test_oidc_refresh_manage_endpoints_noauth);
  tcase_add_test(tc_core, test_oidc_refresh_manage_list);
  tcase_add_test(tc_core, test_oidc_refresh_manage_delete_not_found);
  tcase_add_test(tc_core, test_oidc_refresh_manage_delete_ok);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req;
  struct _u_response auth_resp;
  int res, i, do_test = 0, number_failed = 1, x[1];
  json_t * j_body;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/oidc/token/", SERVER_URI);
  
  gnutls_rnd(GNUTLS_RND_NONCE, x, sizeof(int));
  snprintf(user_agent, 32, "oidc-oauth2-test-%d", x[0]);
  u_map_put(auth_req.map_header, "User-Agent", user_agent);
  u_map_put(auth_req.map_post_body, "grant_type", "password");
  u_map_put(auth_req.map_post_body, "username", USERNAME);
  u_map_put(auth_req.map_post_body, "password", PASSWORD);
  u_map_put(auth_req.map_post_body, "scope", SCOPE_LIST);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    json_t * json_body = ulfius_get_json_body_response(&auth_resp, NULL);
    bearer_token = msprintf("Bearer %s", json_string_value(json_object_get(json_body, "access_token")));
    refresh_token = o_strdup(json_string_value(json_object_get(json_body, "refresh_token")));
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);
    json_decref(json_body);
  }
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
  
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
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
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
  
  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  o_free(bearer_token);
  o_free(refresh_token);
  
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

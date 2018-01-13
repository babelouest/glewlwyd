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
#include <jwt.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define CLIENT "client1_id"

#define PORT   2884
#define PREFIX "/auth"

#define HTTP_USER     "http_user"
#define HTTP_PASSWORD "http_user_password"

struct _u_request user_req;
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

START_TEST(test_glwd_crud_user_connect_http_auth_success)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", HTTP_USER);
  u_map_put(auth_req.map_post_body, "password", HTTP_PASSWORD);
  ulfius_send_http_request(&auth_req, &auth_resp);
  ck_assert_int_eq(auth_resp.status, 200);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST

START_TEST(test_glwd_crud_user_connect_http_auth_fail)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", HTTP_USER);
  u_map_put(auth_req.map_post_body, "password", "invalid");
  ulfius_send_http_request(&auth_req, &auth_resp);
  ck_assert_int_eq(auth_resp.status, 403);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST

START_TEST(test_glwd_crud_user_check_access_token_http_auth_ok)
{
  struct _u_request auth_req;
  struct _u_response auth_resp;
  json_t * j_body;
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/token/", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", HTTP_USER);
  u_map_put(auth_req.map_post_body, "password", HTTP_PASSWORD);
  u_map_put(auth_req.map_post_body, "grant_type", "password");
  ulfius_send_http_request(&auth_req, &auth_resp);
  ck_assert_int_eq(auth_resp.status, 200);
  j_body = json_loadb(auth_resp.binary_body, auth_resp.binary_body_length, JSON_DECODE_ANY, NULL);
  ck_assert_ptr_ne(json_object_get(j_body, "access_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_body, "refresh_token"), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_body, "token_type")), "bearer");
  ck_assert_ptr_ne(json_object_get(j_body, "iat"), NULL);
  ck_assert_ptr_ne(json_object_get(j_body, "expires_in"), NULL);
  json_decref(j_body);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
}
END_TEST

START_TEST(glewlwyd_resource_owner_pwd_cred_valid_http_auth)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "password");
  u_map_put(&body, "username", HTTP_USER);
  u_map_put(&body, "password", HTTP_PASSWORD);

  int res = run_simple_test(NULL, "POST", url, NULL, NULL, NULL, &body, 200, NULL, "refresh_token", NULL);
  free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_code_http_auth_ok)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", "../app/test-token.html?param=client1_cb1");
  u_map_put(&body, "code", code);
  
  free(user_req.http_verb);
  user_req.http_verb = NULL;
  int res = run_simple_test(&user_req, "POST", url, NULL, NULL, NULL, &body, 200, NULL, "refresh_token", NULL);
  free(url);
  u_map_clean(&body);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_auth_code_ok_redirect_cb_with_code_http_auth)
{
  char * url = msprintf("%s/auth?response_type=code&login_validated=true&client_id=client1_id&redirect_uri=../app/test-token.html?param=client1_cb1&state=xyzabcd", SERVER_URI);
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "code=");
  free(url);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_implicit_valid_http_auth)
{
  char * url = msprintf("%s/auth?response_type=token&login_validated=true&client_id=%s&redirect_uri=../app/test-token.html?param=client1_cb1&state=xyzabcd", SERVER_URI, CLIENT);
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "token=");
  free(url);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_refresh_token_ok_http_auth)
{
  char * url = msprintf("%s/token/", SERVER_URI), * refresh_token;
  struct _u_map body;
  struct _u_request auth_req;
  struct _u_response auth_resp;
	int res;
	
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/token/", SERVER_URI);
  u_map_put(auth_req.map_post_body, "grant_type", "password");
  u_map_put(auth_req.map_post_body, "username", HTTP_USER);
  u_map_put(auth_req.map_post_body, "password", HTTP_PASSWORD);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK) {
    json_t * json_body = ulfius_get_json_body_response(&auth_resp, NULL);
    refresh_token = o_strdup(json_string_value(json_object_get(json_body, "refresh_token")));
    json_decref(json_body);
  }
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
	
  u_map_init(&body);
  u_map_put(&body, "grant_type", "refresh_token");
  u_map_put(&body, "refresh_token", refresh_token);
  
  res = run_simple_test(NULL, "POST", url, NULL, NULL, NULL, &body, 200, NULL, NULL, NULL);
  free(url);
  u_map_clean(&body);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_user_refresh_token_list_all_user)
{
  char * url = msprintf("%s/profile/refresh_token", SERVER_URI);
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_user_refresh_token_revoke_ok_user)
{
  struct _u_response list_resp, del_resp;
  int res;
  json_t * json_body, * json_resp_body;
  
  ulfius_init_response(&list_resp);
  ulfius_init_response(&del_resp);
  user_req.http_url = msprintf("%s/profile/refresh_token/?valid=true", SERVER_URI);
  res = ulfius_send_http_request(&user_req, &list_resp);
  if (res == U_OK) {
    json_resp_body = ulfius_get_json_body_response(&list_resp, NULL);
    json_body = json_pack("{ss}", "token_hash", json_string_value(json_object_get(json_array_get(json_resp_body, 0), "token_hash")));
    u_map_put(user_req.map_header, "Content-Type", "application/x-www-form-urlencoded");
    ulfius_set_json_body_request(&user_req, json_body);
    json_decref(json_body);
    json_decref(json_resp_body);
  }
  
  user_req.http_url = msprintf("%s/profile/refresh_token/", SERVER_URI);
  user_req.http_verb = strdup("DELETE");
  ulfius_send_http_request(&user_req, &del_resp);
	ck_assert_int_eq(del_resp.status, 200);
  
  ulfius_clean_response(&list_resp);
  ulfius_clean_response(&del_resp);
}
END_TEST

START_TEST(test_glwd_user_session_list_all_user)
{
  char * url = msprintf("%s/profile/session", SERVER_URI);
  
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_user_session_revoke_ok_user)
{
  struct _u_response list_resp, del_resp;
  int res;
  struct _u_map body;
  json_t * json_resp_body;
  
  u_map_init(&body);
  ulfius_init_response(&list_resp);
  ulfius_init_response(&del_resp);
  user_req.http_url = msprintf("%s/profile/session?valid=true", SERVER_URI);
  res = ulfius_send_http_request(&user_req, &list_resp);
  if (res == U_OK) {
    json_resp_body = ulfius_get_json_body_response(&list_resp, NULL);
    json_t * json_body = json_pack("{ss}", "session_hash", json_string_value(json_object_get(json_array_get(json_resp_body, 0), "session_hash")));
    u_map_put(user_req.map_header, "Content-Type", "application/x-www-form-urlencoded");
    ulfius_set_json_body_request(&user_req, json_body);
    json_decref(json_body);
    json_decref(json_resp_body);
  }
  user_req.http_url = msprintf("%s/profile/session/", SERVER_URI);
  user_req.http_verb = strdup("DELETE");
  ulfius_send_http_request(&user_req, &del_resp);
  
	ck_assert_int_eq(del_resp.status, 200);
  
  u_map_clean(&body);
  ulfius_clean_response(&list_resp);
  ulfius_clean_response(&del_resp);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd HTTP Auth");
  tc_core = tcase_create("test_glwd_http_auth");
  tcase_add_test(tc_core, glewlwyd_resource_owner_pwd_cred_valid_http_auth);
  tcase_add_test(tc_core, test_glwd_crud_user_connect_http_auth_success);
  tcase_add_test(tc_core, test_glwd_crud_user_connect_http_auth_fail);
  tcase_add_test(tc_core, test_glwd_crud_user_check_access_token_http_auth_ok);
  tcase_add_test(tc_core, test_glwd_auth_code_ok_redirect_cb_with_code_http_auth);
  tcase_add_test(tc_core, test_glwd_code_http_auth_ok);
  tcase_add_test(tc_core, test_glwd_implicit_valid_http_auth);
  tcase_add_test(tc_core, test_glwd_refresh_token_ok_http_auth);
  tcase_add_test(tc_core, test_glwd_user_refresh_token_list_all_user);
  tcase_add_test(tc_core, test_glwd_user_refresh_token_revoke_ok_user);
  tcase_add_test(tc_core, test_glwd_user_session_list_all_user);
  tcase_add_test(tc_core, test_glwd_user_session_revoke_ok_user);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed, res;
  Suite *s;
  SRunner *sr;
  struct _u_instance instance;
  struct _u_request auth_req;
  struct _u_response auth_resp, code_resp;
  
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
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", HTTP_USER);
  u_map_put(auth_req.map_post_body, "password", HTTP_PASSWORD);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK) {
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", HTTP_USER);
    int i;
    for (i=0; i<auth_resp.nb_cookies; i++) {
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(user_req.map_header, "Cookie", cookie);
      free(cookie);
    }
    
    ulfius_init_response(&code_resp);
    user_req.http_verb = strdup("GET");
    user_req.http_url = msprintf("%s/auth?response_type=code&login_validated=true&client_id=client1_id&redirect_uri=../app/test-token.html?param=client1_cb1&state=xyzabcd", SERVER_URI);
    if (ulfius_send_http_request(&user_req, &code_resp) != U_OK) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Get code error");
    } else if (strstr(u_map_get(code_resp.map_header, "Location"), "code=") != NULL) {
      code = o_strdup(strstr(u_map_get(code_resp.map_header, "Location"), "code=")+strlen("code="));
      if (strchr(code, '&') != NULL) {
        *strchr(code, '&') = '\0';
      }
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Error, no code given");
    }
    ulfius_clean_response(&code_resp);
  }
  ulfius_clean_response(&auth_resp);
  
  s = glewlwyd_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

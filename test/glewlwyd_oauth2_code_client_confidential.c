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
#define PASSWORD "MyUser1Password!"
#define SCOPE_LIST "scope1 scope2"
#define CLIENT "client3_id"
#define CLIENT_PASSWORD "client3_password"
#define REDIRECT_URI "../app/test-token.html?param=client3_cb"

struct _u_request user_req;
char * code;

START_TEST(test_glwd_code_code_invalid)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", REDIRECT_URI);
  u_map_put(&body, "code", "invalid");
  
  free(user_req.http_verb);
  user_req.http_verb = NULL;
  int res = run_simple_test(&user_req, "POST", url, CLIENT, CLIENT_PASSWORD, NULL, &body, 403, NULL, NULL, NULL);
  free(url);
  u_map_clean(&body);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_code_client_invalid)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "client_id", "invalid");
  u_map_put(&body, "redirect_uri", REDIRECT_URI);
  u_map_put(&body, "code", code);
  
  free(user_req.http_verb);
  user_req.http_verb = NULL;
  int res = run_simple_test(&user_req, "POST", url, CLIENT, CLIENT_PASSWORD, NULL, &body, 403, NULL, "unauthorized_client", NULL);
  free(url);
  u_map_clean(&body);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_code_redirect_uri_invalid)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", "invalid");
  u_map_put(&body, "code", code);
  
  free(user_req.http_verb);
  user_req.http_verb = NULL;
  int res = run_simple_test(&user_req, "POST", url, CLIENT, CLIENT_PASSWORD, NULL, &body, 403, NULL, NULL, NULL);
  free(url);
  u_map_clean(&body);
	ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_glwd_code_ok)
{
  char * url = msprintf("%s/token/", SERVER_URI);
  struct _u_map body;
  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", REDIRECT_URI);
  u_map_put(&body, "code", code);
  
  free(user_req.http_verb);
  user_req.http_verb = NULL;
  int res = run_simple_test(&user_req, "POST", url, CLIENT, CLIENT_PASSWORD, NULL, &body, 200, NULL, "refresh_token", NULL);
  free(url);
  u_map_clean(&body);
	ck_assert_int_eq(res, 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Glewlwyd code client confidential");
	tc_core = tcase_create("test_glwd_code");
	tcase_add_test(tc_core, test_glwd_code_code_invalid);
	tcase_add_test(tc_core, test_glwd_code_client_invalid);
	tcase_add_test(tc_core, test_glwd_code_redirect_uri_invalid);
	tcase_add_test(tc_core, test_glwd_code_ok);
	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	int number_failed;
	Suite *s;
	SRunner *sr;
  struct _u_request auth_req, scope_req;
  struct _u_response auth_resp, code_resp;
  int res;
  char * url;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
  ulfius_init_request(&scope_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/user", SERVER_URI);
  u_map_put(auth_req.map_post_body, "username", USERNAME);
  u_map_put(auth_req.map_post_body, "password", PASSWORD);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK) {
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);
    int i;
    for (i=0; i<auth_resp.nb_cookies; i++) {
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(user_req.map_header, "Cookie", cookie);
      u_map_put(scope_req.map_header, "Cookie", cookie);
      free(cookie);
    }
    ulfius_clean_response(&auth_resp);
    
    ulfius_init_response(&auth_resp);
    scope_req.http_verb = strdup("POST");
    scope_req.http_url = msprintf("%s/auth/grant", SERVER_URI);
    u_map_put(scope_req.map_post_body, "scope", SCOPE_LIST);
    u_map_put(scope_req.map_post_body, "client_id", CLIENT);
    scope_req.auth_basic_user = strdup(CLIENT);
    scope_req.auth_basic_password = strdup(CLIENT_PASSWORD);
    if (ulfius_send_http_request(&scope_req, &auth_resp) != U_OK || auth_resp.status != 200) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope %s for %s error %d", CLIENT, SCOPE_LIST, auth_resp.status);
    } else {
      ulfius_init_response(&code_resp);
      user_req.http_verb = strdup("GET");
      user_req.http_url = msprintf(SERVER_URI "/auth?response_type=code&login_validated=true&state=xyzabcd&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&scope=" SCOPE_LIST);
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
  }
  ulfius_clean_response(&auth_resp);
  
	s = glewlwyd_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
  
  free(scope_req.http_verb);
  scope_req.http_verb = msprintf("DELETE");
    if (ulfius_send_http_request(&auth_req, NULL) != U_OK) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
    }
  
  url = msprintf("%s/auth/user/", SERVER_URI);
  run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  free(url);
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&scope_req);
  ulfius_clean_request(&user_req);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

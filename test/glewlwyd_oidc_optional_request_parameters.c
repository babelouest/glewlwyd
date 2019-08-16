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
#define PASSWORD "password"
#define SCOPE_LIST "openid"
#define CLIENT "client1_id"
#define RESPONSE_TYPE "id_token"

struct _u_request user_req;
char * code;

START_TEST(test_oidc_optional_request_parameters_display)
{
  char * url = msprintf("%s/oidc/auth?response_type=%s&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s&display=page", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  int res = run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "display=page");
  o_free(url);
  ck_assert_int_eq(res, 1);
  
  url = msprintf("%s/oidc/auth?response_type=%s&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s&display=popup", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  res = run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "display=popup");
  o_free(url);
  ck_assert_int_eq(res, 1);
  
  url = msprintf("%s/oidc/auth?response_type=%s&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s&display=touch", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  res = run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "display=touch");
  o_free(url);
  ck_assert_int_eq(res, 1);
  
  url = msprintf("%s/oidc/auth?response_type=%s&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s&display=wap", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  res = run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "display=wap");
  o_free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_optional_request_parameters_prompt_none_no_id_token_hint)
{
  struct _u_response resp;
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/oidc/auth?response_type=%s&prompt=none&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_request"), NULL);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_optional_request_parameters_prompt_none_id_token_hint_invalid)
{
  struct _u_response resp;
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/oidc/auth?response_type=%s&prompt=none&id_token_hint=error&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_request"), NULL);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_optional_request_parameters_prompt_none_id_token_not_last)
{
  struct _u_response resp;
  char * id_token;
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/oidc/auth?response_type=%s&g_continue&id_token_hint=error&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ulfius_clean_response(&resp);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/oidc/auth?response_type=%s&prompt=none&id_token_hint=error&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_request"), NULL);
  ulfius_clean_response(&resp);
  o_free(id_token);
}
END_TEST

START_TEST(test_oidc_optional_request_parameters_prompt_none_id_token_last)
{
  struct _u_response resp;
  char * id_token;
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/oidc/auth?response_type=%s&g_continue&id_token_hint=error&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/oidc/auth?response_type=%s&prompt=none&id_token_hint=%s&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, RESPONSE_TYPE, id_token, CLIENT, SCOPE_LIST);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ulfius_clean_response(&resp);
  o_free(id_token);
}
END_TEST

START_TEST(test_oidc_optional_request_parameters_prompt)
{
  char * url = msprintf("%s/oidc/auth?response_type=%s&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s&prompt=login", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  int res = run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "prompt=login");
  o_free(url);
  ck_assert_int_eq(res, 1);
  
  url = msprintf("%s/oidc/auth?response_type=%s&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s&prompt=consent", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  res = run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "prompt=consent");
  o_free(url);
  ck_assert_int_eq(res, 1);
  
  url = msprintf("%s/oidc/auth?response_type=%s&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s&prompt=select_account", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  res = run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "prompt=select_account");
  o_free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_optional_request_parameters_ui_locales)
{
  char * url = msprintf("%s/oidc/auth?response_type=%s&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s&ui_locales=fr", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  int res = run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "ui_locales=fr");
  o_free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_optional_request_parameters_login_hint)
{
  char * url = msprintf("%s/oidc/auth?response_type=%s&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s&login_hint=myrddin", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  int res = run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "login_hint=myrddin");
  o_free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_optional_request_parameters_max_age)
{
  char * url = msprintf("%s/oidc/auth?response_type=%s&max_age=300&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s&g_continue", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  int res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "id_token=");
  o_free(url);
  ck_assert_int_eq(res, 1);

  url = msprintf("%s/oidc/auth?response_type=%s&max_age=0&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s&g_continue", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "error=invalid_request");
  o_free(url);
  ck_assert_int_eq(res, 1);

  sleep(2);
  url = msprintf("%s/oidc/auth?response_type=%s&max_age=1&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s&g_continue", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  res = run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "login.html");
  o_free(url);
  ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_oidc_optional_request_parameters_unknown)
{
  struct _u_response resp;
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/oidc/auth?response_type=%s&unknown=error&client_id=%s&redirect_uri=../../test-oauth2.html?param=client1_cb1&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "unknown=error"), NULL);
  ulfius_clean_response(&resp);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd implicit");
  tc_core = tcase_create("test_oauth2_implicit");
  tcase_add_test(tc_core, test_oidc_optional_request_parameters_display);
  tcase_add_test(tc_core, test_oidc_optional_request_parameters_prompt_none_no_id_token_hint);
  tcase_add_test(tc_core, test_oidc_optional_request_parameters_prompt_none_id_token_hint_invalid);
  tcase_add_test(tc_core, test_oidc_optional_request_parameters_prompt_none_id_token_not_last);
  tcase_add_test(tc_core, test_oidc_optional_request_parameters_prompt_none_id_token_last);
  tcase_add_test(tc_core, test_oidc_optional_request_parameters_prompt);
  tcase_add_test(tc_core, test_oidc_optional_request_parameters_ui_locales);
  tcase_add_test(tc_core, test_oidc_optional_request_parameters_login_hint);
  tcase_add_test(tc_core, test_oidc_optional_request_parameters_max_age);
  tcase_add_test(tc_core, test_oidc_optional_request_parameters_unknown);
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
  json_t * j_body, * j_register;
  int res, do_test = 0, i;
  char * url;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
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
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_true());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "register", json_true());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_true());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
    ulfius_set_json_body_request(&auth_req, j_body);
    json_decref(j_body);
    res = ulfius_send_http_request(&auth_req, &auth_resp);
    if (res == U_OK && auth_resp.status == 200) {
      j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_true());
      run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
      json_decref(j_register);
      
      ulfius_clean_response(&auth_resp);
      ulfius_init_response(&auth_resp);
      j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
      ulfius_set_json_body_request(&auth_req, j_body);
      json_decref(j_body);
      res = ulfius_send_http_request(&auth_req, &auth_resp);
      if (res == U_OK && auth_resp.status == 200) {
        y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);
    
        scope_req.http_verb = strdup("PUT");
        scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
        j_body = json_pack("{ss}", "scope", SCOPE_LIST);
        ulfius_set_json_body_request(&scope_req, j_body);
        json_decref(j_body);
        if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
        } else {
          do_test = 1;
        }
        ulfius_clean_response(&scope_resp);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Error auth scheme 95");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error auth scheme 42");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error auth password");
  }
  ulfius_clean_response(&auth_resp);

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_false());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "register", json_false());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_false());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
  }
  
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&scope_req, j_body);
  json_decref(j_body);
  if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
  }
  
  url = msprintf("%s/auth/", SERVER_URI);
  run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  o_free(url);
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&scope_req);
  ulfius_clean_request(&register_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

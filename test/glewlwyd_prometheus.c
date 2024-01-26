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
#define METRICS_URI "http://localhost:4594/"
#define USERNAME "user1"
#define PASSWORD "password"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define SCOPE_LIST "g_profile openid"
#define CLIENT "client3_id"
#define CLIENT_SECRET "password"
#define CLIENT_REDIRECT_URI "../../test-oauth2.html?param=client3"
#define RESPONSE_TYPE "code"

struct _u_request admin_req;
struct _u_request user_req;

static int get_metrics(const char * metrics, json_t * labels) {
  struct _u_request req;
  struct _u_response resp;
  char * pattern, * str_result = NULL, ** lines = NULL;
  const char * key = NULL;
  json_t * j_element = NULL;
  int first = 1, int_result = -1;
  size_t i, pattern_len;
  
  ck_assert_ptr_ne(NULL, pattern = o_strdup(metrics));
  if (labels != NULL) {
    ck_assert_ptr_ne(NULL, pattern = mstrcatf(pattern, "{"));
    json_object_foreach(labels, key, j_element) {
      if (!first) {
        ck_assert_ptr_ne(NULL, pattern = mstrcatf(pattern, ", "));
      } else {
        first = 0;
      }
      ck_assert_ptr_ne(NULL, pattern = mstrcatf(pattern, "%s=\"%s\"", key, json_string_value(j_element)));
    }
    ck_assert_ptr_ne(NULL, pattern = mstrcatf(pattern, "}"));
  }
  ck_assert_ptr_ne(NULL, pattern = mstrcatf(pattern, " "));
  ck_assert_int_gt(pattern_len = o_strlen(pattern), 0);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, METRICS_URI,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, str_result = o_strndup((const char *)resp.binary_body, resp.binary_body_length));
  ck_assert_int_gt(split_string(str_result, "\n", &lines), 0);
  
  for (i=0; lines[i] != NULL; i++) {
    if (o_strncmp(lines[i], pattern, pattern_len) == 0) {
      int_result = (int)strtol(lines[i]+pattern_len, NULL, 10);
      break;
    }
  }
  
  free_string_array(lines);
  o_free(pattern);
  o_free(str_result);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  return int_result;
}

START_TEST(test_glwd_prometheus_metrics_open_ok)
{
  ck_assert_int_eq(run_simple_test(NULL, "GET", METRICS_URI, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_prometheus_metrics_auth_pwd_increase)
{
  int nbauth_1, nbauth_2, nbauth_lab_1, nbauth_lab_2, nbauth_scheme_1, nbauth_scheme_2;
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body = NULL, * j_label_pwd = json_pack("{ss}", "scheme_type", "password"), * j_label_scheme = json_pack("{ssss}", "scheme_type", "mock", "scheme_name", "mock_scheme_42");

  ck_assert_int_ne(-1, nbauth_1 = get_metrics("glewlwyd_auth_user_valid_total", NULL));
  ck_assert_int_ne(-1, nbauth_lab_1 = get_metrics("glewlwyd_auth_user_valid_scheme_total", j_label_pwd));
  ck_assert_int_ne(-1, nbauth_scheme_1 = get_metrics("glewlwyd_auth_user_valid_scheme_total", j_label_scheme));

  ulfius_init_request(&req);
  ulfius_init_response(&resp);

  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);

  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  ck_assert_int_ne(-1, nbauth_2 = get_metrics("glewlwyd_auth_user_valid_total", NULL));
  ck_assert_int_ne(-1, nbauth_lab_2 = get_metrics("glewlwyd_auth_user_valid_scheme_total", j_label_pwd));
  ck_assert_int_ne(-1, nbauth_scheme_2 = get_metrics("glewlwyd_auth_user_valid_scheme_total", j_label_scheme));
  ck_assert_int_eq(nbauth_2, nbauth_1+1);
  ck_assert_int_eq(nbauth_lab_2, nbauth_lab_1+1);
  ck_assert_int_eq(nbauth_scheme_1, nbauth_scheme_2);
  
  json_decref(j_label_pwd);
  json_decref(j_label_scheme);
}
END_TEST

START_TEST(test_glwd_prometheus_metrics_auth_invalid_pwd_increase)
{
  int nbauth_1, nbauth_2, nbauth_lab_1, nbauth_lab_2, nbauth_scheme_1, nbauth_scheme_2;
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body = NULL, * j_label_pwd = json_pack("{ss}", "scheme_type", "password"), * j_label_scheme = json_pack("{ssss}", "scheme_type", "mock", "scheme_name", "mock_scheme_42");

  ck_assert_int_ne(-1, nbauth_1 = get_metrics("glewlwyd_auth_user_invalid_total", NULL));
  ck_assert_int_ne(-1, nbauth_lab_1 = get_metrics("glewlwyd_auth_user_invalid_scheme_total", j_label_pwd));
  ck_assert_int_ne(-1, nbauth_scheme_1 = get_metrics("glewlwyd_auth_user_invalid_scheme_total", j_label_scheme));

  ulfius_init_request(&req);
  ulfius_init_response(&resp);

  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);

  j_body = json_pack("{ssss}", "username", USERNAME, "password", "error");
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  ck_assert_int_ne(-1, nbauth_2 = get_metrics("glewlwyd_auth_user_invalid_total", NULL));
  ck_assert_int_ne(-1, nbauth_lab_2 = get_metrics("glewlwyd_auth_user_invalid_scheme_total", j_label_pwd));
  ck_assert_int_ne(-1, nbauth_scheme_2 = get_metrics("glewlwyd_auth_user_invalid_scheme_total", j_label_scheme));
  ck_assert_int_eq(nbauth_2, nbauth_1+1);
  ck_assert_int_eq(nbauth_lab_2, nbauth_lab_1+1);
  ck_assert_int_eq(nbauth_scheme_1, nbauth_scheme_2);
  
  json_decref(j_label_pwd);
  json_decref(j_label_scheme);
}
END_TEST

START_TEST(test_glwd_prometheus_metrics_oidc_flow_ok)
{
  struct _u_request auth_req;
  struct _u_response auth_resp, resp;
  struct _u_map body;
  json_t * j_body;
  char * cookie;
  char * url, * redirect_uri_encoded, * code;
  int code_total_1, code_total_2, idt_total_1, idt_total_2, at_total_1, at_total_2;
  
  ck_assert_int_ne(-1, code_total_1 = get_metrics("glewlwyd_oidc_code_total{plugin=\"oidc\"}", NULL));
  ck_assert_int_ne(-1, idt_total_1 = get_metrics("glewlwyd_oidc_id_token_total{plugin=\"oidc\"}", NULL));
  ck_assert_int_ne(-1, at_total_1 = get_metrics("glewlwyd_oidc_access_token_total{plugin=\"oidc\"}", NULL));
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
  
  url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", url, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  o_free(url);

  // Test id_token framework
  redirect_uri_encoded = ulfius_url_encode(CLIENT_REDIRECT_URI);
  url = msprintf("%s/oidc/auth?response_type=id_token&nonce=nonce1234&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce4321&scope=%s", SERVER_URI, CLIENT, redirect_uri_encoded, SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&auth_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "id_token="), 1);
  o_free(url);
  ck_assert_int_ne(-1, idt_total_2 = get_metrics("glewlwyd_oidc_id_token_total{plugin=\"oidc\"}", NULL));
  ck_assert_int_eq(idt_total_2, idt_total_1+1);
  
  // Test code framework
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_url = msprintf("%s/oidc/auth?response_type=code&nonce=nonce1234&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&scope=%s", SERVER_URI, CLIENT, redirect_uri_encoded, SCOPE_LIST);
  auth_req.http_verb = o_strdup("GET");
  auth_req.auth_basic_user = o_strdup(CLIENT);
  auth_req.auth_basic_password = o_strdup(CLIENT_SECRET);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  url = msprintf("%s/oidc/token/", SERVER_URI);
  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", CLIENT_REDIRECT_URI);
  u_map_put(&body, "code", code);
  ck_assert_int_eq(run_simple_test(NULL, "POST", url, CLIENT, CLIENT_SECRET, NULL, &body, 200, NULL, "id_token", NULL), 1);
  u_map_clean(&body);
  ulfius_clean_response(&resp);
  o_free(url);
  ck_assert_int_ne(-1, code_total_2 = get_metrics("glewlwyd_oidc_code_total{plugin=\"oidc\"}", NULL));
  ck_assert_int_eq(code_total_2, code_total_1+1);
  ck_assert_int_ne(-1, idt_total_2 = get_metrics("glewlwyd_oidc_id_token_total{plugin=\"oidc\"}", NULL));
  ck_assert_int_eq(idt_total_2, idt_total_1+2);
  ck_assert_int_ne(-1, at_total_2 = get_metrics("glewlwyd_oidc_access_token_total{plugin=\"oidc\"}", NULL));
  ck_assert_int_eq(at_total_2, at_total_1+1);


  ulfius_clean_request(&auth_req);
  o_free(cookie);
  o_free(code);
  o_free(redirect_uri_encoded);
}
END_TEST

/*START_TEST(test_glwd_prometheus_metrics_glwd_flow_ok)
{
  struct _u_request auth_req;
  struct _u_response auth_resp, resp;
  struct _u_map body;
  json_t * j_body;
  char * cookie;
  char * url, * redirect_uri_encoded, * code;
  int code_total_1, code_total_2, at_total_1, at_total_2;
  
  ck_assert_int_ne(-1, code_total_1 = get_metrics("glewlwyd_oauth2_code_total{plugin=\"glwd\"}", NULL));
  ck_assert_int_ne(-1, at_total_1 = get_metrics("glewlwyd_oauth2_access_token_total{plugin=\"glwd\"}", NULL));
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
  
  url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", url, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  o_free(url);

  // Test token framework
  redirect_uri_encoded = ulfius_url_encode(CLIENT_REDIRECT_URI);
  url = msprintf("%s/glwd/auth?response_type=token&nonce=nonce1234&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce4321&scope=%s", SERVER_URI, CLIENT, redirect_uri_encoded, SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&auth_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "token="), 1);
  o_free(url);
  ck_assert_int_ne(-1, at_total_2 = get_metrics("glewlwyd_oauth2_access_token_total{plugin=\"glwd\"}", NULL));
  ck_assert_int_eq(at_total_2, at_total_1+1);
  
  // Test code framework
  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_url = msprintf("%s/glwd/auth?response_type=code&nonce=nonce1234&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&scope=%s", SERVER_URI, CLIENT, redirect_uri_encoded, SCOPE_LIST);
  auth_req.http_verb = o_strdup("GET");
  auth_req.auth_basic_user = o_strdup(CLIENT);
  auth_req.auth_basic_password = o_strdup(CLIENT_SECRET);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  url = msprintf("%s/glwd/token/", SERVER_URI);
  u_map_init(&body);
  u_map_put(&body, "grant_type", "authorization_code");
  u_map_put(&body, "client_id", CLIENT);
  u_map_put(&body, "redirect_uri", CLIENT_REDIRECT_URI);
  u_map_put(&body, "code", code);
  ck_assert_int_eq(run_simple_test(NULL, "POST", url, CLIENT, CLIENT_SECRET, NULL, &body, 200, NULL, "token", NULL), 1);
  u_map_clean(&body);
  ulfius_clean_response(&resp);
  o_free(url);
  ck_assert_int_ne(-1, code_total_2 = get_metrics("glewlwyd_oauth2_code_total{plugin=\"glwd\"}", NULL));
  ck_assert_int_eq(code_total_2, code_total_1+1);
  ck_assert_int_ne(-1, at_total_2 = get_metrics("glewlwyd_oauth2_access_token_total{plugin=\"glwd\"}", NULL));
  ck_assert_int_eq(at_total_2, at_total_1+2);

  ulfius_clean_request(&auth_req);
  o_free(cookie);
  o_free(code);
  o_free(redirect_uri_encoded);
}
END_TEST*/

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd prometheus_metrics");
  tc_core = tcase_create("test_glwd_prometheus_metrics");
  tcase_add_test(tc_core, test_glwd_prometheus_metrics_open_ok);
  tcase_add_test(tc_core, test_glwd_prometheus_metrics_auth_pwd_increase);
  tcase_add_test(tc_core, test_glwd_prometheus_metrics_auth_invalid_pwd_increase);
  tcase_add_test(tc_core, test_glwd_prometheus_metrics_oidc_flow_ok);
  //tcase_add_test(tc_core, test_glwd_prometheus_metrics_glwd_flow_ok);
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
  ulfius_init_request(&admin_req);
  admin_req.check_server_certificate = 0;
  ulfius_init_request(&user_req);
  user_req.check_server_certificate = 0;
  
  ulfius_init_request(&auth_req);
  auth_req.check_server_certificate = 0;
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
      y_log_message(Y_LOG_LEVEL_DEBUG, "User %s authenticated", ADMIN_USERNAME);
      do_test = 1;
    }
  } else {
    do_test = 0;
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication %s (%d/%d/%d)", ADMIN_USERNAME, res, auth_resp.status, auth_resp.nb_cookies);
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);

  ulfius_init_request(&auth_req);
  auth_req.check_server_certificate = 0;
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
      y_log_message(Y_LOG_LEVEL_DEBUG, "User %s authenticated", USERNAME);
      do_test = 1;
    }
  } else {
    do_test = 0;
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication %s (%d/%d/%d)", USERNAME, res, auth_resp.status, auth_resp.nb_cookies);
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);
  
  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Tests not executed");
  }
  
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

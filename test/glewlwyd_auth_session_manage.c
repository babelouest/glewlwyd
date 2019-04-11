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
#define SCOPE_LIST "g_profile"

struct _u_request user_req;
char user_agent[33];

START_TEST(test_auth_session_manage_endpoints_noauth)
{
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/profile/session/", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "DELETE", SERVER_URI "/profile/session/test", NULL, NULL, NULL, NULL, 401, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_auth_session_manage_list)
{
  struct _u_response resp;
  json_t * j_body = NULL;
  
  ulfius_init_response(&resp);
  user_req.http_url = o_strdup(SERVER_URI "/profile/session/");
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_gt(json_array_size(j_body), 0);
  
  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/profile/session/?limit=1");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_eq(json_array_size(j_body), 1);

  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/profile/session/?offset=1");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);

  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/profile/session/?sort=authorization_type");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_gt(json_array_size(j_body), 0);

  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/profile/session/?sort=issued_at&desc");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_gt(json_array_size(j_body), 0);

  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/profile/session/?sort=issued_at&desc&limit=1");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_eq(json_array_size(j_body), 1);

  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/profile/session/?pattern=127");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_gt(json_array_size(j_body), 0);

  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/profile/session/?pattern=glwd-auth-test-");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_gt(json_array_size(j_body), 0);

  o_free(user_req.http_url);
  user_req.http_url = o_strdup(SERVER_URI "/profile/session/?pattern=error");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_eq(json_array_size(j_body), 0);

  ulfius_clean_request(&user_req);
  ulfius_clean_response(&resp);
  json_decref(j_body);
}
END_TEST

START_TEST(test_auth_session_manage_delete_not_found)
{
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  user_req.http_url = o_strdup(SERVER_URI "/profile/session/error");
  user_req.http_verb = o_strdup("DELETE");
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 404);
  
  ulfius_clean_request(&user_req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_auth_session_manage_delete_ok)
{
  struct _u_request req, test_req;
  struct _u_response resp;
  char my_user_agent[33], * session_hash = NULL, * session_hash_encoded = NULL, * cookie = NULL;
  json_t * j_body;
  
  ulfius_init_request(&req);
  ulfius_init_request(&test_req);
  ulfius_init_response(&resp);
  test_req.http_url = o_strdup(SERVER_URI "/profile/");
  req.http_verb = strdup("POST");
  req.http_url = msprintf("%s/auth/", SERVER_URI);
  snprintf(my_user_agent, 32, "glwd-auth-test-%d", rand());
  u_map_put(req.map_header, "User-Agent", my_user_agent);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  u_map_put(test_req.map_header, "Cookie", cookie);
  ulfius_clean_response(&resp);
  
  ulfius_init_response(&resp);
  user_req.http_verb = strdup("GET");
  user_req.http_url = msprintf(SERVER_URI "/profile/session/?pattern=%s", my_user_agent);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_body, NULL);
  ck_assert_int_gt(json_array_size(j_body), 0);
  session_hash = o_strdup(json_string_value(json_object_get(json_array_get(j_body, 0), "session_hash")));
  session_hash_encoded = ulfius_url_encode(session_hash);
  ulfius_clean_response(&resp);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&test_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_response(&resp);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_verb);
  o_free(user_req.http_url);
  user_req.http_verb = strdup("DELETE");
  user_req.http_url = msprintf(SERVER_URI "/profile/session/%s", session_hash_encoded);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_response(&resp);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&test_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  ulfius_clean_request(&test_req);
  o_free(session_hash);
  o_free(session_hash_encoded);
  o_free(cookie);
  
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd profile");
  tc_core = tcase_create("test_auth_session_manage");
  tcase_add_test(tc_core, test_auth_session_manage_endpoints_noauth);
  tcase_add_test(tc_core, test_auth_session_manage_list);
  tcase_add_test(tc_core, test_auth_session_manage_delete_not_found);
  tcase_add_test(tc_core, test_auth_session_manage_delete_ok);
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
  
  srand(time(NULL));
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  snprintf(user_agent, 32, "glwd-auth-test-%d", rand());
  u_map_put(auth_req.map_header, "User-Agent", user_agent);
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
  
  ulfius_clean_request(&user_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

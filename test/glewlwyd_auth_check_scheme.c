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
#define SCOPE_LIST_ALLOWED "scope1 scope2 scope3"
#define SCOPE_LIST_FORBIDDEN "g_admin"
#define SCOPE_LIST_MISSING "scope4"

START_TEST(test_glwd_auth_check_scheme_no_session)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body, * j_element;
  const char * key;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);

  req.http_verb = strdup("GET");
  req.http_url = msprintf("%s/auth/scheme/?scope=%s", SERVER_URI, SCOPE_LIST_ALLOWED);

  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_object_size(j_body), 3);
  json_object_foreach(j_body, key, j_element) {
    ck_assert_int_eq(json_object_size(j_element), 0);
  }
  json_decref(j_body);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_glwd_auth_check_scheme_session_password)
{
  struct _u_request auth_req, check_req;
  struct _u_response auth_resp, check_resp;
  json_t * j_body, * j_element, * j_group;
  char * cookie;
  const char * key;

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_request(&check_req);
  ulfius_init_response(&check_resp);

  // Authenticate with password
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  // Get session cookie
  cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
  u_map_put(check_req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);

  check_req.http_verb = strdup("GET");
  check_req.http_url = msprintf("%s/auth/scheme/?scope=%s", SERVER_URI, SCOPE_LIST_ALLOWED);

  ck_assert_int_eq(ulfius_send_http_request(&check_req, &check_resp), U_OK);
  ck_assert_int_eq(check_resp.status, 200);
  j_body = ulfius_get_json_body_response(&check_resp, NULL);
  ck_assert_int_eq(json_object_size(j_body), 3);
  json_object_foreach(j_body, key, j_element) {
    ck_assert_ptr_eq(json_object_get(j_element, "password_authenticated"), json_true());
    if (0 == o_strcmp("scope2", key)) {
      ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_false());
    } else {
      ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_true());
    }
    ck_assert_ptr_eq(json_object_get(j_element, "available"), json_true());
    if (0 == o_strcmp("scope1", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 2);
      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_1");
      ck_assert_int_eq(json_array_size(j_group), 2);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_42");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 1), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 1), "scheme_authenticated"), json_false());

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_2");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else if (0 == o_strcmp("scope2", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_3");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else if (0 == o_strcmp("scope3", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_4");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else {
      // This should not happen, end test
      ck_assert_int_eq(0, 1);
    }
  }
  json_decref(j_body);

  ulfius_clean_request(&check_req);
  ulfius_clean_response(&check_resp);
}
END_TEST

START_TEST(test_glwd_auth_check_scheme_session_password_schemes)
{
  struct _u_request auth_req, check_req;
  struct _u_response auth_resp, check_resp;
  json_t * j_body, * j_element, * j_group, * j_register;
  char * cookie;
  const char * key;

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_request(&check_req);
  ulfius_init_response(&check_resp);

  // Authenticate with password
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  // Get session cookie
  cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
  u_map_put(check_req.map_header, "Cookie", cookie);
  u_map_put(auth_req.map_header, "Cookie", cookie);
  o_free(cookie);

  check_req.http_verb = strdup("GET");
  check_req.http_url = msprintf("%s/auth/scheme/?scope=%s", SERVER_URI, SCOPE_LIST_ALLOWED);

  ck_assert_int_eq(ulfius_send_http_request(&check_req, &check_resp), U_OK);
  ck_assert_int_eq(check_resp.status, 200);
  j_body = ulfius_get_json_body_response(&check_resp, NULL);
  ck_assert_int_eq(json_object_size(j_body), 3);
  json_object_foreach(j_body, key, j_element) {
    ck_assert_ptr_eq(json_object_get(j_element, "password_authenticated"), json_true());
    if (0 == o_strcmp("scope2", key)) {
      ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_false());
    } else {
      ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_true());
    }
    ck_assert_ptr_eq(json_object_get(j_element, "available"), json_true());
    if (0 == o_strcmp("scope1", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 2);
      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_1");
      ck_assert_int_eq(json_array_size(j_group), 2);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_42");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 1), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 1), "scheme_authenticated"), json_false());

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_2");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else if (0 == o_strcmp("scope2", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_3");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else if (0 == o_strcmp("scope3", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_4");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else {
      // This should not happen, end test
      ck_assert_int_eq(0, 1);
    }
  }
  json_decref(j_body);
  
  j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/auth/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);

  // Authenticate scheme mock 42
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  ck_assert_int_eq(ulfius_send_http_request(&check_req, &check_resp), U_OK);
  ck_assert_int_eq(check_resp.status, 200);
  j_body = ulfius_get_json_body_response(&check_resp, NULL);
  ck_assert_int_eq(json_object_size(j_body), 3);
  json_object_foreach(j_body, key, j_element) {
    ck_assert_ptr_eq(json_object_get(j_element, "password_authenticated"), json_true());
    if (0 == o_strcmp("scope2", key)) {
      ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_false());
    } else {
      ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_true());
    }
    ck_assert_ptr_eq(json_object_get(j_element, "available"), json_true());
    if (0 == o_strcmp("scope1", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 2);
      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_1");
      ck_assert_int_eq(json_array_size(j_group), 2);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_42");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_true());
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 1), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 1), "scheme_authenticated"), json_false());

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_2");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else if (0 == o_strcmp("scope2", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_3");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else if (0 == o_strcmp("scope3", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_4");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else {
      // This should not happen, end test
      ck_assert_int_eq(0, 1);
    }
  }
  json_decref(j_body);

  j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_false());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/auth/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);

  j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/auth/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);

  // Authenticate scheme mock 88
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "code", "88");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  ck_assert_int_eq(ulfius_send_http_request(&check_req, &check_resp), U_OK);
  ck_assert_int_eq(check_resp.status, 200);
  j_body = ulfius_get_json_body_response(&check_resp, NULL);
  ck_assert_int_eq(json_object_size(j_body), 3);
  json_object_foreach(j_body, key, j_element) {
    ck_assert_ptr_eq(json_object_get(j_element, "password_authenticated"), json_true());
    if (0 == o_strcmp("scope2", key)) {
      ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_false());
    } else {
      ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_true());
    }
    ck_assert_ptr_eq(json_object_get(j_element, "available"), json_true());
    if (0 == o_strcmp("scope1", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 2);
      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_1");
      ck_assert_int_eq(json_array_size(j_group), 2);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_42");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_true());
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 1), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 1), "scheme_authenticated"), json_true());

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_2");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else if (0 == o_strcmp("scope2", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_3");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else if (0 == o_strcmp("scope3", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_4");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_true());
    } else {
      // This should not happen, end test
      ck_assert_int_eq(0, 1);
    }
  }
  json_decref(j_body);

  j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "register", json_false());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/auth/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);

  j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_true());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/auth/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);

  // Authenticate scheme mock 95
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  ck_assert_int_eq(ulfius_send_http_request(&check_req, &check_resp), U_OK);
  ck_assert_int_eq(check_resp.status, 200);
  j_body = ulfius_get_json_body_response(&check_resp, NULL);
  ck_assert_int_eq(json_object_size(j_body), 3);
  json_object_foreach(j_body, key, j_element) {
    ck_assert_ptr_eq(json_object_get(j_element, "password_authenticated"), json_true());
    if (0 == o_strcmp("scope2", key)) {
      ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_false());
    } else {
      ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_true());
    }
    ck_assert_ptr_eq(json_object_get(j_element, "available"), json_true());
    if (0 == o_strcmp("scope1", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 2);
      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_1");
      ck_assert_int_eq(json_array_size(j_group), 2);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_42");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_true());
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 1), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 1), "scheme_authenticated"), json_true());

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_2");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_true());
    } else if (0 == o_strcmp("scope2", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_3");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_true());
    } else if (0 == o_strcmp("scope3", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_4");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_true());
    } else {
      // This should not happen, end test
      ck_assert_int_eq(0, 1);
    }
  }
  json_decref(j_body);

  j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_false());
  ck_assert_int_eq(run_simple_test(&auth_req, "POST", SERVER_URI "/auth/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_register);

  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&check_req);
  ulfius_clean_response(&check_resp);
}
END_TEST

START_TEST(test_glwd_auth_check_scheme_forbidden)
{
  struct _u_request auth_req, check_req;
  struct _u_response auth_resp, check_resp;
  json_t * j_body, * j_element, * j_group;
  char * cookie;
  const char * key;

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_request(&check_req);
  ulfius_init_response(&check_resp);

  // Authenticate with password
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  // Get session cookie
  cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
  u_map_put(check_req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);

  check_req.http_verb = strdup("GET");
  check_req.http_url = msprintf("%s/auth/scheme/?scope=%s", SERVER_URI, SCOPE_LIST_ALLOWED " " SCOPE_LIST_FORBIDDEN);

  ck_assert_int_eq(ulfius_send_http_request(&check_req, &check_resp), U_OK);
  ck_assert_int_eq(check_resp.status, 200);
  j_body = ulfius_get_json_body_response(&check_resp, NULL);
  ck_assert_int_eq(json_object_size(j_body), 4);
  json_object_foreach(j_body, key, j_element) {
    if (0 != o_strcmp(SCOPE_LIST_FORBIDDEN, key)) {
      ck_assert_ptr_eq(json_object_get(j_element, "password_authenticated"), json_true());
      if (0 == o_strcmp("scope2", key)) {
        ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_false());
      } else {
        ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_true());
      }
      ck_assert_ptr_eq(json_object_get(j_element, "available"), json_true());
    } else {
      ck_assert_ptr_eq(json_object_get(j_element, "password_authenticated"), NULL);
      ck_assert_ptr_eq(json_object_get(j_element, "available"), json_false());
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 0);
    }
    if (0 == o_strcmp("scope1", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 2);
      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_1");
      ck_assert_int_eq(json_array_size(j_group), 2);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_42");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 1), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 1), "scheme_authenticated"), json_false());

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_2");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else if (0 == o_strcmp("scope2", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_3");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else if (0 == o_strcmp("scope3", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_4");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    }
  }
  json_decref(j_body);

  ulfius_clean_request(&check_req);
  ulfius_clean_response(&check_resp);
}
END_TEST

START_TEST(test_glwd_auth_check_scheme_missing)
{
  struct _u_request auth_req, check_req;
  struct _u_response auth_resp, check_resp;
  json_t * j_body, * j_element, * j_group;
  char * cookie;
  const char * key;

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_request(&check_req);
  ulfius_init_response(&check_resp);

  // Authenticate with password
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &auth_resp), U_OK);
  ck_assert_int_eq(auth_resp.status, 200);
  ck_assert_int_eq(auth_resp.nb_cookies, 1);

  // Get session cookie
  cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
  u_map_put(check_req.map_header, "Cookie", cookie);
  o_free(cookie);
  ulfius_clean_request(&auth_req);
  ulfius_clean_response(&auth_resp);

  check_req.http_verb = strdup("GET");
  check_req.http_url = msprintf("%s/auth/scheme/?scope=%s", SERVER_URI, SCOPE_LIST_ALLOWED " " SCOPE_LIST_MISSING);

  ck_assert_int_eq(ulfius_send_http_request(&check_req, &check_resp), U_OK);
  ck_assert_int_eq(check_resp.status, 200);
  j_body = ulfius_get_json_body_response(&check_resp, NULL);
  ck_assert_int_eq(json_object_size(j_body), 3);
  json_object_foreach(j_body, key, j_element) {
    ck_assert_ptr_eq(json_object_get(j_element, "password_authenticated"), json_true());
    if (0 == o_strcmp("scope2", key)) {
      ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_false());
    } else {
      ck_assert_ptr_eq(json_object_get(j_element, "password_required"), json_true());
    }
    ck_assert_ptr_eq(json_object_get(j_element, "available"), json_true());
    if (0 == o_strcmp("scope1", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 2);
      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_1");
      ck_assert_int_eq(json_array_size(j_group), 2);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_42");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 1), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 1), "scheme_authenticated"), json_false());

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_2");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else if (0 == o_strcmp("scope2", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_3");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_95");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else if (0 == o_strcmp("scope3", key)) {
      ck_assert_int_eq(json_object_size(json_object_get(j_element, "schemes")), 1);

      j_group = json_object_get(json_object_get(j_element, "schemes"), "mock_group_4");
      ck_assert_int_eq(json_array_size(j_group), 1);
      ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_group, 0), "scheme_name")), "mock_scheme_88");
      ck_assert_ptr_eq(json_object_get(json_array_get(j_group, 0), "scheme_authenticated"), json_false());
    } else {
      // This shouldn't happen
      ck_assert_int_eq(0, 1);
    }
  }
  json_decref(j_body);

  o_free(check_req.http_url);
  check_req.http_url = msprintf("%s/auth/scheme/?scope=%s", SERVER_URI, SCOPE_LIST_MISSING);
  ck_assert_int_eq(ulfius_send_http_request(&check_req, &check_resp), U_OK);
  ck_assert_int_eq(check_resp.status, 404);

  ulfius_clean_request(&check_req);
  ulfius_clean_response(&check_resp);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd delete token");
  tc_core = tcase_create("test_glwd_auth_check_scheme");
  tcase_add_test(tc_core, test_glwd_auth_check_scheme_no_session);
  tcase_add_test(tc_core, test_glwd_auth_check_scheme_session_password);
  tcase_add_test(tc_core, test_glwd_auth_check_scheme_session_password_schemes);
  tcase_add_test(tc_core, test_glwd_auth_check_scheme_missing);
  tcase_add_test(tc_core, test_glwd_auth_check_scheme_forbidden);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  s = glewlwyd_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

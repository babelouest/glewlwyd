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
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define USER_USERNAME "user1"
#define USER_PASSWORD "password"
#define PLUGIN_PUBLIC "oidc_public"
#define PLUGIN_PAIRWISE "oidc_pairwise"
#define SCOPE_LIST "g_profile openid"
#define CLIENT1 "client1_id"
#define CLIENT1_URL "../../test-oidc.html?param=client1_cb1"
#define CLIENT3 "client3_id"
#define CLIENT3_URL "../../test-oidc.html?param=client3"
#define CLIENT4 "client4_id"
#define CLIENT4_URL "../../test-oidc.html?param=client4"
#define RESPONSE_TYPE "id_token"

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_oidc_subject_type_add_plugin_public)
{
  json_t * j_param = json_pack("{sssssss{sssssssssisisisososososososososs}}",
                                "module",
                                "oidc",
                                "name",
                                PLUGIN_PUBLIC,
                                "display_name",
                                PLUGIN_PUBLIC,
                                "parameters",
                                  "iss",
                                  "https://glewlwyd.tld",
                                  "jwt-type",
                                  "sha",
                                  "jwt-key-size",
                                  "256",
                                  "key",
                                  "secret_" PLUGIN_PUBLIC,
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
                                  "subject-type",
                                  "public");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_subject_type_public_sub_equal)
{
  struct _u_response resp;
  char * id_token, ** id_token_split = NULL, * str_payload;
  char * sub_client1 = NULL, * sub_client3 = NULL, * sub_client4;
  size_t str_payload_len = 0;
  json_t * j_payload;
  
  // Client 1
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_PUBLIC, RESPONSE_TYPE, CLIENT1, CLIENT1_URL, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  id_token = o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token=");
  if (o_strchr(id_token, '&') != NULL) {
    *o_strchr(id_token, '&') = '\0';
  }
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), NULL, &str_payload_len), 1);
  ck_assert_ptr_ne((str_payload = o_malloc(str_payload_len + 3)), NULL);
  ck_assert_int_eq(o_base64url_decode((unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  str_payload[str_payload_len] = '\0';
  ck_assert_ptr_ne((j_payload = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_ptr_ne(json_object_get(j_payload, "sub"), NULL);
  sub_client1 = o_strdup(json_string_value(json_object_get(j_payload, "sub")));
  
  ulfius_clean_response(&resp);
  free_string_array(id_token_split);
  o_free(str_payload);
  json_decref(j_payload);
  
  // Client 3
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_PUBLIC, RESPONSE_TYPE, CLIENT3, CLIENT3_URL, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  id_token = o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token=");
  if (o_strchr(id_token, '&') != NULL) {
    *o_strchr(id_token, '&') = '\0';
  }
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), NULL, &str_payload_len), 1);
  ck_assert_ptr_ne((str_payload = o_malloc(str_payload_len + 3)), NULL);
  ck_assert_int_eq(o_base64url_decode((unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  str_payload[str_payload_len] = '\0';
  ck_assert_ptr_ne((j_payload = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_ptr_ne(json_object_get(j_payload, "sub"), NULL);
  sub_client3 = o_strdup(json_string_value(json_object_get(j_payload, "sub")));
  
  ulfius_clean_response(&resp);
  free_string_array(id_token_split);
  o_free(str_payload);
  json_decref(j_payload);
  
  // Client 4
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_PUBLIC, RESPONSE_TYPE, CLIENT4, CLIENT4_URL, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  id_token = o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token=");
  if (o_strchr(id_token, '&') != NULL) {
    *o_strchr(id_token, '&') = '\0';
  }
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), NULL, &str_payload_len), 1);
  ck_assert_ptr_ne((str_payload = o_malloc(str_payload_len + 3)), NULL);
  ck_assert_int_eq(o_base64url_decode((unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  str_payload[str_payload_len] = '\0';
  ck_assert_ptr_ne((j_payload = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_ptr_ne(json_object_get(j_payload, "sub"), NULL);
  sub_client4 = o_strdup(json_string_value(json_object_get(j_payload, "sub")));
  
  ulfius_clean_response(&resp);
  free_string_array(id_token_split);
  o_free(str_payload);
  json_decref(j_payload);
  
  ck_assert_str_eq(sub_client1, sub_client3);
  ck_assert_str_eq(sub_client1, sub_client4);
  
  o_free(sub_client1);
  o_free(sub_client3);
  o_free(sub_client4);
}
END_TEST

START_TEST(test_oidc_subject_type_delete_plugin_public)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_PUBLIC, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_subject_type_add_plugin_pairwise)
{
  json_t * j_param = json_pack("{sssssss{sssssssssisisisososososososososs}}",
                                "module",
                                "oidc",
                                "name",
                                PLUGIN_PAIRWISE,
                                "display_name",
                                PLUGIN_PAIRWISE,
                                "parameters",
                                  "iss",
                                  "https://glewlwyd.tld",
                                  "jwt-type",
                                  "sha",
                                  "jwt-key-size",
                                  "256",
                                  "key",
                                  "secret_" PLUGIN_PAIRWISE,
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
                                  "subject-type",
                                  "pairwise");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_subject_type_pairwise_sub_different)
{
  struct _u_response resp;
  char * id_token, ** id_token_split = NULL, * str_payload;
  char * sub_client1 = NULL, * sub_client3 = NULL, * sub_client4;
  size_t str_payload_len = 0;
  json_t * j_payload;
  
  // Client 1
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_PAIRWISE, RESPONSE_TYPE, CLIENT1, CLIENT1_URL, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  id_token = o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token=");
  if (o_strchr(id_token, '&') != NULL) {
    *o_strchr(id_token, '&') = '\0';
  }
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), NULL, &str_payload_len), 1);
  ck_assert_ptr_ne((str_payload = o_malloc(str_payload_len + 3)), NULL);
  ck_assert_int_eq(o_base64url_decode((unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  str_payload[str_payload_len] = '\0';
  ck_assert_ptr_ne((j_payload = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_ptr_ne(json_object_get(j_payload, "sub"), NULL);
  sub_client1 = o_strdup(json_string_value(json_object_get(j_payload, "sub")));
  
  ulfius_clean_response(&resp);
  free_string_array(id_token_split);
  o_free(str_payload);
  json_decref(j_payload);
  
  // Client 3
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_PAIRWISE, RESPONSE_TYPE, CLIENT3, CLIENT3_URL, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  id_token = o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token=");
  if (o_strchr(id_token, '&') != NULL) {
    *o_strchr(id_token, '&') = '\0';
  }
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), NULL, &str_payload_len), 1);
  ck_assert_ptr_ne((str_payload = o_malloc(str_payload_len + 3)), NULL);
  ck_assert_int_eq(o_base64url_decode((unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  str_payload[str_payload_len] = '\0';
  ck_assert_ptr_ne((j_payload = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_ptr_ne(json_object_get(j_payload, "sub"), NULL);
  sub_client3 = o_strdup(json_string_value(json_object_get(j_payload, "sub")));
  
  ulfius_clean_response(&resp);
  free_string_array(id_token_split);
  o_free(str_payload);
  json_decref(j_payload);
  
  // Client 4
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_PAIRWISE, RESPONSE_TYPE, CLIENT4, CLIENT4_URL, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  id_token = o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token=");
  if (o_strchr(id_token, '&') != NULL) {
    *o_strchr(id_token, '&') = '\0';
  }
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), NULL, &str_payload_len), 1);
  ck_assert_ptr_ne((str_payload = o_malloc(str_payload_len + 3)), NULL);
  ck_assert_int_eq(o_base64url_decode((unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  str_payload[str_payload_len] = '\0';
  ck_assert_ptr_ne((j_payload = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_ptr_ne(json_object_get(j_payload, "sub"), NULL);
  sub_client4 = o_strdup(json_string_value(json_object_get(j_payload, "sub")));
  
  ulfius_clean_response(&resp);
  free_string_array(id_token_split);
  o_free(str_payload);
  json_decref(j_payload);
  
  ck_assert_str_eq(sub_client1, sub_client3);
  ck_assert_str_ne(sub_client1, sub_client4);
  
  o_free(sub_client1);
  o_free(sub_client3);
  o_free(sub_client4);
}
END_TEST

START_TEST(test_oidc_subject_type_delete_plugin_pairwise)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_PAIRWISE, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd subject type");
  tc_core = tcase_create("test_oidc_subject_type");
  tcase_add_test(tc_core, test_oidc_subject_type_add_plugin_public);
  tcase_add_test(tc_core, test_oidc_subject_type_public_sub_equal);
  tcase_add_test(tc_core, test_oidc_subject_type_delete_plugin_public);
  tcase_add_test(tc_core, test_oidc_subject_type_add_plugin_pairwise);
  tcase_add_test(tc_core, test_oidc_subject_type_pairwise_sub_different);
  tcase_add_test(tc_core, test_oidc_subject_type_delete_plugin_pairwise);
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
        scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT1);
        j_body = json_pack("{ss}", "scope", SCOPE_LIST);
        ulfius_set_json_body_request(&scope_req, j_body);
        json_decref(j_body);
        if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK || scope_resp.status != 200) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", SCOPE_LIST, CLIENT1);
          do_test = 0;
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope OK");
        }
        ulfius_clean_response(&scope_resp);
        
        ulfius_init_response(&scope_resp);
        o_free(scope_req.http_url);
        scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT3);
        if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK || scope_resp.status != 200) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", SCOPE_LIST, CLIENT3);
          do_test = 0;
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope OK");
        }
        ulfius_clean_response(&scope_resp);
        
        ulfius_init_response(&scope_resp);
        o_free(scope_req.http_url);
        scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT4);
        if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK || scope_resp.status != 200) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", SCOPE_LIST, CLIENT4);
          do_test = 0;
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope OK");
        }
        ulfius_clean_response(&scope_resp);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication user %s", USER_USERNAME);
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
  
  if (do_test) {
    j_body = json_pack("{ss}", "scope", "");
    ulfius_set_json_body_request(&scope_req, j_body);
    json_decref(j_body);
    o_free(scope_req.http_url);
    scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT1);
    if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT1, SCOPE_LIST);
    }
    
    o_free(scope_req.http_url);
    scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT3);
    if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT3, SCOPE_LIST);
    }
    
    o_free(scope_req.http_url);
    scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT4);
    if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT4, SCOPE_LIST);
    }
    
    char * url = msprintf("%s/auth/", SERVER_URI);
    run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
    o_free(url);
  }
  
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&scope_req);
  y_close_logs();
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

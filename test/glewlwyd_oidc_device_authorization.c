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
#define SCOPE_LIST "openid g_profile"
#define NONCE_TEST "nonce5678"
#define STATE_TEST "abcxyz"

#define PLUGIN_MODULE "oidc"
#define PLUGIN_NAME "oidc_device"
#define PLUGIN_DISPLAY_NAME "oidc with device authorization"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_ACCESS_TOKEN_DURATION 3600

#define CLIENT_ID "client_device"
#define CLIENT_NAME "client for device"
#define CLIENT_SECRET "very-secret"

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_oidc_device_authorization_add_module_ok)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisosososososososo}}",
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
                                  "auth-type-device-enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_device_authorization_add_client_confidential_ok)
{
  json_t * j_parameters = json_pack("{sssssssos[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "client_secret", CLIENT_SECRET,
                                "confidential", json_true(),
                                "authorization_type", "device_authorization",
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_device_authorization_add_client_public_ok)
{
  json_t * j_parameters = json_pack("{sssssos[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "confidential", json_false(),
                                "authorization_type", "device_authorization",
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_device_authorization_add_client_unauthorized)
{
  json_t * j_parameters = json_pack("{sssssos[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "confidential", json_false(),
                                "authorization_type", "code",
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_device_authorization_delete_module)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_device_authorization_delete_client)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_device_authorization_client_cred_post_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "client_secret", CLIENT_SECRET);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_device_authorization_client_cred_header_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_device_authorization_client_cred_header_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup("error");
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(403, resp.status);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_device_authorization_client_cred_header_no_post_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_device_authorization_client_pub_post_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_device_authorization_client_pub_post_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(403, resp.status);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_device_authorization_user_code_redirect_login_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * redirect_uri;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device/");
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(redirect_uri = u_map_get(resp.map_header, "Location"), NULL);
  ck_assert_ptr_ne(o_strstr(redirect_uri, "prompt=device"), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_device_authorization_user_code_input_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * redirect_uri;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  json_decref(j_resp);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/device?code=error&g_continue");
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(redirect_uri = u_map_get(resp.map_header, "Location"), NULL);
  ck_assert_ptr_ne(o_strstr(redirect_uri, "prompt=deviceCodeError"), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_device_authorization_user_code_input_redirect_login_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * redirect_uri, * code;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_ptr_ne(code = json_string_value(json_object_get(j_resp, "user_code")), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/device?code=%s&g_continue", code);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(redirect_uri = u_map_get(resp.map_header, "Location"), NULL);
  ck_assert_ptr_ne(o_strstr(redirect_uri, "login.html"), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_resp);
}
END_TEST

START_TEST(test_oidc_device_authorization_user_code_input_complete_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_grant;
  const char * redirect_uri, * code;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_ptr_ne(code = json_string_value(json_object_get(j_resp, "user_code")), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  j_grant = json_pack("{ss}", "scope", SCOPE_LIST);
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL);
  json_decref(j_grant);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/device?code=%s&g_continue", code);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(redirect_uri = u_map_get(resp.map_header, "Location"), NULL);
  ck_assert_ptr_ne(o_strstr(redirect_uri, "prompt=deviceComplete"), NULL);
  ulfius_clean_response(&resp);
  json_decref(j_resp);
  
  j_grant = json_pack("{ss}", "scope", "");
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL);
  json_decref(j_grant);
  
}
END_TEST

START_TEST(test_oidc_device_authorization_device_verification_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_grant;
  const char * redirect_uri, * code, * device_code;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_ptr_ne(code = json_string_value(json_object_get(j_resp, "user_code")), NULL);
  ck_assert_ptr_ne(device_code = json_string_value(json_object_get(j_resp, "device_code")), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  j_grant = json_pack("{ss}", "scope", SCOPE_LIST);
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL);
  json_decref(j_grant);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/device?code=%s&g_continue", code);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(redirect_uri = u_map_get(resp.map_header, "Location"), NULL);
  ck_assert_ptr_ne(o_strstr(redirect_uri, "prompt=deviceComplete"), NULL);
  ulfius_clean_response(&resp);
  
  j_grant = json_pack("{ss}", "scope", "");
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL);
  json_decref(j_grant);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "refresh_token"), NULL);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_device_authorization_device_verification_auth_pending)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * code, * device_code;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_ptr_ne(code = json_string_value(json_object_get(j_resp, "user_code")), NULL);
  ck_assert_ptr_ne(device_code = json_string_value(json_object_get(j_resp, "device_code")), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "error")), "authorization_pending");
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_device_authorization_device_verification_auth_slow_down)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * code, * device_code;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_ptr_ne(code = json_string_value(json_object_get(j_resp, "user_code")), NULL);
  ck_assert_ptr_ne(device_code = json_string_value(json_object_get(j_resp, "device_code")), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "error")), "authorization_pending");
  ulfius_clean_response(&resp);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "error")), "slow_down");
  ulfius_clean_response(&resp);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  
}
END_TEST

START_TEST(test_oidc_device_authorization_device_verification_device_code_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_grant;
  const char * redirect_uri, * code;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_ptr_ne(code = json_string_value(json_object_get(j_resp, "user_code")), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  j_grant = json_pack("{ss}", "scope", SCOPE_LIST);
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL);
  json_decref(j_grant);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/device?code=%s&g_continue", code);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(redirect_uri = u_map_get(resp.map_header, "Location"), NULL);
  ck_assert_ptr_ne(o_strstr(redirect_uri, "prompt=deviceComplete"), NULL);
  ulfius_clean_response(&resp);
  
  j_grant = json_pack("{ss}", "scope", "");
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL);
  json_decref(j_grant);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", "error");
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_device_authorization_device_verification_client_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_grant;
  const char * redirect_uri, * code, * device_code;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_ptr_ne(code = json_string_value(json_object_get(j_resp, "user_code")), NULL);
  ck_assert_ptr_ne(device_code = json_string_value(json_object_get(j_resp, "device_code")), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  j_grant = json_pack("{ss}", "scope", SCOPE_LIST);
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL);
  json_decref(j_grant);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/device?code=%s&g_continue", code);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(redirect_uri = u_map_get(resp.map_header, "Location"), NULL);
  ck_assert_ptr_ne(o_strstr(redirect_uri, "prompt=deviceComplete"), NULL);
  ulfius_clean_response(&resp);
  
  j_grant = json_pack("{ss}", "scope", "");
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL);
  json_decref(j_grant);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", "client1_id");
  u_map_put(req.map_post_body, "device_code", device_code);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(403, resp.status);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_device_authorization_device_verification_client_secret_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_grant;
  const char * redirect_uri, * code, * device_code;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_ptr_ne(code = json_string_value(json_object_get(j_resp, "user_code")), NULL);
  ck_assert_ptr_ne(device_code = json_string_value(json_object_get(j_resp, "device_code")), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/oidc_device/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  j_grant = json_pack("{ss}", "scope", SCOPE_LIST);
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL);
  json_decref(j_grant);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/device?code=%s&g_continue", code);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(redirect_uri = u_map_get(resp.map_header, "Location"), NULL);
  ck_assert_ptr_ne(o_strstr(redirect_uri, "prompt=deviceComplete"), NULL);
  ulfius_clean_response(&resp);
  
  j_grant = json_pack("{ss}", "scope", "");
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL);
  json_decref(j_grant);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup("error");
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(403, resp.status);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc device authorization");
  tc_core = tcase_create("test_oidc_device_authorization");
  tcase_add_test(tc_core, test_oidc_device_authorization_add_module_ok);
  tcase_add_test(tc_core, test_oidc_device_authorization_add_client_public_ok);
  tcase_add_test(tc_core, test_oidc_device_authorization_client_pub_post_valid);
  tcase_add_test(tc_core, test_oidc_device_authorization_delete_client);
  tcase_add_test(tc_core, test_oidc_device_authorization_add_client_unauthorized);
  tcase_add_test(tc_core, test_oidc_device_authorization_client_pub_post_invalid);
  tcase_add_test(tc_core, test_oidc_device_authorization_delete_client);
  tcase_add_test(tc_core, test_oidc_device_authorization_add_client_confidential_ok);
  tcase_add_test(tc_core, test_oidc_device_authorization_client_cred_post_valid);
  tcase_add_test(tc_core, test_oidc_device_authorization_client_cred_header_valid);
  tcase_add_test(tc_core, test_oidc_device_authorization_client_cred_header_no_post_valid);
  tcase_add_test(tc_core, test_oidc_device_authorization_client_cred_header_invalid);
  tcase_add_test(tc_core, test_oidc_device_authorization_user_code_redirect_login_valid);
  tcase_add_test(tc_core, test_oidc_device_authorization_user_code_input_invalid);
  tcase_add_test(tc_core, test_oidc_device_authorization_user_code_input_redirect_login_valid);
  tcase_add_test(tc_core, test_oidc_device_authorization_user_code_input_complete_valid);
  tcase_add_test(tc_core, test_oidc_device_authorization_device_verification_valid);
  tcase_add_test(tc_core, test_oidc_device_authorization_device_verification_auth_pending);
  tcase_add_test(tc_core, test_oidc_device_authorization_device_verification_auth_slow_down);
  tcase_add_test(tc_core, test_oidc_device_authorization_device_verification_device_code_invalid);
  tcase_add_test(tc_core, test_oidc_device_authorization_device_verification_client_invalid);
  tcase_add_test(tc_core, test_oidc_device_authorization_device_verification_client_secret_invalid);
  tcase_add_test(tc_core, test_oidc_device_authorization_delete_client);
  tcase_add_test(tc_core, test_oidc_device_authorization_delete_module);
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

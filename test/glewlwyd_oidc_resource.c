/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <check.h>

#include <orcania.h>
#include <yder.h>
#include <ulfius.h>
#include <rhonabwy.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define USER_USERNAME "user1"
#define USER_PASSWORD "password"
#define PLUGIN_NAME "oidc_resource"
#define SCOPE_LIST "g_profile openid"
#define SCOPE_1 "g_profile"
#define SCOPE_2 "openid"
#define RESPONSE_TYPE_CODE "code"
#define RESPONSE_TYPE_TOKEN_ID_TOKEN "token%20id_token"
#define RESPONSE_TYPE_CODE_TOKEN "token%20code"
#define PLUGIN_PAR_PREFIX "urn:ietf:params:oauth:request_uri:"
#define PLUGIN_PAR_DURATION 90

#define CLIENT_ID "client_resource"
#define CLIENT_NAME "client for resource"
#define CLIENT_SECRET "very-secret"
#define CLIENT_RESOURCE_PROPERTY "resource"
#define CLIENT_REDIRECT_URI "https://client.tld/"
#define CLIENT_REDIRECT_URI_ENC "https%3A%2F%2Fclient.tld%2F"
#define NONCE "Nonce1234"
#define STATE "State1234"

#define RESOURCE1_ENC "https%3A%2F%2Fresource1.tld%2F"
#define RESOURCE1 "https://resource1.tld/"
#define RESOURCE2_ENC "https%3A%2F%2Fresource2.tld%2F"
#define RESOURCE2 "https://resource2.tld/"
#define RESOURCE3_ENC "https%3A%2F%2Fresource3.tld%2F"
#define RESOURCE3 "https://resource3.tld/"
#define RESOURCE_ERR_ENC "https%3A%2F%error.tld%2F"
#define RESOURCE_ERR "https://error.tld/"
#define RESOURCE_HASH_ENC "https%3A%2F%error.tld%2F%23my_hash"
#define RESOURCE_HASH "https://error.tld/#my_hash"

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_oidc_resource_add_plugin_scope_or_client)
{
  json_t * j_param = json_pack("{sssssss{sssssssssisisisososososososososososssisosss{s[s]s[s]}sososo}}",
                                "module", "oidc",
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "iss", "https://glewlwyd.tld",
                                  "jwt-type", "sha",
                                  "jwt-key-size", "256",
                                  "key", "secret_" PLUGIN_NAME,
                                  "access-token-duration", 3600,
                                  "refresh-token-duration", 1209600,
                                  "code-duration", 600,
                                  "refresh-token-rolling", json_true(),
                                  "allow-non-oidc", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-id-token-enabled", json_true(),
                                  "auth-type-device-enabled", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "oauth-par-allowed", json_true(),
                                  "oauth-par-required", json_false(),
                                  "oauth-par-request_uri-prefix", PLUGIN_PAR_PREFIX,
                                  "oauth-par-duration", PLUGIN_PAR_DURATION,
                                  "resource-allowed", json_true(),
                                  "resource-client-property", CLIENT_RESOURCE_PROPERTY,
                                  "resource-scope",
                                    SCOPE_1,
                                      RESOURCE1,
                                    SCOPE_2,
                                      RESOURCE2,
                                  "resource-scope-and-client-property", json_false(),
                                  "introspection-revocation-allowed", json_true(),
                                  "introspection-revocation-allow-target-client", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_resource_add_plugin_scope_and_client)
{
  json_t * j_param = json_pack("{sssssss{sssssssssisisisosososososososososss{s[s]s[s]}so}}",
                                "module", "oidc",
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "iss", "https://glewlwyd.tld",
                                  "jwt-type", "sha",
                                  "jwt-key-size", "256",
                                  "key", "secret_" PLUGIN_NAME,
                                  "access-token-duration", 3600,
                                  "refresh-token-duration", 1209600,
                                  "code-duration", 600,
                                  "refresh-token-rolling", json_true(),
                                  "allow-non-oidc", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-id-token-enabled", json_true(),
                                  "auth-type-device-enabled", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "resource-allowed", json_true(),
                                  "resource-client-property", CLIENT_RESOURCE_PROPERTY,
                                  "resource-scope",
                                    SCOPE_1,
                                      RESOURCE1,
                                    SCOPE_2,
                                      RESOURCE3,
                                  "resource-scope-and-client-property", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_resource_add_plugin_scope_or_client_with_hash)
{
  json_t * j_param = json_pack("{sssssss{sssssssssisisisosososososososososss{s[s]s[s]}so}}",
                                "module", "oidc",
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "iss", "https://glewlwyd.tld",
                                  "jwt-type", "sha",
                                  "jwt-key-size", "256",
                                  "key", "secret_" PLUGIN_NAME,
                                  "access-token-duration", 3600,
                                  "refresh-token-duration", 1209600,
                                  "code-duration", 600,
                                  "refresh-token-rolling", json_true(),
                                  "allow-non-oidc", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-id-token-enabled", json_true(),
                                  "auth-type-device-enabled", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "resource-allowed", json_true(),
                                  "resource-client-property", CLIENT_RESOURCE_PROPERTY,
                                  "resource-scope",
                                    SCOPE_1,
                                      RESOURCE1,
                                    SCOPE_2,
                                      RESOURCE_HASH,
                                  "resource-scope-and-client-property", json_false());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_resource_add_client_confidential_ok)
{
  json_t * j_parameters = json_pack("{sssssssos[ssssss]sos[s]s[s]s[s]}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "client_secret", CLIENT_SECRET,
                                "confidential", json_true(),
                                "authorization_type", "device_authorization", "code", "id_token", "token", "refresh_token", "client_credentials",
                                "enabled", json_true(),
                                CLIENT_RESOURCE_PROPERTY, RESOURCE3,
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "token_endpoint_auth_method", "client_secret_basic");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);

  j_parameters = json_pack("{ss}", "scope", SCOPE_LIST);
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_resource_device_verification_valid_with_resource1)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * redirect_uri, * code, * device_code;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "resource", RESOURCE1);
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
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/" PLUGIN_NAME "/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
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
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  u_map_put(req.map_post_body, "resource", RESOURCE1);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "refresh_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "id_token"), NULL);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq(RESOURCE1, r_jwt_get_claim_str_value(jwt, "aud"));
  r_jwt_free(jwt);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_resource_device_verification_invalid_with_resource2)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "resource", RESOURCE2);
  u_map_put(req.map_post_body, "scope", SCOPE_1);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_resource_device_verification_invalid_with_resource_error)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "resource", RESOURCE_ERR);
  u_map_put(req.map_post_body, "scope", SCOPE_1);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_resource_device_verification_valid_without_resource)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * redirect_uri, * code, * device_code;
  jwt_t * jwt;
  
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
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/" PLUGIN_NAME "/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
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
  ck_assert_ptr_ne(json_object_get(j_resp, "id_token"), NULL);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq(SCOPE_LIST, r_jwt_get_claim_str_value(jwt, "aud"));
  r_jwt_free(jwt);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_resource_device_verification_invalid_with_resource_change)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * redirect_uri, * code, * device_code;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "resource", RESOURCE1);
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
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/" PLUGIN_NAME "/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
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
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  u_map_put(req.map_post_body, "resource", RESOURCE2);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_resource_device_verification_valid_without_resource1_on_confirmation)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * redirect_uri, * code, * device_code;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "resource", RESOURCE1);
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
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/" PLUGIN_NAME "/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
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
  ck_assert_ptr_ne(json_object_get(j_resp, "id_token"), NULL);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq(RESOURCE1, r_jwt_get_claim_str_value(jwt, "aud"));
  r_jwt_free(jwt);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_resource_device_verification_invalid_with_resource1_on_confirmation_only)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
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
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/" PLUGIN_NAME "/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
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
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  u_map_put(req.map_post_body, "resource", RESOURCE1);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_resource_device_verification_valid_with_resource3)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * redirect_uri, * code, * device_code;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "resource", RESOURCE3);
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
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/" PLUGIN_NAME "/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
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
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  u_map_put(req.map_post_body, "resource", RESOURCE3);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "refresh_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "id_token"), NULL);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq(RESOURCE3, r_jwt_get_claim_str_value(jwt, "aud"));
  r_jwt_free(jwt);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_resource_device_verification_invalid_with_resource1)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "resource", RESOURCE1);
  u_map_put(req.map_post_body, "scope", SCOPE_1);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_resource_device_verification_invalid_with_hash)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "resource", RESOURCE_HASH);
  u_map_put(req.map_post_body, "scope", SCOPE_1);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_resource_device_verification_valid_with_multiple_resource)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * redirect_uri, * code, * device_code;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "resource", RESOURCE1 "," RESOURCE2);
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
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/" PLUGIN_NAME "/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
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
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  u_map_put(req.map_post_body, "resource", RESOURCE1);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "refresh_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "id_token"), NULL);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq(RESOURCE1, r_jwt_get_claim_str_value(jwt, "aud"));
  r_jwt_free(jwt);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_resource_device_verification_invalid_with_multiple_resource)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "resource", RESOURCE1 "," RESOURCE_ERR);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_device_verification_valid_with_multiple_resource_on_refresh)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * redirect_uri, * code, * device_code;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "resource", RESOURCE1 "," RESOURCE2);
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
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/" PLUGIN_NAME "/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
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
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  u_map_put(req.map_post_body, "resource", RESOURCE1);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "refresh_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "id_token"), NULL);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq(RESOURCE1, r_jwt_get_claim_str_value(jwt, "aud"));
  r_jwt_free(jwt);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "grant_type", "refresh_token");
  u_map_put(req.map_post_body, "refresh_token", json_string_value(json_object_get(j_resp, "refresh_token")));
  u_map_put(req.map_post_body, "resource", RESOURCE2);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq(RESOURCE2, r_jwt_get_claim_str_value(jwt, "aud"));
  r_jwt_free(jwt);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_resource_device_verification_invalid_with_multiple_resource_on_token)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * redirect_uri, * code, * device_code;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "resource", RESOURCE1 "," RESOURCE3);
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
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/" PLUGIN_NAME "/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
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
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  u_map_put(req.map_post_body, "resource", RESOURCE2);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);
  ulfius_clean_response(&resp);

  u_map_put(req.map_post_body, "resource", RESOURCE_ERR);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_resource_implicit_token_id_token_valid_with_resource1)
{
  struct _u_response resp;
  char * access_token;
  jwt_t * jwt;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_TOKEN_ID_TOKEN, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  access_token = o_strstr(u_map_get(resp.map_header, "Location"), "access_token=") + o_strlen("access_token=");
  if (o_strchr(access_token, '&') != NULL) {
    *o_strchr(access_token, '&') = '\0';
  }
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE1, r_jwt_get_claim_str_value(jwt, "aud"));
  
  r_jwt_free(jwt);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_implicit_token_id_token_invalid_with_multiple_resource)
{
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_TOKEN_ID_TOKEN, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC, RESOURCE2_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_target"), NULL);

  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_implicit_code_token_invalid_with_multiple_resource)
{
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE_TOKEN, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC, RESOURCE2_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_target"), NULL);

  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_implicit_token_id_token_invalid_with_resource1)
{
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_TOKEN_ID_TOKEN, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_2, RESOURCE1_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_target"), NULL);
  
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_implicit_token_id_token_invalid_with_resource_error)
{
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_TOKEN_ID_TOKEN, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_2, RESOURCE_ERR_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_target"), NULL);
  
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_implicit_token_id_token_invalid_with_multiple_resource_including_error)
{
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_2, RESOURCE1_ENC, RESOURCE_ERR_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_target"), NULL);
  
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_implicit_token_id_token_valid_without_resource)
{
  struct _u_response resp;
  char * access_token;
  jwt_t * jwt;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_TOKEN_ID_TOKEN, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  access_token = o_strstr(u_map_get(resp.map_header, "Location"), "access_token=") + o_strlen("access_token=");
  if (o_strchr(access_token, '&') != NULL) {
    *o_strchr(access_token, '&') = '\0';
  }
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(SCOPE_LIST, r_jwt_get_claim_str_value(jwt, "aud"));
  
  r_jwt_free(jwt);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_implicit_token_id_token_valid_with_resource3)
{
  struct _u_response resp;
  char * access_token;
  jwt_t * jwt;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_TOKEN_ID_TOKEN, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE3_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  access_token = o_strstr(u_map_get(resp.map_header, "Location"), "access_token=") + o_strlen("access_token=");
  if (o_strchr(access_token, '&') != NULL) {
    *o_strchr(access_token, '&') = '\0';
  }
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE3, r_jwt_get_claim_str_value(jwt, "aud"));
  
  r_jwt_free(jwt);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_implicit_token_id_token_invalid_and_with_resource1)
{
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_TOKEN_ID_TOKEN, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_target"), NULL);
  
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_implicit_token_id_token_invalid_with_hash)
{
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_TOKEN_ID_TOKEN, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_2, RESOURCE_HASH_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_target"), NULL);
  
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_code_valid_with_resource1)
{
  struct _u_request req;
  struct _u_response resp;
  const char * access_token;
  char * code;
  json_t * j_resp;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, access_token = json_string_value(json_object_get(j_resp, "access_token")));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE1, r_jwt_get_claim_str_value(jwt, "aud"));
  
  r_jwt_free(jwt);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_resp);
}
END_TEST

START_TEST(test_oidc_resource_code_valid_with_multiple_resource)
{
  struct _u_request req;
  struct _u_response resp;
  const char * access_token;
  char * code;
  json_t * j_resp;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC, RESOURCE2_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE2,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, access_token = json_string_value(json_object_get(j_resp, "access_token")));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE2, r_jwt_get_claim_str_value(jwt, "aud"));
  
  r_jwt_free(jwt);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_resp);
}
END_TEST

START_TEST(test_oidc_resource_code_invalid_with_multiple_resource)
{
  struct _u_request req;
  struct _u_response resp;
  char * code;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC, RESOURCE2_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE3,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_code_invalid_with_multiple_resource_on_token)
{
  struct _u_request req;
  struct _u_response resp;
  char * code;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC, RESOURCE2_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1 "," RESOURCE2,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_code_invalid_with_resource2)
{
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_1, RESOURCE2_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_target"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);

  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_code_invalid_with_resource_error)
{
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_1, RESOURCE_ERR_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_target"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);

  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_code_valid_without_resource)
{
  struct _u_request req;
  struct _u_response resp;
  const char * access_token;
  char * code;
  json_t * j_resp;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, access_token = json_string_value(json_object_get(j_resp, "access_token")));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(SCOPE_LIST, r_jwt_get_claim_str_value(jwt, "aud"));
  
  r_jwt_free(jwt);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_resp);
}
END_TEST

START_TEST(test_oidc_resource_code_invalid_with_resource_change)
{
  struct _u_request req;
  struct _u_response resp;
  char * code;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE2,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_code_valid_without_resource1_on_confirmation)
{
  struct _u_request req;
  struct _u_response resp;
  const char * access_token;
  char * code;
  json_t * j_resp;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, access_token = json_string_value(json_object_get(j_resp, "access_token")));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE1, r_jwt_get_claim_str_value(jwt, "aud"));
  
  r_jwt_free(jwt);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_resp);
}
END_TEST

START_TEST(test_oidc_resource_code_invalid_with_resource1_on_confirmation_only)
{
  struct _u_request req;
  struct _u_response resp;
  char * code;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_code_valid_with_resource3)
{
  struct _u_request req;
  struct _u_response resp;
  const char * access_token;
  char * code;
  json_t * j_resp;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE3_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE3,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, access_token = json_string_value(json_object_get(j_resp, "access_token")));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE3, r_jwt_get_claim_str_value(jwt, "aud"));
  
  r_jwt_free(jwt);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_resp);
}
END_TEST

START_TEST(test_oidc_resource_code_invalid_with_resource1)
{
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_target"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);

  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_code_invalid_with_hash)
{
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_1, RESOURCE_HASH_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_target"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);

  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_refresh_valid_with_resource1)
{
  struct _u_request req;
  struct _u_response resp;
  const char * access_token, * refresh_token;
  char * code;
  json_t * j_resp;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, refresh_token = json_string_value(json_object_get(j_resp, "refresh_token")));
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                 U_OPT_POST_BODY_PARAMETER, "refresh_token", refresh_token,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  json_decref(j_resp);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, access_token = json_string_value(json_object_get(j_resp, "access_token")));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE1, r_jwt_get_claim_str_value(jwt, "aud"));
  
  json_decref(j_resp);
  r_jwt_free(jwt);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_refresh_valid_with_multiple_resource)
{
  struct _u_request req;
  struct _u_response resp;
  const char * access_token, * refresh_token;
  char * code;
  json_t * j_resp1, * j_resp;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC, RESOURCE2_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp1 = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, refresh_token = json_string_value(json_object_get(j_resp1, "refresh_token")));
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                 U_OPT_POST_BODY_PARAMETER, "refresh_token", refresh_token,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, access_token = json_string_value(json_object_get(j_resp, "access_token")));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE1, r_jwt_get_claim_str_value(jwt, "aud"));
  
  json_decref(j_resp);
  r_jwt_free(jwt);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                 U_OPT_POST_BODY_PARAMETER, "refresh_token", refresh_token,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE2,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, access_token = json_string_value(json_object_get(j_resp, "access_token")));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE2, r_jwt_get_claim_str_value(jwt, "aud"));
  
  json_decref(j_resp);
  json_decref(j_resp1);
  r_jwt_free(jwt);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_refresh_invalid_with_resource_change)
{
  struct _u_request req;
  struct _u_response resp;
  const char * refresh_token;
  char * code;
  json_t * j_resp;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, refresh_token = json_string_value(json_object_get(j_resp, "refresh_token")));
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                 U_OPT_POST_BODY_PARAMETER, "refresh_token", refresh_token,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE2,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_refresh_invalid_with_resource_error)
{
  struct _u_request req;
  struct _u_response resp;
  const char * refresh_token;
  char * code;
  json_t * j_resp;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, refresh_token = json_string_value(json_object_get(j_resp, "refresh_token")));
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                 U_OPT_POST_BODY_PARAMETER, "refresh_token", refresh_token,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE_ERR,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_refresh_valid_with_resource3)
{
  struct _u_request req;
  struct _u_response resp;
  const char * access_token, * refresh_token;
  char * code;
  json_t * j_resp;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE3_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE3,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, refresh_token = json_string_value(json_object_get(j_resp, "refresh_token")));
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                 U_OPT_POST_BODY_PARAMETER, "refresh_token", refresh_token,
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE3,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  json_decref(j_resp);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, access_token = json_string_value(json_object_get(j_resp, "access_token")));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE3, r_jwt_get_claim_str_value(jwt, "aud"));
  
  json_decref(j_resp);
  r_jwt_free(jwt);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_delete_client)
{
  json_t * j_parameters = json_pack("{ss}", "scope", "");
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL);
  json_decref(j_parameters);

  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_resource_delete_plugin)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_resource_introspect_valid_with_resource1)
{
  struct _u_request req;
  struct _u_response resp;
  char * access_token;
  jwt_t * jwt;
  json_t * j_result;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s&resource=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_TOKEN_ID_TOKEN, CLIENT_ID, CLIENT_REDIRECT_URI_ENC, SCOPE_LIST, RESOURCE1_ENC);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  access_token = o_strstr(u_map_get(resp.map_header, "Location"), "access_token=") + o_strlen("access_token=");
  if (o_strchr(access_token, '&') != NULL) {
    *o_strchr(access_token, '&') = '\0';
  }
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE1, r_jwt_get_claim_str_value(jwt, "aud"));
  r_jwt_free(jwt);
  
  ulfius_init_request(&req);
  u_map_put(req.map_post_body, "token", access_token);
  u_map_put(req.map_post_body, "token_type_hint", "access_token");
  j_result = json_pack("{ss}", "aud", RESOURCE1);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/" PLUGIN_NAME "/introspect", CLIENT_ID, CLIENT_SECRET, NULL, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_result);
  ulfius_clean_request(&req);
  
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_resource_par_client_confidential_valid_with_resource1)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_response;
  char * code;
  const char * access_token;
  jwt_t * jwt;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_AUTH_BASIC, CLIENT_ID, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "response_type", RESPONSE_TYPE_CODE,
                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                U_OPT_POST_BODY_PARAMETER, "state", STATE,
                                U_OPT_POST_BODY_PARAMETER, "nonce", NONCE,
                                U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(201, resp.status);
  ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_response, "request_uri")), o_strlen(PLUGIN_PAR_PREFIX));
  ck_assert_int_eq(0, o_strncmp(json_string_value(json_object_get(j_response, "request_uri")), PLUGIN_PAR_PREFIX, o_strlen(PLUGIN_PAR_PREFIX)));
  ck_assert_int_eq(PLUGIN_PAR_DURATION, json_integer_value(json_object_get(j_response, "expires_in")));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  ulfius_init_request(&req);
  ulfius_copy_request(&req, &user_req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/auth"),
                                U_OPT_URL_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_URL_PARAMETER, "nonce", NONCE,
                                U_OPT_URL_PARAMETER, "request_uri", json_string_value(json_object_get(j_response, "request_uri")),
                                U_OPT_URL_PARAMETER, "g_continue", NULL,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  json_decref(j_response);
  
  ulfius_init_request(&req);
  ulfius_copy_request(&req, &user_req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/token"),
                                U_OPT_AUTH_BASIC, CLIENT_ID, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                U_OPT_POST_BODY_PARAMETER, "code", code,
                                U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, access_token = json_string_value(json_object_get(j_response, "access_token")));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE1, r_jwt_get_claim_str_value(jwt, "aud"));
  
  r_jwt_free(jwt);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  o_free(code);
  json_decref(j_response);
}
END_TEST

START_TEST(test_oidc_resource_par_client_confidential_valid_with_multiple_resource)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_response, * j_resp;
  char * code;
  const char * access_token;
  jwt_t * jwt;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_AUTH_BASIC, CLIENT_ID, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "response_type", RESPONSE_TYPE_CODE,
                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                U_OPT_POST_BODY_PARAMETER, "state", STATE,
                                U_OPT_POST_BODY_PARAMETER, "nonce", NONCE,
                                U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1 "," RESOURCE2,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(201, resp.status);
  ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_response, "request_uri")), o_strlen(PLUGIN_PAR_PREFIX));
  ck_assert_int_eq(0, o_strncmp(json_string_value(json_object_get(j_response, "request_uri")), PLUGIN_PAR_PREFIX, o_strlen(PLUGIN_PAR_PREFIX)));
  ck_assert_int_eq(PLUGIN_PAR_DURATION, json_integer_value(json_object_get(j_response, "expires_in")));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  ulfius_init_request(&req);
  ulfius_copy_request(&req, &user_req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/auth"),
                                U_OPT_URL_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_URL_PARAMETER, "nonce", NONCE,
                                U_OPT_URL_PARAMETER, "request_uri", json_string_value(json_object_get(j_response, "request_uri")),
                                U_OPT_URL_PARAMETER, "g_continue", NULL,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  json_decref(j_response);
  
  ulfius_init_request(&req);
  ulfius_copy_request(&req, &user_req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/token"),
                                U_OPT_AUTH_BASIC, CLIENT_ID, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                U_OPT_POST_BODY_PARAMETER, "code", code,
                                U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, access_token = json_string_value(json_object_get(j_response, "access_token")));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE1, r_jwt_get_claim_str_value(jwt, "aud"));
  
  r_jwt_free(jwt);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_AUTH_BASIC, CLIENT_ID, CLIENT_SECRET,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                 U_OPT_POST_BODY_PARAMETER, "refresh_token", json_string_value(json_object_get(j_response, "refresh_token")),
                                                 U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE2,
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, access_token = json_string_value(json_object_get(j_resp, "access_token")));
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(RESOURCE2, r_jwt_get_claim_str_value(jwt, "aud"));
  
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  r_jwt_free(jwt);
  o_free(code);
  json_decref(j_response);
  json_decref(j_resp);
}
END_TEST

START_TEST(test_oidc_resource_par_client_confidential_invalid_with_resource3)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_response;
  char * code;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_AUTH_BASIC, CLIENT_ID, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "response_type", RESPONSE_TYPE_CODE,
                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                U_OPT_POST_BODY_PARAMETER, "state", STATE,
                                U_OPT_POST_BODY_PARAMETER, "nonce", NONCE,
                                U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(201, resp.status);
  ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_response, "request_uri")), o_strlen(PLUGIN_PAR_PREFIX));
  ck_assert_int_eq(0, o_strncmp(json_string_value(json_object_get(j_response, "request_uri")), PLUGIN_PAR_PREFIX, o_strlen(PLUGIN_PAR_PREFIX)));
  ck_assert_int_eq(PLUGIN_PAR_DURATION, json_integer_value(json_object_get(j_response, "expires_in")));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  ulfius_init_request(&req);
  ulfius_copy_request(&req, &user_req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/auth"),
                                U_OPT_URL_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_URL_PARAMETER, "nonce", NONCE,
                                U_OPT_URL_PARAMETER, "request_uri", json_string_value(json_object_get(j_response, "request_uri")),
                                U_OPT_URL_PARAMETER, "g_continue", NULL,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  json_decref(j_response);
  
  ulfius_init_request(&req);
  ulfius_copy_request(&req, &user_req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/token"),
                                U_OPT_AUTH_BASIC, CLIENT_ID, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                U_OPT_POST_BODY_PARAMETER, "code", code,
                                U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE3,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  o_free(code);
}
END_TEST

START_TEST(test_oidc_resource_par_client_confidential_invalid_with_multiple_resource_on_token)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_response;
  char * code;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_AUTH_BASIC, CLIENT_ID, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "response_type", RESPONSE_TYPE_CODE,
                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                U_OPT_POST_BODY_PARAMETER, "state", STATE,
                                U_OPT_POST_BODY_PARAMETER, "nonce", NONCE,
                                U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1 "," RESOURCE2,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(201, resp.status);
  ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_response, "request_uri")), o_strlen(PLUGIN_PAR_PREFIX));
  ck_assert_int_eq(0, o_strncmp(json_string_value(json_object_get(j_response, "request_uri")), PLUGIN_PAR_PREFIX, o_strlen(PLUGIN_PAR_PREFIX)));
  ck_assert_int_eq(PLUGIN_PAR_DURATION, json_integer_value(json_object_get(j_response, "expires_in")));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  ulfius_init_request(&req);
  ulfius_copy_request(&req, &user_req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/auth"),
                                U_OPT_URL_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_URL_PARAMETER, "nonce", NONCE,
                                U_OPT_URL_PARAMETER, "request_uri", json_string_value(json_object_get(j_response, "request_uri")),
                                U_OPT_URL_PARAMETER, "g_continue", NULL,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  json_decref(j_response);
  
  ulfius_init_request(&req);
  ulfius_copy_request(&req, &user_req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/token"),
                                U_OPT_AUTH_BASIC, CLIENT_ID, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                U_OPT_POST_BODY_PARAMETER, "code", code,
                                U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE1 "," RESOURCE2,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  o_free(code);
}
END_TEST

START_TEST(test_oidc_resource_par_client_confidential_invalid_with_resource_err)
{
  struct _u_request req;
  struct _u_response resp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_AUTH_BASIC, CLIENT_ID, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "response_type", RESPONSE_TYPE_CODE,
                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                U_OPT_POST_BODY_PARAMETER, "state", STATE,
                                U_OPT_POST_BODY_PARAMETER, "nonce", NONCE,
                                U_OPT_POST_BODY_PARAMETER, "resource", RESOURCE_ERR,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ck_assert_ptr_eq(NULL, ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc resource");
  tc_core = tcase_create("test_oidc_resource");
  tcase_add_test(tc_core, test_oidc_resource_add_plugin_scope_or_client);
  tcase_add_test(tc_core, test_oidc_resource_add_client_confidential_ok);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_valid_with_resource1);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_invalid_with_resource2);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_invalid_with_resource_error);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_valid_without_resource);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_invalid_with_resource_change);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_valid_without_resource1_on_confirmation);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_invalid_with_resource1_on_confirmation_only);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_valid_with_multiple_resource);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_invalid_with_multiple_resource);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_valid_with_multiple_resource_on_refresh);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_invalid_with_multiple_resource_on_token);
  tcase_add_test(tc_core, test_oidc_resource_implicit_token_id_token_valid_with_resource1);
  tcase_add_test(tc_core, test_oidc_resource_implicit_token_id_token_invalid_with_multiple_resource);
  tcase_add_test(tc_core, test_oidc_resource_implicit_code_token_invalid_with_multiple_resource);
  tcase_add_test(tc_core, test_oidc_resource_implicit_token_id_token_invalid_with_resource1);
  tcase_add_test(tc_core, test_oidc_resource_implicit_token_id_token_invalid_with_resource_error);
  tcase_add_test(tc_core, test_oidc_resource_implicit_token_id_token_invalid_with_multiple_resource_including_error);
  tcase_add_test(tc_core, test_oidc_resource_implicit_token_id_token_valid_without_resource);
  tcase_add_test(tc_core, test_oidc_resource_code_valid_with_resource1);
  tcase_add_test(tc_core, test_oidc_resource_code_valid_with_multiple_resource);
  tcase_add_test(tc_core, test_oidc_resource_code_invalid_with_multiple_resource);
  tcase_add_test(tc_core, test_oidc_resource_code_invalid_with_multiple_resource_on_token);
  tcase_add_test(tc_core, test_oidc_resource_code_invalid_with_resource2);
  tcase_add_test(tc_core, test_oidc_resource_code_invalid_with_resource_error);
  tcase_add_test(tc_core, test_oidc_resource_code_valid_without_resource);
  tcase_add_test(tc_core, test_oidc_resource_code_invalid_with_resource_change);
  tcase_add_test(tc_core, test_oidc_resource_code_valid_without_resource1_on_confirmation);
  tcase_add_test(tc_core, test_oidc_resource_code_invalid_with_resource1_on_confirmation_only);
  tcase_add_test(tc_core, test_oidc_resource_refresh_valid_with_resource1);
  tcase_add_test(tc_core, test_oidc_resource_refresh_valid_with_multiple_resource);
  tcase_add_test(tc_core, test_oidc_resource_refresh_invalid_with_resource_change);
  tcase_add_test(tc_core, test_oidc_resource_refresh_invalid_with_resource_error);
  tcase_add_test(tc_core, test_oidc_resource_introspect_valid_with_resource1);
  tcase_add_test(tc_core, test_oidc_resource_par_client_confidential_valid_with_resource1);
  tcase_add_test(tc_core, test_oidc_resource_par_client_confidential_valid_with_multiple_resource);
  tcase_add_test(tc_core, test_oidc_resource_par_client_confidential_invalid_with_resource3);
  tcase_add_test(tc_core, test_oidc_resource_par_client_confidential_invalid_with_multiple_resource_on_token);
  tcase_add_test(tc_core, test_oidc_resource_par_client_confidential_invalid_with_resource_err);
  tcase_add_test(tc_core, test_oidc_resource_delete_plugin);
  tcase_add_test(tc_core, test_oidc_resource_add_plugin_scope_and_client);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_valid_with_resource3);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_invalid_with_resource1);
  tcase_add_test(tc_core, test_oidc_resource_implicit_token_id_token_valid_with_resource3);
  tcase_add_test(tc_core, test_oidc_resource_implicit_token_id_token_invalid_and_with_resource1);
  tcase_add_test(tc_core, test_oidc_resource_code_valid_with_resource3);
  tcase_add_test(tc_core, test_oidc_resource_code_invalid_with_resource1);
  tcase_add_test(tc_core, test_oidc_resource_refresh_valid_with_resource3);
  tcase_add_test(tc_core, test_oidc_resource_delete_plugin);
  tcase_add_test(tc_core, test_oidc_resource_add_plugin_scope_or_client_with_hash);
  tcase_add_test(tc_core, test_oidc_resource_device_verification_invalid_with_hash);
  tcase_add_test(tc_core, test_oidc_resource_implicit_token_id_token_invalid_with_hash);
  tcase_add_test(tc_core, test_oidc_resource_code_invalid_with_hash);
  tcase_add_test(tc_core, test_oidc_resource_delete_client);
  tcase_add_test(tc_core, test_oidc_resource_delete_plugin);
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
  struct _u_response auth_resp;
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

      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication user");
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
  
  char * url = msprintf("%s/auth/", SERVER_URI);
  run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  o_free(url);
  
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&scope_req);
  y_close_logs();
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

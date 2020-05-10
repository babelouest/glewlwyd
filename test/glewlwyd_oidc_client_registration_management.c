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
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define PLUGIN_MODULE "oidc"
#define PLUGIN_NAME "register_management"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_DISPLAY_NAME "Client registration management test"
#define PLUGIN_JWT_TYPE "sha"
#define PLUGIN_JWT_KEY_SIZE "256"
#define PLUGIN_KEY "secret"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_ACCESS_TOKEN_DURATION 3600
#define PLUGIN_REGISTER_AUTH_SCOPE "g_profile"
#define PLUGIN_REGISTER_DEFAULT_SCOPE "scope3"

#define CLIENT_NAME                             "New Client"
#define CLIENT_REDIRECT_URI                     "https://client.tld/callback"
#define CLIENT_TOKEN_AUTH_NONE                  "none"
#define CLIENT_TOKEN_AUTH_SECRET_POST           "client_secret_post"
#define CLIENT_TOKEN_AUTH_SECRET_BASIC          "client_secret_basic"
#define CLIENT_TOKEN_AUTH_SECRET_JWT            "client_secret_jwt"
#define CLIENT_TOKEN_AUTH_PRIVATE_KEY_JWT       "private_key_jwt"
#define CLIENT_RESPONSE_TYPE_CODE               "code"
#define CLIENT_RESPONSE_TYPE_TOKEN              "token"
#define CLIENT_RESPONSE_TYPE_ID_TOKEN           "id_token"
#define CLIENT_GRANT_TYPE_AUTH_CODE             "authorization_code"
#define CLIENT_GRANT_TYPE_IMPLICIT              "implicit"
#define CLIENT_GRANT_TYPE_PASSWORD              "password"
#define CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS    "client_credentials"
#define CLIENT_GRANT_TYPE_REFRESH_TOKEN         "refresh_token"
#define CLIENT_GRANT_TYPE_DELETE_TOKEN          "delete_token"
#define CLIENT_GRANT_TYPE_DEVICE_AUTH           "device_authorization"
#define CLIENT_APP_TYPE_WEB                     "web"
#define CLIENT_APP_TYPE_NATIVE                  "native"
#define CLIENT_LOGO_URI                         "https://client.tld/logo.png"
#define CLIENT_CONTACT                          "contact@client.tld"
#define CLIENT_URI                              "https://client.tld/"
#define CLIENT_POLICY_URI                       "https://client.tld/policy"
#define CLIENT_TOS_URI                          "https://client.tld/tos"
#define CLIENT_JWKS_URI                         "https://client.tld/jwks"

const char jwk_pubkey_ecdsa_str[] = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}]}";

struct _u_request admin_req;

START_TEST(test_oidc_registration_plugin_add_using_management)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisososososososos[s]s[s]so}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", PLUGIN_JWT_TYPE,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", PLUGIN_KEY,
                                  "code-duration", PLUGIN_CODE_DURATION,
                                  "refresh-token-duration", PLUGIN_REFRESH_TOKEN_DURATION,
                                  "access-token-duration", PLUGIN_ACCESS_TOKEN_DURATION,
                                  "allow-non-oidc", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-implicit-enabled", json_true(),
                                  "auth-type-password-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "register-client-allowed", json_true(),
                                  "register-client-auth-scope", PLUGIN_REGISTER_AUTH_SCOPE,
                                  "register-client-credentials-scope", PLUGIN_REGISTER_DEFAULT_SCOPE,
                                  "register-client-management-allowed", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_revocation_plugin_remove)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_registration_auth_register_client_with_valid_credentials)
{
  struct _u_request req, req_reg;
  struct _u_response resp;
  json_t * j_body, * j_client, * j_result;
  const char * token;
  char * tmp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", PLUGIN_REGISTER_AUTH_SCOPE);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  token = json_string_value(json_object_get(j_body, "access_token"));
  ck_assert_ptr_ne(token, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  tmp = msprintf("Bearer %s", token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  j_client = json_pack("{sss[s]s[ss]}", "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_SECRET_BASIC, "redirect_uris", CLIENT_REDIRECT_URI, "grant_types", "authorization_code", "refresh_token");
  ck_assert_ptr_ne(j_client, NULL);
  req_reg.http_verb = o_strdup("POST");
  req_reg.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/register");
  ck_assert_int_eq(ulfius_set_json_body_request(&req_reg, j_client), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_result, NULL);
  ck_assert_ptr_ne(json_object_get(j_result, "client_id"), NULL);
  ck_assert_ptr_ne(json_object_get(j_result, "client_secret"), NULL);
  ck_assert_ptr_ne(json_object_get(j_result, "registration_access_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_result, "registration_client_uri"), NULL);
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = msprintf(SERVER_URI "/client/%s", json_string_value(json_object_get(j_result, "client_id")));
  admin_req.http_verb = o_strdup("GET");
  json_decref(j_result);
  json_decref(j_client);
  json_decref(j_body);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_registration_auth_register_client_management_get)
{
  struct _u_request req, req_reg;
  struct _u_response resp;
  json_t * j_body, * j_client, * j_result, * j_result_get;
  const char * token, * registration_access_token, * registration_client_uri;
  char * tmp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", PLUGIN_REGISTER_AUTH_SCOPE);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  token = json_string_value(json_object_get(j_body, "access_token"));
  ck_assert_ptr_ne(token, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  tmp = msprintf("Bearer %s", token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  j_client = json_pack("{sss[s]s[ss]}", "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_SECRET_BASIC, "redirect_uris", CLIENT_REDIRECT_URI, "grant_types", "authorization_code", "refresh_token");
  ck_assert_ptr_ne(j_client, NULL);
  req_reg.http_verb = o_strdup("POST");
  req_reg.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/register");
  ck_assert_int_eq(ulfius_set_json_body_request(&req_reg, j_client), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_result, NULL);
  ck_assert_ptr_ne(json_object_get(j_result, "client_id"), NULL);
  ck_assert_ptr_ne(json_object_get(j_result, "client_secret"), NULL);
  ck_assert_ptr_ne(registration_access_token = json_string_value(json_object_get(j_result, "registration_access_token")), NULL);
  ck_assert_ptr_ne(registration_client_uri = json_string_value(json_object_get(j_result, "registration_client_uri")), NULL);
  json_decref(j_client);
  json_decref(j_body);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  req_reg.http_url = o_strdup(registration_client_uri);
  tmp = msprintf("Bearer %s", registration_access_token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_result_get = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_result_get, NULL);
  ck_assert_ptr_eq(json_object_get(j_result_get, "registration_access_token"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result_get, "registration_client_uri"), NULL);
  json_object_set(j_result_get, "registration_access_token", json_object_get(j_result, "registration_access_token"));
  json_object_set(j_result_get, "registration_client_uri", json_object_get(j_result, "registration_client_uri"));
  json_object_set(j_result_get, "client_id_issued_at", json_object_get(j_result, "client_id_issued_at"));
  json_object_set(j_result_get, "client_secret_expires_at", json_object_get(j_result, "client_secret_expires_at"));
  ck_assert_int_eq(json_equal(j_result, j_result_get), 1);

  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);
  
  json_decref(j_result_get);
  json_decref(j_result);
}
END_TEST

START_TEST(test_oidc_registration_auth_register_client_management_get_invalid_access_token)
{
  struct _u_request req, req_reg;
  struct _u_response resp;
  json_t * j_body, * j_client, * j_result;
  const char * token, * registration_access_token, * registration_client_uri;
  char * tmp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", PLUGIN_REGISTER_AUTH_SCOPE);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  token = json_string_value(json_object_get(j_body, "access_token"));
  ck_assert_ptr_ne(token, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  tmp = msprintf("Bearer %s", token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  j_client = json_pack("{sss[s]s[ss]}", "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_SECRET_BASIC, "redirect_uris", CLIENT_REDIRECT_URI, "grant_types", "authorization_code", "refresh_token");
  ck_assert_ptr_ne(j_client, NULL);
  req_reg.http_verb = o_strdup("POST");
  req_reg.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/register");
  ck_assert_int_eq(ulfius_set_json_body_request(&req_reg, j_client), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_result, NULL);
  ck_assert_ptr_ne(json_object_get(j_result, "client_id"), NULL);
  ck_assert_ptr_ne(json_object_get(j_result, "client_secret"), NULL);
  ck_assert_ptr_ne(registration_access_token = json_string_value(json_object_get(j_result, "registration_access_token")), NULL);
  ck_assert_ptr_ne(registration_client_uri = json_string_value(json_object_get(j_result, "registration_client_uri")), NULL);
  json_decref(j_client);
  json_decref(j_body);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  req_reg.http_url = o_strdup(registration_client_uri);
  tmp = msprintf("Bearer %s", "error");
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);

  json_decref(j_result);
}
END_TEST

START_TEST(test_oidc_registration_auth_register_client_management_get_invalid_clent_id)
{
  struct _u_request req, req_reg;
  struct _u_response resp;
  json_t * j_body, * j_client, * j_result;
  const char * token, * registration_access_token, * registration_client_uri;
  char * tmp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", PLUGIN_REGISTER_AUTH_SCOPE);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  token = json_string_value(json_object_get(j_body, "access_token"));
  ck_assert_ptr_ne(token, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  tmp = msprintf("Bearer %s", token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  j_client = json_pack("{sss[s]s[ss]}", "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_SECRET_BASIC, "redirect_uris", CLIENT_REDIRECT_URI, "grant_types", "authorization_code", "refresh_token");
  ck_assert_ptr_ne(j_client, NULL);
  req_reg.http_verb = o_strdup("POST");
  req_reg.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/register");
  ck_assert_int_eq(ulfius_set_json_body_request(&req_reg, j_client), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_result, NULL);
  ck_assert_ptr_ne(json_object_get(j_result, "client_id"), NULL);
  ck_assert_ptr_ne(json_object_get(j_result, "client_secret"), NULL);
  ck_assert_ptr_ne(registration_access_token = json_string_value(json_object_get(j_result, "registration_access_token")), NULL);
  ck_assert_ptr_ne(registration_client_uri = json_string_value(json_object_get(j_result, "registration_client_uri")), NULL);
  json_decref(j_client);
  json_decref(j_body);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  req_reg.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/register/error");
  tmp = msprintf("Bearer %s", registration_access_token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  req_reg.http_url = o_strdup(registration_client_uri);
  tmp = msprintf("Bearer %s", registration_access_token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);
  
  json_decref(j_result);
}
END_TEST

START_TEST(test_oidc_registration_auth_register_client_management_update_error_parameters)
{
  json_t * j_client, * j_jwks = json_loads(jwk_pubkey_ecdsa_str, JSON_DECODE_ANY, NULL);
  struct _u_request req, req_reg;
  struct _u_response resp;
  json_t * j_body, * j_result;
  const char * token, * registration_access_token, * registration_client_uri;
  char * tmp;
  
  ck_assert_ptr_ne(j_jwks, NULL);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", PLUGIN_REGISTER_AUTH_SCOPE);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  token = json_string_value(json_object_get(j_body, "access_token"));
  ck_assert_ptr_ne(token, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  tmp = msprintf("Bearer %s", token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  j_client = json_pack("{s[s]}", "redirect_uris", CLIENT_REDIRECT_URI);
  ck_assert_ptr_ne(j_client, NULL);
  req_reg.http_verb = o_strdup("POST");
  req_reg.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/register");
  ck_assert_int_eq(ulfius_set_json_body_request(&req_reg, j_client), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_result, NULL);
  ck_assert_ptr_ne(json_object_get(j_result, "client_id"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "client_secret"), NULL);
  ck_assert_ptr_ne(registration_access_token = json_string_value(json_object_get(j_result, "registration_access_token")), NULL);
  ck_assert_ptr_ne(registration_client_uri = json_string_value(json_object_get(j_result, "registration_client_uri")), NULL);
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = msprintf(SERVER_URI "/client/%s", json_string_value(json_object_get(j_result, "client_id")));
  admin_req.http_verb = o_strdup("GET");
  json_decref(j_client);
  json_decref(j_body);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);
  
  ulfius_init_request(&req_reg);
  tmp = msprintf("Bearer %s", registration_access_token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  
  // Invalid client_id
  j_client = json_pack("{sssss[s]sss[ssssss]s[sss]sss[s]sssssssssO}",
                       "client_id", "error",
                       "client_name", CLIENT_NAME,
                       "redirect_uris", CLIENT_REDIRECT_URI,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_PRIVATE_KEY_JWT,
                       "grant_types",
                         CLIENT_GRANT_TYPE_AUTH_CODE,
                         CLIENT_GRANT_TYPE_PASSWORD,
                         CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS,
                         CLIENT_GRANT_TYPE_REFRESH_TOKEN,
                         CLIENT_GRANT_TYPE_DELETE_TOKEN,
                         CLIENT_GRANT_TYPE_DEVICE_AUTH,
                       "response_types",
                         CLIENT_RESPONSE_TYPE_CODE,
                         CLIENT_RESPONSE_TYPE_TOKEN,
                         CLIENT_RESPONSE_TYPE_ID_TOKEN,
                       "application_type", CLIENT_APP_TYPE_WEB,
                       "contacts",
                         CLIENT_CONTACT,
                       "logo_uri", CLIENT_LOGO_URI,
                       "client_uri", CLIENT_URI,
                       "policy_uri", CLIENT_POLICY_URI,
                       "tos_uri", CLIENT_TOS_URI,
                       "jwks", j_jwks);
  ck_assert_ptr_ne(j_client, NULL);
  ck_assert_int_eq(run_simple_test(&req_reg, "PUT", registration_client_uri, NULL, NULL, j_client, NULL, 400, NULL, "\"Invalid client_id\"", NULL), 1);
  json_decref(j_client);

  // No redirect_uri
  j_client = json_pack("{sssssss[ssssss]s[sss]sss[s]ssssssss}",
                       "client_id", json_string_value(json_object_get(j_result, "client_id")),
                       "client_name", CLIENT_NAME,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_NONE,
                       "grant_types",
                         CLIENT_GRANT_TYPE_AUTH_CODE,
                         CLIENT_GRANT_TYPE_PASSWORD,
                         CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS,
                         CLIENT_GRANT_TYPE_REFRESH_TOKEN,
                         CLIENT_GRANT_TYPE_DELETE_TOKEN,
                         CLIENT_GRANT_TYPE_DEVICE_AUTH,
                       "response_types",
                         CLIENT_RESPONSE_TYPE_CODE,
                         CLIENT_RESPONSE_TYPE_TOKEN,
                         CLIENT_RESPONSE_TYPE_ID_TOKEN,
                       "application_type", CLIENT_APP_TYPE_WEB,
                       "contacts",
                         CLIENT_CONTACT,
                       "logo_uri", CLIENT_LOGO_URI,
                       "client_uri", CLIENT_URI,
                       "policy_uri", CLIENT_POLICY_URI,
                       "tos_uri", CLIENT_TOS_URI);
  ck_assert_ptr_ne(j_client, NULL);
  ck_assert_int_eq(run_simple_test(&req_reg, "PUT", registration_client_uri, NULL, NULL, j_client, NULL, 400, NULL, "\"redirect_uris is mandatory and must be an array of strings\"", NULL), 1);
  json_decref(j_client);

  // invalid response_types
  j_client = json_pack("{sssss[s]sss[ssssss]s[s]sss[s]ssssssss}",
                       "client_id", json_string_value(json_object_get(j_result, "client_id")),
                       "client_name", CLIENT_NAME,
                       "redirect_uris", CLIENT_REDIRECT_URI,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_NONE,
                       "grant_types",
                         CLIENT_GRANT_TYPE_AUTH_CODE,
                         CLIENT_GRANT_TYPE_PASSWORD,
                         CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS,
                         CLIENT_GRANT_TYPE_REFRESH_TOKEN,
                         CLIENT_GRANT_TYPE_DELETE_TOKEN,
                         CLIENT_GRANT_TYPE_DEVICE_AUTH,
                       "response_types",
                         "error",
                       "application_type", CLIENT_APP_TYPE_WEB,
                       "contacts",
                         CLIENT_CONTACT,
                       "logo_uri", CLIENT_LOGO_URI,
                       "client_uri", CLIENT_URI,
                       "policy_uri", CLIENT_POLICY_URI,
                       "tos_uri", CLIENT_TOS_URI);
  ck_assert_ptr_ne(j_client, NULL);
  ck_assert_int_eq(run_simple_test(&req_reg, "PUT", registration_client_uri, NULL, NULL, j_client, NULL, 400, NULL, "\"response_types must have one of the following values: 'code', 'token', 'id_token'\"", NULL), 1);
  json_decref(j_client);

  // invalid grant_types
  j_client = json_pack("{sssss[s]sss[s]s[sss]sss[s]sssssssssO}",
                       "client_id", json_string_value(json_object_get(j_result, "client_id")),
                       "client_name", CLIENT_NAME,
                       "redirect_uris", CLIENT_REDIRECT_URI,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_PRIVATE_KEY_JWT,
                       "grant_types",
                         "error",
                       "response_types",
                         CLIENT_RESPONSE_TYPE_CODE,
                         CLIENT_RESPONSE_TYPE_TOKEN,
                         CLIENT_RESPONSE_TYPE_ID_TOKEN,
                       "application_type", CLIENT_APP_TYPE_WEB,
                       "contacts",
                         CLIENT_CONTACT,
                       "logo_uri", CLIENT_LOGO_URI,
                       "client_uri", CLIENT_URI,
                       "policy_uri", CLIENT_POLICY_URI,
                       "tos_uri", CLIENT_TOS_URI,
                       "jwks", j_jwks);
  ck_assert_ptr_ne(j_client, NULL);
  ck_assert_int_eq(run_simple_test(&req_reg, "PUT", registration_client_uri, NULL, NULL, j_client, NULL, 400, NULL, "\"grant_types must have one of the following values: 'authorization_code', 'implicit', 'password', 'client_credentials', 'refresh_token', 'delete_token', 'device_authorization'\"", NULL), 1);
  json_decref(j_client);

  // Invaid application_type
  j_client = json_pack("{sssss[s]sss[ssssss]s[sss]sss[s]ssssssss}",
                       "client_id", json_string_value(json_object_get(j_result, "client_id")),
                       "client_name", CLIENT_NAME,
                       "redirect_uris", CLIENT_REDIRECT_URI,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_NONE,
                       "grant_types",
                         CLIENT_GRANT_TYPE_AUTH_CODE,
                         CLIENT_GRANT_TYPE_PASSWORD,
                         CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS,
                         CLIENT_GRANT_TYPE_REFRESH_TOKEN,
                         CLIENT_GRANT_TYPE_DELETE_TOKEN,
                         CLIENT_GRANT_TYPE_DEVICE_AUTH,
                       "response_types",
                         CLIENT_RESPONSE_TYPE_CODE,
                         CLIENT_RESPONSE_TYPE_TOKEN,
                         CLIENT_RESPONSE_TYPE_ID_TOKEN,
                       "application_type", "error",
                       "contacts",
                         CLIENT_CONTACT,
                       "logo_uri", CLIENT_LOGO_URI,
                       "client_uri", CLIENT_URI,
                       "policy_uri", CLIENT_POLICY_URI,
                       "tos_uri", CLIENT_TOS_URI);
  ck_assert_ptr_ne(j_client, NULL);
  ck_assert_int_eq(run_simple_test(&req_reg, "PUT", registration_client_uri, NULL, NULL, j_client, NULL, 400, NULL, "\"application_type is optional and must have one of the following values: 'web', 'native'\"", NULL), 1);
  json_decref(j_client);

  // Invalid contacts
  j_client = json_pack("{sssss[s]sss[ssssss]s[sss]sss[i]ssssssss}",
                       "client_id", json_string_value(json_object_get(j_result, "client_id")),
                       "client_name", CLIENT_NAME,
                       "redirect_uris", CLIENT_REDIRECT_URI,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_NONE,
                       "grant_types",
                         CLIENT_GRANT_TYPE_AUTH_CODE,
                         CLIENT_GRANT_TYPE_PASSWORD,
                         CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS,
                         CLIENT_GRANT_TYPE_REFRESH_TOKEN,
                         CLIENT_GRANT_TYPE_DELETE_TOKEN,
                         CLIENT_GRANT_TYPE_DEVICE_AUTH,
                       "response_types",
                         CLIENT_RESPONSE_TYPE_CODE,
                         CLIENT_RESPONSE_TYPE_TOKEN,
                         CLIENT_RESPONSE_TYPE_ID_TOKEN,
                       "application_type", CLIENT_APP_TYPE_WEB,
                       "contacts",
                         42,
                       "logo_uri", CLIENT_LOGO_URI,
                       "client_uri", CLIENT_URI,
                       "policy_uri", CLIENT_POLICY_URI,
                       "tos_uri", CLIENT_TOS_URI);
  ck_assert_ptr_ne(j_client, NULL);
  ck_assert_int_eq(run_simple_test(&req_reg, "PUT", registration_client_uri, NULL, NULL, j_client, NULL, 400, NULL, "\"contact value must be a non empty string\"", NULL), 1);
  json_decref(j_client);

  // Invalid logo_uri
  j_client = json_pack("{sssss[s]sss[ssssss]s[sss]sss[s]ssssssss}",
                       "client_id", json_string_value(json_object_get(j_result, "client_id")),
                       "client_name", CLIENT_NAME,
                       "redirect_uris", CLIENT_REDIRECT_URI,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_NONE,
                       "grant_types",
                         CLIENT_GRANT_TYPE_AUTH_CODE,
                         CLIENT_GRANT_TYPE_PASSWORD,
                         CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS,
                         CLIENT_GRANT_TYPE_REFRESH_TOKEN,
                         CLIENT_GRANT_TYPE_DELETE_TOKEN,
                         CLIENT_GRANT_TYPE_DEVICE_AUTH,
                       "response_types",
                         CLIENT_RESPONSE_TYPE_CODE,
                         CLIENT_RESPONSE_TYPE_TOKEN,
                         CLIENT_RESPONSE_TYPE_ID_TOKEN,
                       "application_type", CLIENT_APP_TYPE_WEB,
                       "contacts",
                         CLIENT_CONTACT,
                       "logo_uri", "error",
                       "client_uri", CLIENT_URI,
                       "policy_uri", CLIENT_POLICY_URI,
                       "tos_uri", CLIENT_TOS_URI);
  ck_assert_ptr_ne(j_client, NULL);
  ck_assert_int_eq(run_simple_test(&req_reg, "PUT", registration_client_uri, NULL, NULL, j_client, NULL, 400, NULL, "\"logo_uri is optional and must be a string\"", NULL), 1);
  json_decref(j_client);

  // Invalid client_uri
  j_client = json_pack("{sssss[s]sss[ssssss]s[sss]sss[s]ssssssss}",
                       "client_id", json_string_value(json_object_get(j_result, "client_id")),
                       "client_name", CLIENT_NAME,
                       "redirect_uris", CLIENT_REDIRECT_URI,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_NONE,
                       "grant_types",
                         CLIENT_GRANT_TYPE_AUTH_CODE,
                         CLIENT_GRANT_TYPE_PASSWORD,
                         CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS,
                         CLIENT_GRANT_TYPE_REFRESH_TOKEN,
                         CLIENT_GRANT_TYPE_DELETE_TOKEN,
                         CLIENT_GRANT_TYPE_DEVICE_AUTH,
                       "response_types",
                         CLIENT_RESPONSE_TYPE_CODE,
                         CLIENT_RESPONSE_TYPE_TOKEN,
                         CLIENT_RESPONSE_TYPE_ID_TOKEN,
                       "application_type", CLIENT_APP_TYPE_WEB,
                       "contacts",
                         CLIENT_CONTACT,
                       "logo_uri", CLIENT_LOGO_URI,
                       "client_uri", "error",
                       "policy_uri", CLIENT_POLICY_URI,
                       "tos_uri", CLIENT_TOS_URI);
  ck_assert_ptr_ne(j_client, NULL);
  ck_assert_int_eq(run_simple_test(&req_reg, "PUT", registration_client_uri, NULL, NULL, j_client, NULL, 400, NULL, "\"client_uri is optional and must be a string\"", NULL), 1);
  json_decref(j_client);

  // Invalid policy_uri
  j_client = json_pack("{sssss[s]sss[ssssss]s[sss]sss[s]ssssssss}",
                       "client_id", json_string_value(json_object_get(j_result, "client_id")),
                       "client_name", CLIENT_NAME,
                       "redirect_uris", CLIENT_REDIRECT_URI,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_NONE,
                       "grant_types",
                         CLIENT_GRANT_TYPE_AUTH_CODE,
                         CLIENT_GRANT_TYPE_PASSWORD,
                         CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS,
                         CLIENT_GRANT_TYPE_REFRESH_TOKEN,
                         CLIENT_GRANT_TYPE_DELETE_TOKEN,
                         CLIENT_GRANT_TYPE_DEVICE_AUTH,
                       "response_types",
                         CLIENT_RESPONSE_TYPE_CODE,
                         CLIENT_RESPONSE_TYPE_TOKEN,
                         CLIENT_RESPONSE_TYPE_ID_TOKEN,
                       "application_type", CLIENT_APP_TYPE_WEB,
                       "contacts",
                         CLIENT_CONTACT,
                       "logo_uri", CLIENT_LOGO_URI,
                       "client_uri", CLIENT_URI,
                       "policy_uri", "error",
                       "tos_uri", CLIENT_TOS_URI);
  ck_assert_ptr_ne(j_client, NULL);
  ck_assert_int_eq(run_simple_test(&req_reg, "PUT", registration_client_uri, NULL, NULL, j_client, NULL, 400, NULL, "\"policy_uri is optional and must be a string\"", NULL), 1);
  json_decref(j_client);

  // Invalid tos_uri
  j_client = json_pack("{sssss[s]sss[ssssss]s[sss]sss[s]ssssssss}",
                       "client_id", json_string_value(json_object_get(j_result, "client_id")),
                       "client_name", CLIENT_NAME,
                       "redirect_uris", CLIENT_REDIRECT_URI,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_NONE,
                       "grant_types",
                         CLIENT_GRANT_TYPE_AUTH_CODE,
                         CLIENT_GRANT_TYPE_PASSWORD,
                         CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS,
                         CLIENT_GRANT_TYPE_REFRESH_TOKEN,
                         CLIENT_GRANT_TYPE_DELETE_TOKEN,
                         CLIENT_GRANT_TYPE_DEVICE_AUTH,
                       "response_types",
                         CLIENT_RESPONSE_TYPE_CODE,
                         CLIENT_RESPONSE_TYPE_TOKEN,
                         CLIENT_RESPONSE_TYPE_ID_TOKEN,
                       "application_type", CLIENT_APP_TYPE_WEB,
                       "contacts",
                         CLIENT_CONTACT,
                       "logo_uri", CLIENT_LOGO_URI,
                       "client_uri", CLIENT_URI,
                       "policy_uri", CLIENT_POLICY_URI,
                       "tos_uri", "error");
  ck_assert_ptr_ne(j_client, NULL);
  ck_assert_int_eq(run_simple_test(&req_reg, "PUT", registration_client_uri, NULL, NULL, j_client, NULL, 400, NULL, "\"tos_uri is optional and must be a string\"", NULL), 1);
  json_decref(j_client);

  // Invalid jwks
  j_client = json_pack("{sssss[s]sss[ssssss]s[sss]sss[s]ssssssssss}",
                       "client_id", json_string_value(json_object_get(j_result, "client_id")),
                       "client_name", CLIENT_NAME,
                       "redirect_uris", CLIENT_REDIRECT_URI,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_PRIVATE_KEY_JWT,
                       "grant_types",
                         CLIENT_GRANT_TYPE_AUTH_CODE,
                         CLIENT_GRANT_TYPE_PASSWORD,
                         CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS,
                         CLIENT_GRANT_TYPE_REFRESH_TOKEN,
                         CLIENT_GRANT_TYPE_DELETE_TOKEN,
                         CLIENT_GRANT_TYPE_DEVICE_AUTH,
                       "response_types",
                         CLIENT_RESPONSE_TYPE_CODE,
                         CLIENT_RESPONSE_TYPE_TOKEN,
                         CLIENT_RESPONSE_TYPE_ID_TOKEN,
                       "application_type", CLIENT_APP_TYPE_WEB,
                       "contacts",
                         CLIENT_CONTACT,
                       "logo_uri", CLIENT_LOGO_URI,
                       "client_uri", CLIENT_URI,
                       "policy_uri", CLIENT_POLICY_URI,
                       "tos_uri", CLIENT_TOS_URI,
                       "jwks", "error");
  ck_assert_ptr_ne(j_client, NULL);
  ck_assert_int_eq(run_simple_test(&req_reg, "PUT", registration_client_uri, NULL, NULL, j_client, NULL, 400, NULL, "\"Invalid JWKS\"", NULL), 1);
  json_decref(j_client);

  // Invalid jwks_uri
  j_client = json_pack("{sssss[s]sss[ssssss]s[sss]sss[s]ssssssssss}",
                       "client_id", json_string_value(json_object_get(j_result, "client_id")),
                       "client_name", CLIENT_NAME,
                       "redirect_uris", CLIENT_REDIRECT_URI,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_PRIVATE_KEY_JWT,
                       "grant_types",
                         CLIENT_GRANT_TYPE_AUTH_CODE,
                         CLIENT_GRANT_TYPE_PASSWORD,
                         CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS,
                         CLIENT_GRANT_TYPE_REFRESH_TOKEN,
                         CLIENT_GRANT_TYPE_DELETE_TOKEN,
                         CLIENT_GRANT_TYPE_DEVICE_AUTH,
                       "response_types",
                         CLIENT_RESPONSE_TYPE_CODE,
                         CLIENT_RESPONSE_TYPE_TOKEN,
                         CLIENT_RESPONSE_TYPE_ID_TOKEN,
                       "application_type", CLIENT_APP_TYPE_WEB,
                       "contacts",
                         CLIENT_CONTACT,
                       "logo_uri", CLIENT_LOGO_URI,
                       "client_uri", CLIENT_URI,
                       "policy_uri", CLIENT_POLICY_URI,
                       "tos_uri", CLIENT_TOS_URI,
                       "jwks_uri", "error");
  ck_assert_ptr_ne(j_client, NULL);
  ck_assert_int_eq(run_simple_test(&req_reg, "PUT", registration_client_uri, NULL, NULL, j_client, NULL, 400, NULL, "\"jwks_uri is optional and must be an https:// uri\"", NULL), 1);
  json_decref(j_client);

  // Invalid jwks_uri and jwks
  j_client = json_pack("{sssss[s]sss[ssssss]s[sss]sss[s]sssssssssOss}",
                       "client_id", json_string_value(json_object_get(j_result, "client_id")),
                       "client_name", CLIENT_NAME,
                       "redirect_uris", CLIENT_REDIRECT_URI,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_PRIVATE_KEY_JWT,
                       "grant_types",
                         CLIENT_GRANT_TYPE_AUTH_CODE,
                         CLIENT_GRANT_TYPE_PASSWORD,
                         CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS,
                         CLIENT_GRANT_TYPE_REFRESH_TOKEN,
                         CLIENT_GRANT_TYPE_DELETE_TOKEN,
                         CLIENT_GRANT_TYPE_DEVICE_AUTH,
                       "response_types",
                         CLIENT_RESPONSE_TYPE_CODE,
                         CLIENT_RESPONSE_TYPE_TOKEN,
                         CLIENT_RESPONSE_TYPE_ID_TOKEN,
                       "application_type", CLIENT_APP_TYPE_WEB,
                       "contacts",
                         CLIENT_CONTACT,
                       "logo_uri", CLIENT_LOGO_URI,
                       "client_uri", CLIENT_URI,
                       "policy_uri", CLIENT_POLICY_URI,
                       "tos_uri", CLIENT_TOS_URI,
                       "jwks", j_jwks,
                       "jwks_uri", CLIENT_JWKS_URI);
  ck_assert_ptr_ne(j_client, NULL);
  ck_assert_int_eq(run_simple_test(&req_reg, "PUT", registration_client_uri, NULL, NULL, j_client, NULL, 400, NULL, "\"jwks_uri and jwks can't coexist\"", NULL), 1);
  json_decref(j_client);

  json_decref(j_result);
  json_decref(j_jwks);
  ulfius_clean_request(&req_reg);
}
END_TEST

START_TEST(test_oidc_registration_auth_register_client_management_update)
{
  json_t * j_client, * j_client_update, * j_jwks = json_loads(jwk_pubkey_ecdsa_str, JSON_DECODE_ANY, NULL);
  struct _u_request req, req_reg;
  struct _u_response resp;
  json_t * j_body, * j_result, * j_result_get;
  const char * token, * registration_access_token, * registration_client_uri;
  char * tmp;
  
  ck_assert_ptr_ne(j_jwks, NULL);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", PLUGIN_REGISTER_AUTH_SCOPE);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  token = json_string_value(json_object_get(j_body, "access_token"));
  ck_assert_ptr_ne(token, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  tmp = msprintf("Bearer %s", token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  j_client = json_pack("{s[s]}", "redirect_uris", CLIENT_REDIRECT_URI);
  ck_assert_ptr_ne(j_client, NULL);
  req_reg.http_verb = o_strdup("POST");
  req_reg.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/register");
  ck_assert_int_eq(ulfius_set_json_body_request(&req_reg, j_client), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_result, NULL);
  ck_assert_ptr_ne(json_object_get(j_result, "client_id"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "client_secret"), NULL);
  ck_assert_ptr_ne(registration_access_token = json_string_value(json_object_get(j_result, "registration_access_token")), NULL);
  ck_assert_ptr_ne(registration_client_uri = json_string_value(json_object_get(j_result, "registration_client_uri")), NULL);
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = msprintf(SERVER_URI "/client/%s", json_string_value(json_object_get(j_result, "client_id")));
  admin_req.http_verb = o_strdup("GET");
  json_decref(j_body);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);
  
  j_client_update = json_pack("{sOsss[s]sss[sssssss]s[sss]sss[s]sssssssssO}",
                       "client_id", json_object_get(j_result, "client_id"),
                       "client_name", CLIENT_NAME,
                       "redirect_uris", CLIENT_REDIRECT_URI,
                       "token_endpoint_auth_method", CLIENT_TOKEN_AUTH_PRIVATE_KEY_JWT,
                       "grant_types",
                         CLIENT_GRANT_TYPE_AUTH_CODE,
                         CLIENT_GRANT_TYPE_IMPLICIT,
                         CLIENT_GRANT_TYPE_PASSWORD,
                         CLIENT_GRANT_TYPE_CLIENT_CREDENTIALS,
                         CLIENT_GRANT_TYPE_REFRESH_TOKEN,
                         CLIENT_GRANT_TYPE_DELETE_TOKEN,
                         CLIENT_GRANT_TYPE_DEVICE_AUTH,
                       "response_types",
                         CLIENT_RESPONSE_TYPE_CODE,
                         CLIENT_RESPONSE_TYPE_TOKEN,
                         CLIENT_RESPONSE_TYPE_ID_TOKEN,
                       "application_type", CLIENT_APP_TYPE_WEB,
                       "contacts",
                         CLIENT_CONTACT,
                       "logo_uri", CLIENT_LOGO_URI,
                       "client_uri", CLIENT_URI,
                       "policy_uri", CLIENT_POLICY_URI,
                       "tos_uri", CLIENT_TOS_URI,
                       "jwks", j_jwks);
  ck_assert_ptr_ne(j_client_update, NULL);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  req_reg.http_verb = o_strdup("PUT");
  req_reg.http_url = o_strdup(registration_client_uri);
  ck_assert_int_eq(ulfius_set_json_body_request(&req_reg, j_client_update), U_OK);
  tmp = msprintf("Bearer %s", registration_access_token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  req_reg.http_url = o_strdup(registration_client_uri);
  tmp = msprintf("Bearer %s", registration_access_token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_result_get = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_result_get, NULL);
  ck_assert_ptr_eq(json_object_get(j_result_get, "registration_access_token"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result_get, "registration_client_uri"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result_get, "client_id_issued_at"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result_get, "client_secret_expires_at"), NULL);
  json_object_set_new(j_client_update, "client_secret", json_object_get(j_result_get, "client_secret"));
  ck_assert_int_eq(json_equal(j_client_update, j_result_get), 1);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);

  json_decref(j_result_get);
  json_decref(j_result);
  
  json_decref(j_client);
  json_decref(j_client_update);
  json_decref(j_jwks);
}
END_TEST

START_TEST(test_oidc_registration_auth_register_client_management_delete)
{
  json_t * j_client;
  struct _u_request req, req_reg;
  struct _u_response resp;
  json_t * j_body, * j_result;
  const char * token, * registration_access_token, * registration_client_uri;
  char * tmp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "scope", PLUGIN_REGISTER_AUTH_SCOPE);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  token = json_string_value(json_object_get(j_body, "access_token"));
  ck_assert_ptr_ne(token, NULL);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  tmp = msprintf("Bearer %s", token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  j_client = json_pack("{s[s]}", "redirect_uris", CLIENT_REDIRECT_URI);
  ck_assert_ptr_ne(j_client, NULL);
  req_reg.http_verb = o_strdup("POST");
  req_reg.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/register");
  ck_assert_int_eq(ulfius_set_json_body_request(&req_reg, j_client), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_result, NULL);
  ck_assert_ptr_ne(json_object_get(j_result, "client_id"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "client_secret"), NULL);
  ck_assert_ptr_ne(registration_access_token = json_string_value(json_object_get(j_result, "registration_access_token")), NULL);
  ck_assert_ptr_ne(registration_client_uri = json_string_value(json_object_get(j_result, "registration_client_uri")), NULL);
  o_free(admin_req.http_url);
  o_free(admin_req.http_verb);
  admin_req.http_url = msprintf(SERVER_URI "/client/%s", json_string_value(json_object_get(j_result, "client_id")));
  admin_req.http_verb = o_strdup("GET");
  json_decref(j_body);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  req_reg.http_verb = o_strdup("DELETE");
  req_reg.http_url = o_strdup(registration_client_uri);
  tmp = msprintf("Bearer %s", registration_access_token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);
  
  ulfius_init_request(&req_reg);
  ulfius_init_response(&resp);
  req_reg.http_url = o_strdup(registration_client_uri);
  tmp = msprintf("Bearer %s", registration_access_token);
  u_map_put(req_reg.map_header, "Authorization", tmp);
  o_free(tmp);
  ck_assert_int_eq(ulfius_send_http_request(&req_reg, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req_reg);
  ulfius_clean_response(&resp);
  
  json_decref(j_result);
  json_decref(j_client);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc token revocation");
  tc_core = tcase_create("test_oidc_token_revocation");
  tcase_add_test(tc_core, test_oidc_registration_plugin_add_using_management);
  tcase_add_test(tc_core, test_oidc_registration_auth_register_client_with_valid_credentials);
  tcase_add_test(tc_core, test_oidc_registration_auth_register_client_management_get);
  tcase_add_test(tc_core, test_oidc_registration_auth_register_client_management_get_invalid_access_token);
  tcase_add_test(tc_core, test_oidc_registration_auth_register_client_management_get_invalid_clent_id);
  tcase_add_test(tc_core, test_oidc_registration_auth_register_client_management_update_error_parameters);
  tcase_add_test(tc_core, test_oidc_registration_auth_register_client_management_update);
  tcase_add_test(tc_core, test_oidc_registration_auth_register_client_management_delete);
  tcase_add_test(tc_core, test_oidc_revocation_plugin_remove);
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
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", ADMIN_USERNAME, "password", ADMIN_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  j_body = NULL;
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    for (i=0; i<auth_resp.nb_cookies; i++) {
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(admin_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", ADMIN_USERNAME);
    do_test = 1;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
    do_test = 0;
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  json_decref(j_body);
  
  ulfius_clean_request(&admin_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

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
#define PLUGIN_NAME "oidc_refresh_one_use"
#define PLUGIN_DISPLAY_NAME "oidc with one use refresh tokens"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_REFRESH_TOKEN_ONE_USE_ALWAYS "always"
#define PLUGIN_REFRESH_TOKEN_ONE_USE_CLIENT_DRIVEN "client-driven"
#define PLUGIN_REFRESH_TOKEN_ONE_USE_NEVER "never"
#define PLUGIN_ACCESS_TOKEN_DURATION 3600

#define CLIENT_ID "client_refresh_one_use"
#define CLIENT_NAME "client one use refresh tokens"
#define CLIENT_SECRET "very-secret"

#define CLIENT_ID_PUBLIC "client_public_refresh_one_use"
#define CLIENT_NAME_PUBLIC "client public one use refresh tokens"
#define CLIENT_REDIRECT_URI_PUBLIC "https://client.org/"

struct _u_request admin_req;

START_TEST(test_oidc_refresh_token_one_use_add_module_always_ok)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisssisosososososososo}}",
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
                                  "refresh-token-one-use", PLUGIN_REFRESH_TOKEN_ONE_USE_ALWAYS,
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

START_TEST(test_oidc_refresh_token_one_use_add_module_client_driven_ok)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisssssisosososososososo}}",
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
                                  "refresh-token-one-use", PLUGIN_REFRESH_TOKEN_ONE_USE_CLIENT_DRIVEN,
                                  "client-refresh-token-one-use-parameter", "refresh-token-one-use",
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

START_TEST(test_oidc_refresh_token_one_use_add_module_client_driven_public_ok)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisssosisosososososososo}}",
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
                                  "refresh-token-one-use", PLUGIN_REFRESH_TOKEN_ONE_USE_CLIENT_DRIVEN,
                                  "client-refresh-token-one-use-public-client", json_true(),
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

START_TEST(test_oidc_refresh_token_one_use_add_module_never_ok)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisssisosososososososo}}",
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
                                  "refresh-token-one-use", PLUGIN_REFRESH_TOKEN_ONE_USE_NEVER,
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

START_TEST(test_oidc_refresh_token_one_use_add_client_ok)
{
  json_t * j_parameters = json_pack("{sssssssos[ss]sos[s]}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "client_secret", CLIENT_SECRET,
                                "confidential", json_true(),
                                "authorization_type", "password", "refresh_token",
                                "enabled", json_true(),
                                "token_endpoint_auth_method", "client_secret_post");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_refresh_token_one_use_add_client_driven_one_use_ok)
{
  json_t * j_parameters = json_pack("{sssssssssos[ss]sos[s]}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "client_secret", CLIENT_SECRET,
                                "refresh-token-one-use", "1",
                                "confidential", json_true(),
                                "authorization_type", "password", "refresh_token",
                                "enabled", json_true(),
                                "token_endpoint_auth_method", "client_secret_post");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_refresh_token_one_use_add_client_public_driven_one_use_ok)
{
  json_t * j_parameters = json_pack("{sssssssos[s]s[ss]so}",
                                    "client_id", CLIENT_ID_PUBLIC,
                                    "client_name", CLIENT_NAME,
                                    "client_secret", CLIENT_SECRET,
                                    "confidential", json_false(),
                                    "redirect_uri",
                                      CLIENT_REDIRECT_URI_PUBLIC,
                                    "authorization_type",
                                      "code",
                                      "refresh_token",
                                    "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_refresh_token_one_use_add_client_driven_multiple_use_ok)
{
  json_t * j_parameters = json_pack("{sssssssssos[ss]sos[s]}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "client_secret", CLIENT_SECRET,
                                "refresh-token-one-use", "0",
                                "confidential", json_true(),
                                "authorization_type", "password", "refresh_token",
                                "enabled", json_true(),
                                "token_endpoint_auth_method", "client_secret_post");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_refresh_token_one_use_delete_module)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_refresh_token_one_use_delete_client)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_refresh_token_one_use_delete_client_public)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID_PUBLIC, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_refresh_token_one_use_refresh_queue_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * refresh_token;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "client_secret", CLIENT_SECRET);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(refresh_token = json_string_value(json_object_get(j_resp, "refresh_token")), NULL);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  u_map_put(req.map_post_body, "grant_type", "refresh_token");
  u_map_put(req.map_post_body, "refresh_token", refresh_token);
  json_decref(j_resp);
  u_map_remove_from_key(req.map_post_body, "scope");
  u_map_remove_from_key(req.map_post_body, "username");
  u_map_remove_from_key(req.map_post_body, "password");
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(refresh_token = json_string_value(json_object_get(j_resp, "refresh_token")), NULL);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  u_map_put(req.map_post_body, "refresh_token", refresh_token);
  json_decref(j_resp);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "refresh_token"), NULL);
  ulfius_clean_response(&resp);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oidc_refresh_token_one_use_public_refresh_queue_valid)
{
  struct _u_request auth_req, client_req;
  struct _u_response auth_resp, resp;
  json_t * j_body, * j_resp = NULL;
  char * cookie;
  char * url, * redirect_uri_encoded, * code;
  const char * refresh_token;
  
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
  
  url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT_ID_PUBLIC);
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", url, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  o_free(url);

  // Test code framework
  redirect_uri_encoded = ulfius_url_encode(CLIENT_REDIRECT_URI_PUBLIC);
  ck_assert_int_eq(ulfius_set_request_properties(&auth_req, U_OPT_HTTP_VERB, "GET",
                                                            U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&nonce=nonce1234&g_continue&client_id=" CLIENT_ID_PUBLIC "&redirect_uri=",
                                                            U_OPT_HTTP_URL_APPEND, redirect_uri_encoded,
                                                            U_OPT_HTTP_URL_APPEND, "&scope=" SCOPE_LIST,
                                                            U_OPT_NONE), U_OK);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &resp), U_OK);
  ulfius_clean_request(&auth_req);
  ck_assert_int_eq(resp.status, 302);
  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  ulfius_clean_response(&resp);

  ulfius_init_request(&client_req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&client_req, U_OPT_HTTP_VERB, "POST",
                                                              U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                              U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                              U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID_PUBLIC,
                                                              U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI_PUBLIC,
                                                              U_OPT_POST_BODY_PARAMETER, "code", code,
                                                              U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&client_req, &resp), U_OK);
  ulfius_clean_request(&client_req);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(NULL, json_object_get(j_resp, "access_token"));
  ck_assert_ptr_ne(NULL, refresh_token = json_string_value(json_object_get(j_resp, "refresh_token")));
  ulfius_clean_response(&resp);

  ulfius_init_request(&client_req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&client_req, U_OPT_HTTP_VERB, "POST",
                                                              U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                              U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                              U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID_PUBLIC,
                                                              U_OPT_POST_BODY_PARAMETER, "refresh_token", refresh_token,
                                                              U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&client_req, &resp), U_OK);
  ulfius_clean_request(&client_req);
  ck_assert_int_eq(resp.status, 200);
  json_decref(j_resp);
  ck_assert_ptr_ne(NULL, (j_resp = ulfius_get_json_body_response(&resp, NULL)));
  ck_assert_ptr_ne(NULL, json_object_get(j_resp, "access_token"));
  ck_assert_ptr_ne(NULL, json_object_get(j_resp, "refresh_token"));
  ulfius_clean_response(&resp);

  ulfius_init_request(&client_req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&client_req, U_OPT_HTTP_VERB, "POST",
                                                              U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                              U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                              U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID_PUBLIC,
                                                              U_OPT_POST_BODY_PARAMETER, "refresh_token", json_string_value(json_object_get(j_resp, "refresh_token")),
                                                              U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&client_req, &resp), U_OK);
  ulfius_clean_request(&client_req);
  ck_assert_int_eq(resp.status, 200);
  json_decref(j_resp);
  ulfius_clean_response(&resp);

  ulfius_init_request(&client_req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&client_req, U_OPT_HTTP_VERB, "POST",
                                                              U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                              U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                              U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID_PUBLIC,
                                                              U_OPT_POST_BODY_PARAMETER, "refresh_token", refresh_token,
                                                              U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&client_req, &resp), U_OK);
  ulfius_clean_request(&client_req);
  ck_assert_int_eq(resp.status, 400);
  ulfius_clean_response(&resp);

  o_free(cookie);
  o_free(code);
  o_free(redirect_uri_encoded);
}
END_TEST

START_TEST(test_oidc_refresh_token_one_use_refresh_no_queue_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp;
  const char * refresh_token;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "client_secret", CLIENT_SECRET);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(refresh_token = json_string_value(json_object_get(j_resp, "refresh_token")), NULL);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  u_map_put(req.map_post_body, "grant_type", "refresh_token");
  u_map_put(req.map_post_body, "refresh_token", refresh_token);
  json_decref(j_resp);
  u_map_remove_from_key(req.map_post_body, "scope");
  u_map_remove_from_key(req.map_post_body, "username");
  u_map_remove_from_key(req.map_post_body, "password");
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_eq(json_object_get(j_resp, "refresh_token"), NULL);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  json_decref(j_resp);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_eq(json_object_get(j_resp, "refresh_token"), NULL);
  ulfius_clean_response(&resp);
  
  json_decref(j_resp);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oidc_refresh_token_one_use_simulate_attack_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_resp_orig;
  const char * refresh_token, * origin_refresh_token;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "password");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "client_secret", CLIENT_SECRET);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  u_map_put(req.map_post_body, "username", USERNAME);
  u_map_put(req.map_post_body, "password", PASSWORD);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp_orig = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp_orig, "access_token"), NULL);
  ck_assert_ptr_ne(origin_refresh_token = json_string_value(json_object_get(j_resp_orig, "refresh_token")), NULL);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  u_map_put(req.map_post_body, "grant_type", "refresh_token");
  u_map_put(req.map_post_body, "refresh_token", origin_refresh_token);
  u_map_remove_from_key(req.map_post_body, "scope");
  u_map_remove_from_key(req.map_post_body, "username");
  u_map_remove_from_key(req.map_post_body, "password");
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(refresh_token = json_string_value(json_object_get(j_resp, "refresh_token")), NULL);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  u_map_put(req.map_post_body, "refresh_token", refresh_token);
  json_decref(j_resp);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(refresh_token = json_string_value(json_object_get(j_resp, "refresh_token")), NULL);
  ulfius_clean_response(&resp);
  
  // Use old and disabled token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  u_map_put(req.map_post_body, "refresh_token", origin_refresh_token);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);
  ulfius_clean_response(&resp);
  
  // Use newly disabled token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  u_map_put(req.map_post_body, "refresh_token", refresh_token);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(400, resp.status);
  ulfius_clean_response(&resp);
  
  json_decref(j_resp);
  json_decref(j_resp_orig);
  ulfius_clean_request(&req);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc refresh token one use");
  tc_core = tcase_create("test_oidc_refresh_token_one_use");
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_add_module_always_ok);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_add_client_ok);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_refresh_queue_valid);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_simulate_attack_valid);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_delete_client);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_delete_module);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_add_module_client_driven_ok);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_add_client_driven_one_use_ok);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_refresh_queue_valid);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_simulate_attack_valid);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_delete_client);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_add_client_driven_multiple_use_ok);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_refresh_no_queue_valid);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_delete_module);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_add_module_never_ok);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_refresh_no_queue_valid);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_delete_client);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_delete_module);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_add_module_client_driven_public_ok);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_add_client_driven_one_use_ok);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_add_client_public_driven_one_use_ok);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_public_refresh_queue_valid);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_refresh_no_queue_valid);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_delete_client);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_delete_client_public);
  tcase_add_test(tc_core, test_oidc_refresh_token_one_use_delete_module);
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

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&admin_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

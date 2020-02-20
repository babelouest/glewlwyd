/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <liboath/oath.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api/"
#define USERNAME "user1"
#define USERNAME2 "user2"
#define PASSWORD "password"
#define SCOPE_LIST "scope1 scope2"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define MODULE_MODULE "oauth2"
#define MODULE_NAME "test_oauth2"
#define MODULE_NAME_2 "test_oauth2_2"
#define MODULE_DISPLAY_NAME "OAuth2 scheme for test"
#define MODULE_EXPIRATION 600
#define MODULE_MAX_USE 0

#define PROVIDER_PORT 8080
#define REDIRECT_URI "https://www.sso.tld/callback.html"
#define SESSION_EXPIRATION 600
#define CODE "codeXyz1234"
#define REFRESH_TOKEN "refresh_tokenXyz1234"
#define ACCESS_TOKEN "access_tokenXyz1234"
#define PROVIDER_NAME "provider"
#define PROVIDER_TYPE_OAUTH2 "oauth2"
#define PROVIDER_TYPE_OIDC "oidc"
#define PROVIDER_RESPONSE_TYPE "code"
#define PROVIDER_LOGO_URI "https://provider.tld/logo.png"
#define PROVIDER_LOGO_FA "fa-plus"
#define PROVIDER_CLIENT_ID "client1"
#define PROVIDER_CLIENT_SECRET "secret"
#define PROVIDER_USERID_PROPERTY "username"
#define PROVIDER_AUTH_ENDPOINT "http://localhost:8080/auth/"
#define PROVIDER_TOKEN_ENDPOINT "http://localhost:8080/token/"
#define PROVIDER_USERINFO_ENDPOINT "http://localhost:8080/userinfo"
#define PROVIDER_SCOPE "scope"

const char public_key[] = 
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\n"
"vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\n"
"aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\n"
"tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\n"
"e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\n"
"V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\n"
"MwIDAQAB\n"
"-----END PUBLIC KEY-----\n";

const unsigned char private_key[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw\n"
"kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr\n"
"m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi\n"
"NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV\n"
"3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2\n"
"QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs\n"
"kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go\n"
"amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM\n"
"+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9\n"
"D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC\n"
"0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y\n"
"lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+\n"
"hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp\n"
"bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X\n"
"+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B\n"
"BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC\n"
"2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx\n"
"QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz\n"
"5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9\n"
"Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0\n"
"NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j\n"
"8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma\n"
"3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K\n"
"y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB\n"
"jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=\n"
"-----END RSA PRIVATE KEY-----\n";

struct _u_request user_req;
struct _u_request admin_req;

static int callback_token_error_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_result = json_pack("{ss}", "error", "invalid_client");
  ulfius_set_json_body_response(response, 400, j_result);
  json_decref(j_result);
  
  return U_CALLBACK_CONTINUE;
}

static int callback_token_error_format (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_result = json_pack("{sssi}", "access_token", ACCESS_TOKEN, "expires_in", 3600);
  ulfius_set_json_body_response(response, 400, j_result);
  json_decref(j_result);
  
  return U_CALLBACK_CONTINUE;
}

static int callback_token_ok (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_result = json_pack("{sssssssi}", "refresh_token", REFRESH_TOKEN, "access_token", ACCESS_TOKEN, "token_type", "bearer", "expires_in", 3600);
  ulfius_set_json_body_response(response, 200, j_result);
  json_decref(j_result);
  
  return U_CALLBACK_CONTINUE;
}

static int callback_userinfo_error_format (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, "username=" USERNAME);
  
  return U_CALLBACK_CONTINUE;
}

static int callback_userinfo_ok (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_result = json_pack("{ss}", PROVIDER_USERID_PROPERTY, USERNAME);
  ulfius_set_json_body_response(response, 200, j_result);
  json_decref(j_result);
  
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_glwd_scheme_oauth2_irl_module_add_provider_error_parameters)
{
  json_t * j_parameters = json_pack("{sssssssisis{sssis[{ssso}]}}", 
                                    "module", MODULE_MODULE, 
                                    "name", MODULE_NAME, 
                                    "display_name", MODULE_DISPLAY_NAME, 
                                    "expiration", MODULE_EXPIRATION, 
                                    "max_use", MODULE_MAX_USE, 
                                    "parameters", 
                                      "redirect_uri", REDIRECT_URI,
                                      "session_expiration", SESSION_EXPIRATION,
                                      "provider_list",
                                        "name", PROVIDER_NAME,
                                        "enabled", json_true());
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssssisis{sssis[{sissssssssssssssssssssssso}]}}", 
                            "module", MODULE_MODULE, 
                            "name", MODULE_NAME, 
                            "display_name", MODULE_DISPLAY_NAME, 
                            "expiration", MODULE_EXPIRATION, 
                            "max_use", MODULE_MAX_USE, 
                            "parameters", 
                              "redirect_uri", REDIRECT_URI,
                              "session_expiration", SESSION_EXPIRATION,
                              "provider_list",
                                "name", 42,
                                "provider_type", PROVIDER_TYPE_OAUTH2,
                                "logo_uri", PROVIDER_LOGO_URI,
                                "logo_fa", PROVIDER_LOGO_FA,
                                "response_type", PROVIDER_RESPONSE_TYPE,
                                "client_id", PROVIDER_CLIENT_ID,
                                "client_secret", PROVIDER_CLIENT_SECRET,
                                "userid_property", PROVIDER_USERID_PROPERTY,
                                "auth_endpoint", PROVIDER_AUTH_ENDPOINT,
                                "token_endpoint", PROVIDER_TOKEN_ENDPOINT,
                                "userinfo_endpoint", PROVIDER_USERINFO_ENDPOINT,
                                "scope", PROVIDER_SCOPE,
                                "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssssisis{sssis[{ssssssssssssssssssssssssso}]}}", 
                            "module", MODULE_MODULE, 
                            "name", MODULE_NAME, 
                            "display_name", MODULE_DISPLAY_NAME, 
                            "expiration", MODULE_EXPIRATION, 
                            "max_use", MODULE_MAX_USE, 
                            "parameters", 
                              "redirect_uri", REDIRECT_URI,
                              "session_expiration", SESSION_EXPIRATION,
                              "provider_list",
                                "name", PROVIDER_NAME,
                                "provider_type", "error",
                                "logo_uri", PROVIDER_LOGO_URI,
                                "logo_fa", PROVIDER_LOGO_FA,
                                "response_type", PROVIDER_RESPONSE_TYPE,
                                "client_id", PROVIDER_CLIENT_ID,
                                "client_secret", PROVIDER_CLIENT_SECRET,
                                "userid_property", PROVIDER_USERID_PROPERTY,
                                "auth_endpoint", PROVIDER_AUTH_ENDPOINT,
                                "token_endpoint", PROVIDER_TOKEN_ENDPOINT,
                                "userinfo_endpoint", PROVIDER_USERINFO_ENDPOINT,
                                "scope", PROVIDER_SCOPE,
                                "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssssisis{sssis[{ssssssssssssssssssssssssso}]}}", 
                            "module", MODULE_MODULE, 
                            "name", MODULE_NAME, 
                            "display_name", MODULE_DISPLAY_NAME, 
                            "expiration", MODULE_EXPIRATION, 
                            "max_use", MODULE_MAX_USE, 
                            "parameters", 
                              "redirect_uri", REDIRECT_URI,
                              "session_expiration", SESSION_EXPIRATION,
                              "provider_list",
                                "name", PROVIDER_NAME,
                                "provider_type", PROVIDER_TYPE_OAUTH2,
                                "logo_uri", PROVIDER_LOGO_URI,
                                "logo_fa", PROVIDER_LOGO_FA,
                                "response_type", "error",
                                "client_id", PROVIDER_CLIENT_ID,
                                "client_secret", PROVIDER_CLIENT_SECRET,
                                "userid_property", PROVIDER_USERID_PROPERTY,
                                "auth_endpoint", PROVIDER_AUTH_ENDPOINT,
                                "token_endpoint", PROVIDER_TOKEN_ENDPOINT,
                                "userinfo_endpoint", PROVIDER_USERINFO_ENDPOINT,
                                "scope", PROVIDER_SCOPE,
                                "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssssisis{sssis[{ssssssssssssssssssssssso}]}}", 
                            "module", MODULE_MODULE, 
                            "name", MODULE_NAME, 
                            "display_name", MODULE_DISPLAY_NAME, 
                            "expiration", MODULE_EXPIRATION, 
                            "max_use", MODULE_MAX_USE, 
                            "parameters", 
                              "redirect_uri", REDIRECT_URI,
                              "session_expiration", SESSION_EXPIRATION,
                              "provider_list",
                                "name", PROVIDER_NAME,
                                "provider_type", PROVIDER_TYPE_OAUTH2,
                                "logo_uri", PROVIDER_LOGO_URI,
                                "logo_fa", PROVIDER_LOGO_FA,
                                "response_type", PROVIDER_RESPONSE_TYPE,
                                "client_id", PROVIDER_CLIENT_ID,
                                "client_secret", PROVIDER_CLIENT_SECRET,
                                "userid_property", PROVIDER_USERID_PROPERTY,
                                "token_endpoint", PROVIDER_TOKEN_ENDPOINT,
                                "userinfo_endpoint", PROVIDER_USERINFO_ENDPOINT,
                                "scope", PROVIDER_SCOPE,
                                "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssssisis{sssis[{sssssssssssssssssssssssssi}]}}", 
                            "module", MODULE_MODULE, 
                            "name", MODULE_NAME, 
                            "display_name", MODULE_DISPLAY_NAME, 
                            "expiration", MODULE_EXPIRATION, 
                            "max_use", MODULE_MAX_USE, 
                            "parameters", 
                              "redirect_uri", REDIRECT_URI,
                              "session_expiration", SESSION_EXPIRATION,
                              "provider_list",
                                "name", PROVIDER_NAME,
                                "provider_type", PROVIDER_TYPE_OAUTH2,
                                "logo_uri", PROVIDER_LOGO_URI,
                                "logo_fa", PROVIDER_LOGO_FA,
                                "response_type", PROVIDER_RESPONSE_TYPE,
                                "client_id", PROVIDER_CLIENT_ID,
                                "client_secret", PROVIDER_CLIENT_SECRET,
                                "userid_property", PROVIDER_USERID_PROPERTY,
                                "auth_endpoint", PROVIDER_AUTH_ENDPOINT,
                                "token_endpoint", PROVIDER_TOKEN_ENDPOINT,
                                "userinfo_endpoint", PROVIDER_USERINFO_ENDPOINT,
                                "scope", PROVIDER_SCOPE,
                                "enabled", 42);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/scheme/" MODULE_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_module_add_provider_oauth2_code)
{
  json_t * j_parameters = json_pack("{sssssssisis{sssis[{ssssssssssssssssssssssssso}]}}", 
                                    "module", MODULE_MODULE, 
                                    "name", MODULE_NAME, 
                                    "display_name", MODULE_DISPLAY_NAME, 
                                    "expiration", MODULE_EXPIRATION, 
                                    "max_use", MODULE_MAX_USE, 
                                    "parameters", 
                                      "redirect_uri", REDIRECT_URI,
                                      "session_expiration", SESSION_EXPIRATION,
                                      "provider_list",
                                        "name", PROVIDER_NAME,
                                        "provider_type", PROVIDER_TYPE_OAUTH2,
                                        "logo_uri", PROVIDER_LOGO_URI,
                                        "logo_fa", PROVIDER_LOGO_FA,
                                        "response_type", PROVIDER_RESPONSE_TYPE,
                                        "client_id", PROVIDER_CLIENT_ID,
                                        "client_secret", PROVIDER_CLIENT_SECRET,
                                        "userid_property", PROVIDER_USERID_PROPERTY,
                                        "auth_endpoint", PROVIDER_AUTH_ENDPOINT,
                                        "token_endpoint", PROVIDER_TOKEN_ENDPOINT,
                                        "userinfo_endpoint", PROVIDER_USERINFO_ENDPOINT,
                                        "scope", PROVIDER_SCOPE,
                                        "enabled", json_true());
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/mod/scheme/" MODULE_NAME, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_module_remove)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/scheme/" MODULE_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_register_get_oauth2)
{
  json_t * j_parameters = json_pack("{ssssssso}",
                                    "username", USERNAME,
                                    "scheme_type", MODULE_MODULE,
                                    "scheme_name", MODULE_NAME,
                                    "last_session", json_null()),
         * j_result = json_pack("{ssssss}", "provider", PROVIDER_NAME, "logo_uri", PROVIDER_LOGO_URI, "logo_fa", PROVIDER_LOGO_FA);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_parameters);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_register_invalid_parameters)
{
  json_t * j_parameters = json_pack("{sssssss{ssss}}",
                                    "username", USERNAME,
                                    "scheme_type", MODULE_MODULE,
                                    "scheme_name", MODULE_NAME,
                                    "value",
                                      "provider", PROVIDER_NAME,
                                      "action", "error");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);

  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", "error",
                             "action", "new");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_register_twice_forbidden)
{
  json_t * j_parameters = json_pack("{sssssss{ssss}}",
                                    "username", USERNAME,
                                    "scheme_type", MODULE_MODULE,
                                    "scheme_name", MODULE_NAME,
                                    "value",
                                      "provider", PROVIDER_NAME,
                                      "action", "new");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);

  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "new");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);

  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "delete");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_register_server_callback_error_state)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_parameters, * j_response;
  const char * redirect_to, * state = NULL;
  char ** url_array = NULL, * tmp = NULL;
  size_t i;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_copy_request(&req, &user_req);
  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "new");
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&req, j_parameters), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_response = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_response, NULL);
  redirect_to = json_string_value(json_object_get(j_response, "redirect_to"));
  ck_assert_ptr_ne(redirect_to, NULL);
  ck_assert_int_eq(split_string(redirect_to+o_strlen(REDIRECT_URI)+1, "&", &url_array), 6);
  for (i=0; url_array[i]!=NULL; i++) {
    if (o_strncmp(url_array[i], "state=", o_strlen("state=")) == 0) {
      state = url_array[i] + o_strlen("state=");
    }
  }
  ck_assert_ptr_ne(state, NULL);
  json_decref(j_parameters);
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  tmp = msprintf(REDIRECT_URI "?code=" CODE "&state=%s", state);
  j_parameters = json_pack("{sssssss{ssssssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "callback",
                             "redirect_to", tmp,
                             "state", "error");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  o_free(tmp);

  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "delete");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  free_string_array(url_array);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_register_server_callback_error_redirect_to)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_parameters, * j_response;
  const char * redirect_to, * state = NULL;
  char ** url_array = NULL;
  size_t i;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_copy_request(&req, &user_req);
  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "new");
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&req, j_parameters), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_response = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_response, NULL);
  redirect_to = json_string_value(json_object_get(j_response, "redirect_to"));
  ck_assert_ptr_ne(redirect_to, NULL);
  ck_assert_int_eq(split_string(redirect_to+o_strlen(REDIRECT_URI)+1, "&", &url_array), 6);
  for (i=0; url_array[i]!=NULL; i++) {
    if (o_strncmp(url_array[i], "state=", o_strlen("state=")) == 0) {
      state = url_array[i] + o_strlen("state=");
    }
  }
  ck_assert_ptr_ne(state, NULL);
  json_decref(j_parameters);
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  j_parameters = json_pack("{sssssss{ssssssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "callback",
                             "redirect_to", "error",
                             "state", state);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);

  free_string_array(url_array);

  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "delete");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_register_server_callback_response_error_scope)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_parameters, * j_response;
  const char * redirect_to, * state = NULL;
  char ** url_array = NULL, * tmp = NULL;
  size_t i;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_copy_request(&req, &user_req);
  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "new");
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&req, j_parameters), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_response = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_response, NULL);
  redirect_to = json_string_value(json_object_get(j_response, "redirect_to"));
  ck_assert_ptr_ne(redirect_to, NULL);
  ck_assert_int_eq(split_string(redirect_to+o_strlen(REDIRECT_URI)+1, "&", &url_array), 6);
  for (i=0; url_array[i]!=NULL; i++) {
    if (o_strncmp(url_array[i], "state=", o_strlen("state=")) == 0) {
      state = url_array[i] + o_strlen("state=");
    }
  }
  ck_assert_ptr_ne(state, NULL);
  json_decref(j_parameters);
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  tmp = msprintf(REDIRECT_URI "?error=invalid_scope&state=", state);
  j_parameters = json_pack("{sssssss{ssssssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "callback",
                             "redirect_to", tmp,
                             "state", state);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  o_free(tmp);

  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "delete");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  free_string_array(url_array);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_register_server_callback_response_error_client)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_parameters, * j_response;
  const char * redirect_to, * state = NULL;
  char ** url_array = NULL, * tmp = NULL;
  size_t i;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_copy_request(&req, &user_req);
  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "new");
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&req, j_parameters), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_response = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_response, NULL);
  redirect_to = json_string_value(json_object_get(j_response, "redirect_to"));
  ck_assert_ptr_ne(redirect_to, NULL);
  ck_assert_int_eq(split_string(redirect_to+o_strlen(REDIRECT_URI)+1, "&", &url_array), 6);
  for (i=0; url_array[i]!=NULL; i++) {
    if (o_strncmp(url_array[i], "state=", o_strlen("state=")) == 0) {
      state = url_array[i] + o_strlen("state=");
    }
  }
  ck_assert_ptr_ne(state, NULL);
  json_decref(j_parameters);
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  tmp = msprintf(REDIRECT_URI "?error=invalid_client&state=", state);
  j_parameters = json_pack("{sssssss{ssssssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "callback",
                             "redirect_to", tmp,
                             "state", state);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  o_free(tmp);

  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "delete");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  free_string_array(url_array);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_register_server_callback_token_response_error_client)
{
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, PROVIDER_PORT, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_token_error_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  struct _u_request req;
  struct _u_response resp;
  json_t * j_parameters, * j_response;
  const char * redirect_to, * state = NULL;
  char ** url_array = NULL, * tmp = NULL;
  size_t i;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_copy_request(&req, &user_req);
  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "new");
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&req, j_parameters), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_response = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_response, NULL);
  redirect_to = json_string_value(json_object_get(j_response, "redirect_to"));
  ck_assert_ptr_ne(redirect_to, NULL);
  ck_assert_int_eq(split_string(redirect_to+o_strlen(REDIRECT_URI)+1, "&", &url_array), 6);
  for (i=0; url_array[i]!=NULL; i++) {
    if (o_strncmp(url_array[i], "state=", o_strlen("state=")) == 0) {
      state = url_array[i] + o_strlen("state=");
    }
  }
  ck_assert_ptr_ne(state, NULL);
  json_decref(j_parameters);
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  tmp = msprintf(REDIRECT_URI "?code=" CODE "&state=%s", state);
  j_parameters = json_pack("{sssssss{ssssssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "callback",
                             "redirect_to", tmp,
                             "state", state);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  o_free(tmp);

  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "delete");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);

  ck_assert_int_eq(ulfius_stop_framework(&instance), U_OK);
  ulfius_clean_instance(&instance);
  free_string_array(url_array);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_register_server_callback_token_response_error_format)
{
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, PROVIDER_PORT, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_token_error_format, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  struct _u_request req;
  struct _u_response resp;
  json_t * j_parameters, * j_response;
  const char * redirect_to, * state = NULL;
  char ** url_array = NULL, * tmp = NULL;
  size_t i;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_copy_request(&req, &user_req);
  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "new");
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&req, j_parameters), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_response = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_response, NULL);
  redirect_to = json_string_value(json_object_get(j_response, "redirect_to"));
  ck_assert_ptr_ne(redirect_to, NULL);
  ck_assert_int_eq(split_string(redirect_to+o_strlen(REDIRECT_URI)+1, "&", &url_array), 6);
  for (i=0; url_array[i]!=NULL; i++) {
    if (o_strncmp(url_array[i], "state=", o_strlen("state=")) == 0) {
      state = url_array[i] + o_strlen("state=");
    }
  }
  ck_assert_ptr_ne(state, NULL);
  json_decref(j_parameters);
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  tmp = msprintf(REDIRECT_URI "?code=" CODE "&state=%s", state);
  j_parameters = json_pack("{sssssss{ssssssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "callback",
                             "redirect_to", tmp,
                             "state", state);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  o_free(tmp);

  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "delete");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);

  ck_assert_int_eq(ulfius_stop_framework(&instance), U_OK);
  ulfius_clean_instance(&instance);
  free_string_array(url_array);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_register_server_callback_userinfo_response_error_format)
{
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, PROVIDER_PORT, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_token_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_userinfo_error_format, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  struct _u_request req;
  struct _u_response resp;
  json_t * j_parameters, * j_response;
  const char * redirect_to, * state = NULL;
  char ** url_array = NULL, * tmp = NULL;
  size_t i;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_copy_request(&req, &user_req);
  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "new");
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&req, j_parameters), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_response = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_response, NULL);
  redirect_to = json_string_value(json_object_get(j_response, "redirect_to"));
  ck_assert_ptr_ne(redirect_to, NULL);
  ck_assert_int_eq(split_string(redirect_to+o_strlen(REDIRECT_URI)+1, "&", &url_array), 6);
  for (i=0; url_array[i]!=NULL; i++) {
    if (o_strncmp(url_array[i], "state=", o_strlen("state=")) == 0) {
      state = url_array[i] + o_strlen("state=");
    }
  }
  ck_assert_ptr_ne(state, NULL);
  json_decref(j_parameters);
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  tmp = msprintf(REDIRECT_URI "?code=" CODE "&state=%s", state);
  j_parameters = json_pack("{sssssss{ssssssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "callback",
                             "redirect_to", tmp,
                             "state", state);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  o_free(tmp);

  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "delete");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);

  ck_assert_int_eq(ulfius_stop_framework(&instance), U_OK);
  ulfius_clean_instance(&instance);
  free_string_array(url_array);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_register_ok)
{
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, PROVIDER_PORT, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_token_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_userinfo_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  struct _u_request req;
  struct _u_response resp;
  json_t * j_parameters, * j_response;
  const char * redirect_to, * state = NULL;
  char ** url_array = NULL, * tmp = NULL;
  size_t i;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_copy_request(&req, &user_req);
  j_parameters = json_pack("{sssssss{ssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "new");
  req.http_verb = o_strdup("POST");
  req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&req, j_parameters), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_response = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(j_response, NULL);
  redirect_to = json_string_value(json_object_get(j_response, "redirect_to"));
  ck_assert_ptr_ne(redirect_to, NULL);
  ck_assert_int_eq(split_string(redirect_to+o_strlen(REDIRECT_URI)+1, "&", &url_array), 6);
  for (i=0; url_array[i]!=NULL; i++) {
    if (o_strncmp(url_array[i], "state=", o_strlen("state=")) == 0) {
      state = url_array[i] + o_strlen("state=");
    }
  }
  ck_assert_ptr_ne(state, NULL);
  json_decref(j_parameters);
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  tmp = msprintf(REDIRECT_URI "?code=" CODE "&state=%s", state);
  j_parameters = json_pack("{sssssss{ssssssss}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                             "provider", PROVIDER_NAME,
                             "action", "callback",
                             "redirect_to", tmp,
                             "state", state);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  o_free(tmp);

  ck_assert_int_eq(ulfius_stop_framework(&instance), U_OK);
  ulfius_clean_instance(&instance);
  free_string_array(url_array);
}
END_TEST

START_TEST(test_glwd_scheme_oauth2_irl_register_delete)
{
  json_t * j_parameters = json_pack("{sssssss{ssss}}",
                                   "username", USERNAME,
                                   "scheme_type", MODULE_MODULE,
                                   "scheme_name", MODULE_NAME,
                                   "value",
                                     "provider", PROVIDER_NAME,
                                     "action", "delete");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd scheme oauth2");
  tc_core = tcase_create("test_glwd_scheme_oauth2_irl");
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_module_add_provider_error_parameters);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_module_add_provider_oauth2_code);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_register_get_oauth2);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_register_invalid_parameters);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_register_twice_forbidden);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_register_server_callback_error_state);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_register_server_callback_error_redirect_to);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_register_server_callback_response_error_scope);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_register_server_callback_response_error_client);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_register_server_callback_token_response_error_client);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_register_server_callback_token_response_error_format);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_register_server_callback_userinfo_response_error_format);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_register_ok);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_register_delete);
  tcase_add_test(tc_core, test_glwd_scheme_oauth2_irl_module_remove);
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
  
  oath_init();
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&user_req);
  ulfius_init_request(&admin_req);
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    for (i=0; i<auth_resp.nb_cookies; i++) {
      y_log_message(Y_LOG_LEVEL_INFO, "user %s authenticated", USERNAME);
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(user_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    do_test = 1;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication user");
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);

  ulfius_init_request(&auth_req);
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
  
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&admin_req);
  
  y_close_logs();
  oath_done();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

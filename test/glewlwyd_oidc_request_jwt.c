/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <jwt.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define USERNAME "user1"
#define PASSWORD "password"
#define SCOPE_LIST "openid"
#define SCOPE_LIST_WITH_AUTH "scope1 openid"
#define CLIENT "client4_id"
#define CLIENT_PUBLIC "client1_id"
#define CLIENT_ERROR "error"
#define CLIENT_SECRET "secret"
#define REDIRECT_URI "../../test-oidc.html?param=client4"
#define REDIRECT_URI_PUBLIC "../../test-oidc.html?param=client1_cb1"
#define RESPONSE_TYPE "id_token token"
#define NONCE_TEST "nonce5678"
#define STATE_TEST "abcxyz"

struct _u_request user_req;
char * code;

static int callback_request_uri (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, (const char *)user_data);
  return U_CALLBACK_COMPLETE;
}

static int callback_request_uri_status_404 (const struct _u_request * request, struct _u_response * response, void * user_data) {
  response->status = 404;
  return U_CALLBACK_COMPLETE;
}

static int callback_request_uri_incomplete_jwt (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, (const char *)(user_data+1));
  return U_CALLBACK_COMPLETE;
}

START_TEST(test_oidc_request_jwt_redirect_login)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/oidc/auth?request=%s", SERVER_URI, request);
  ck_assert_int_eq(run_simple_test(NULL, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "login.html"), 1);
  
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_ok)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/oidc/auth?g_continue&request=%s", SERVER_URI, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "id_token="), 1);
  
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_client_public_response_ok)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_NONE, NULL, 0), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT_PUBLIC);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI_PUBLIC);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/oidc/auth?g_continue&request=%s", SERVER_URI, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "id_token="), 1);
  
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_unsigned_error)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_NONE, NULL, 0), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/oidc/auth?g_continue&request=%s", SERVER_URI, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_invalid_signature)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)(CLIENT_SECRET "error"), o_strlen((CLIENT_SECRET "error"))), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/oidc/auth?g_continue&request=%s", SERVER_URI, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_error_no_response_type_in_request)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/oidc/auth?g_continue&response_type=" RESPONSE_TYPE "&request=%s", SERVER_URI, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_error_no_client_id_in_request)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/oidc/auth?g_continue&response_type=" RESPONSE_TYPE "&request=%s", SERVER_URI, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_error_client_id_missing)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/oidc/auth?g_continue&request=%s", SERVER_URI, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_error_client_id_invalid)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT_ERROR);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/oidc/auth?g_continue&request=%s", SERVER_URI, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_error_request_in_request)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "request", "plop");
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/oidc/auth?g_continue&request=%s", SERVER_URI, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_nonce_supersede)
{
  jwt_t * jwt_request = NULL, * jwt_id_token = NULL;
  char * request, * id_token = NULL;
  jwt_new(&jwt_request);
  struct _u_response resp;
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  o_free(user_req.http_verb);
  user_req.http_url = msprintf("%s/oidc/auth?g_continue&request=%s&nonce=" NONCE_TEST, SERVER_URI, request);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  ck_assert_ptr_ne(id_token, NULL);
  if (o_strchr(id_token, '&') != NULL) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ck_assert_int_eq(jwt_decode(&jwt_id_token, id_token, NULL, 0), 0);
  ck_assert_str_eq(jwt_get_grant(jwt_id_token, "nonce"), NONCE_TEST);
  
  o_free(request);
  o_free(id_token);
  jwt_free(jwt_request);
  jwt_free(jwt_id_token);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_state_supersede)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/oidc/auth?g_continue&request=%s&state=" STATE_TEST, SERVER_URI, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, STATE_TEST), 1);
  
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_response_type_supersede)
{
  jwt_t * jwt_request = NULL;
  char * request;
  jwt_new(&jwt_request);
  struct _u_response resp;
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", "id_token");
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  o_free(user_req.http_verb);
  user_req.http_url = msprintf("%s/oidc/auth?g_continue&request=%s", SERVER_URI, request);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  
  o_free(request);
  jwt_free(jwt_request);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_request_jwt_error_redirect_uri)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", "invalid");
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/oidc/auth?g_continue&request=%s", SERVER_URI, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "error="), 1);
  
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_uri_jwt_response_ok)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  struct _u_instance instance;
  ulfius_init_instance(&instance, 7597, NULL, NULL);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/", 0, &callback_request_uri, request);
  ulfius_start_framework(&instance);
  
  url = msprintf("%s/oidc/auth?g_continue&request_uri=http://localhost:7597/", SERVER_URI);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "id_token="), 1);
  
  ulfius_clean_instance(&instance);
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_uri_jwt_no_connection)
{  
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "/oidc/auth?g_continue&request_uri=http://localhost:7597/", NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_request_uri_jwt_connection_error)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  struct _u_instance instance;
  ulfius_init_instance(&instance, 7597, NULL, NULL);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/", 0, &callback_request_uri_status_404, request);
  ulfius_start_framework(&instance);
  
  url = msprintf("%s/oidc/auth?g_continue&request_uri=http://localhost:7597/", SERVER_URI);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  ulfius_clean_instance(&instance);
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_uri_jwt_response_incomplete)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  struct _u_instance instance;
  ulfius_init_instance(&instance, 7597, NULL, NULL);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_HS256, (unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET)), 0);
  jwt_add_grant(jwt_request, "aud", REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/", 0, &callback_request_uri_incomplete_jwt, request);
  ulfius_start_framework(&instance);
  
  url = msprintf("%s/oidc/auth?g_continue&request_uri=http://localhost:7597/", SERVER_URI);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  ulfius_clean_instance(&instance);
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc request_jwt");
  tc_core = tcase_create("test_oidc_implicit");
  tcase_add_test(tc_core, test_oidc_request_jwt_redirect_login);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_ok);
  tcase_add_test(tc_core, test_oidc_request_jwt_client_public_response_ok);
  tcase_add_test(tc_core, test_oidc_request_jwt_unsigned_error);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_invalid_signature);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_error_no_response_type_in_request);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_error_no_client_id_in_request);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_error_client_id_missing);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_error_client_id_invalid);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_error_request_in_request);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_nonce_supersede);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_state_supersede);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_response_type_supersede);
  tcase_add_test(tc_core, test_oidc_request_jwt_error_redirect_uri);
  tcase_add_test(tc_core, test_oidc_request_uri_jwt_response_ok);
  tcase_add_test(tc_core, test_oidc_request_uri_jwt_no_connection);
  tcase_add_test(tc_core, test_oidc_request_uri_jwt_connection_error);
  tcase_add_test(tc_core, test_oidc_request_uri_jwt_response_incomplete);
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
  if (res == U_OK && auth_resp.status == 200 && auth_resp.nb_cookies) {
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
    
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);

    scope_req.http_verb = strdup("PUT");
    scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
    j_body = json_pack("{ss}", "scope", SCOPE_LIST);
    ulfius_set_json_body_request(&scope_req, j_body);
    json_decref(j_body);
    if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
    } else {
      o_free(scope_req.http_url);
      scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT_PUBLIC);
      j_body = json_pack("{ss}", "scope", SCOPE_LIST);
      ulfius_set_json_body_request(&scope_req, j_body);
      json_decref(j_body);
      if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT_PUBLIC, SCOPE_LIST);
      } else {
        do_test = 1;
      }
    }

    ulfius_clean_response(&scope_resp);
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
  if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
  }
  o_free(scope_req.http_url);
  scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
  }
  json_decref(j_body);
  
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

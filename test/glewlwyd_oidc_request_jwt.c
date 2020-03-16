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
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
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

#define PLUGIN_MODULE "oidc"
#define PLUGIN_NAME "oidc_pubkey"
#define PLUGIN_DISPLAY_NAME "oidc pubkey"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_JWT_TYPE "sha"
#define PLUGIN_JWT_KEY_SIZE "256"
#define PLUGIN_KEY "secret"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_ACCESS_TOKEN_DURATION 3600

#define CLIENT_PUBKEY_PARAM "pubkey"
#define CLIENT_JWKS_PARAM "jwks"
#define CLIENT_JWKS_URI_PARAM "jwks_uri"
#define CLIENT_PUBKEY_ID "client_pubkey"
#define CLIENT_PUBKEY_NAME "client with pubkey"
#define CLIENT_PUBKEY_REDIRECT "https://glewlwyd.local/"
#define KID_PUB "pubkey"
#define KID_PRIV "privkey"

struct _u_request admin_req;
struct _u_request user_req;
char * code;

const char jwk_pubkey_ecdsa_str[] = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                     "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"" KID_PUB "\"}]}";
const char jwk_pubkey_ecdsa_pem[] = "-----BEGIN PUBLIC KEY-----\n"\
                                     "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8A\n"\
                                     "iTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==\n"\
                                     "-----END PUBLIC KEY-----\n";
const char jwk_privkey_ecdsa_pem[] = "-----BEGIN EC PRIVATE KEY-----\n"\
                                      "MHgCAQEEIQDzvQwHqB+5Mnge1SdS9gzImmvl5Rk0/gGTjdtV2Pd4AaAKBggqhkjO\n"\
                                      "PQMBB6FEA0IABDCgQkzSHClEg4otdckrN+duog2fAIk6O07uijwKr+w+4Etl6SRW\n"\
                                      "2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM=\n"\
                                      "-----END EC PRIVATE KEY-----\n";
const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                   "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                   "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                   ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"" KID_PUB "\"}";
const char jwk_pubkey_rsa_pem[] = "-----BEGIN PUBLIC KEY-----\n"\
                                   "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX\n"\
                                   "ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS\n"\
                                   "oc/BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt\n"\
                                   "7/RN5w6Cf0h4QyQ5v+65YGjQR0/FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0\n"\
                                   "zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0f\n"\
                                   "M4lFd2NcRwr3XPksINHaQ+G/xBniIqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDK\n"\
                                   "gwIDAQAB\n"\
                                   "-----END PUBLIC KEY-----\n";
const char jwk_privkey_rsa_pem[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
                                    "MIIEowIBAAKCAQEA0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78L\n"\
                                    "hWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc/BJECPebWKRXjBZCiFV4n3oknj\n"\
                                    "hMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt7/RN5w6Cf0h4QyQ5v+65YGjQR0/F\n"\
                                    "DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbO\n"\
                                    "pbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ+G/xBni\n"\
                                    "Iqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDKgwIDAQABAoIBAF+HE7XiWP4J+BWD\n"\
                                    "7FwfK3V4seb8LINRSzeRNxGhukSaFR/hyyyg/TO3ceaKOxlEZJ3IZ60cHlJAu4U+\n"\
                                    "XySzNFmxQCjS1mNr7+wejal0s1L8U9P2En6oo8Kd0U85QWgsVqeHaBZOTdqPBsv5\n"\
                                    "xzSq6AAyJCeOqUVKIbF8sG0XgHWGjMBbPbb/Hf3D1WN4tO2t7fDDekzcJtHUmsJv\n"\
                                    "b+O1Igpd0pOWYhu8aIzy7uLG4NVNo8eCAUzQc52yUsxRyuuo0/G4JLqrJNBo7JAy\n"\
                                    "ZNfWeKsI8G7J5+I9lgYot0S/lLNpRlZGPH5Bc5ntc9B2yJH89GOpqpzmLanNF+I3\n"\
                                    "3CqAAvECgYEA83i+7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxt\n"\
                                    "PVnwD20R+60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQy\n"\
                                    "qVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfsCgYEA3dfO\n"\
                                    "R9cuYq+0S+mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgT\n"\
                                    "nCdpYzBcOfW5r370AFXjiWft/NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ+1k\n"\
                                    "Yd/s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxkCgYAbiw9eRzphr3Lyglb38guP\n"\
                                    "jG6mm7SXOL8ftVORLzGPlJ1fdygTSiKZjDEiLZ6ZMC57RQ5rl2mAUbIEnhzy1DZU\n"\
                                    "XjTZdG6AoNM/xqRiEWjm0ADvtB782a25hlzcLebcjbgbYa9HmxIPFTIA3bOrwt+f\n"\
                                    "0RSazqtjc5vxh6IqROIGPQKBgQCz2UAf1+CAGygVHw5pzZH8TaDDbzatPaQY4CG8\n"\
                                    "iWURMTV5+sDqG5RS8x8FwymfyWp5bq/POdhjlJJAXukx0L9qAjecbwhunUFRvQlS\n"\
                                    "KtpE2pR8uFxBv930YXgOHt7vhZtGyhtGie6NNg3XEJo/pM7rWO9atf4vXy3FfDj3\n"\
                                    "hD9yCQKBgBsjP6eia18kos9baBYCm1lfiXSN40OMqbva2zFsd60CQX5rdBaGM4FC\n"\
                                    "GRFRRHDqsHpkTfNc6AwGmvgZNCljRg4yR2Q3Q5hYVtwDe5SPqbsZP5h2Ridda8ck\n"\
                                    "fDueVy0nt0j5kXysGSOslNuGcb0ChWCLXZXVChszuiGus0yoQFUV\n"\
                                    "-----END RSA PRIVATE KEY-----\n";

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

int callback_jwks_ok (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_jwks = json_loads(jwk_pubkey_ecdsa_str, JSON_DECODE_ANY, NULL);
  ulfius_set_json_body_response(response, 200, j_jwks);
  json_decref(j_jwks);
  return U_CALLBACK_CONTINUE;
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
  
  ulfius_stop_framework(&instance);
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
  
  ulfius_stop_framework(&instance);
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
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_add_module_request_signed)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisosososososososossssss}}",
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
                                  "request-parameter-allow", json_true(),
                                  "request-uri-allow-https-non-secure", json_true(),
                                  "client-pubkey-parameter", CLIENT_PUBKEY_PARAM,
                                  "client-jwks-parameter", CLIENT_JWKS_PARAM,
                                  "client-jwks_uri-parameter", CLIENT_JWKS_URI_PARAM);

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_request_jwt_add_client_pubkey)
{
  json_t * j_client = json_pack("{ss ss ss so s[s] s[sss] ss so}", "client_id", CLIENT_PUBKEY_ID, "secret", CLIENT_SECRET, "name", CLIENT_PUBKEY_NAME, "confidential", json_true(), "redirect_uri", CLIENT_PUBKEY_REDIRECT, "authorization_type", "code", "token", "id_token", "pubkey", jwk_pubkey_ecdsa_pem, "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_request_jwt_add_client_jwks)
{
  json_t * j_client = json_pack("{ss ss ss so s[s] s[sss] so so}", "client_id", CLIENT_PUBKEY_ID, "secret", CLIENT_SECRET, "name", CLIENT_PUBKEY_NAME, "confidential", json_true(), "redirect_uri", CLIENT_PUBKEY_REDIRECT, "authorization_type", "code", "token", "id_token", "jwks", json_loads(jwk_pubkey_ecdsa_str, JSON_DECODE_ANY, NULL), "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_request_jwt_add_client_jwks_uri)
{
  json_t * j_client = json_pack("{ss ss ss so s[s] s[sss] ss so}", "client_id", CLIENT_PUBKEY_ID, "secret", CLIENT_SECRET, "name", CLIENT_PUBKEY_NAME, "confidential", json_true(), "redirect_uri", CLIENT_PUBKEY_REDIRECT, "authorization_type", "code", "token", "id_token", "jwks_uri", "http://localhost:7462/jwks", "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_request_jwt_add_client_multiple)
{
  json_t * j_client = json_pack("{ss ss ss so s[s] s[sss] so ss so ss}", "client_id", CLIENT_PUBKEY_ID, "secret", CLIENT_SECRET, "name", CLIENT_PUBKEY_NAME, "confidential", json_true(), "redirect_uri", CLIENT_PUBKEY_REDIRECT, "authorization_type", "code", "token", "id_token", "enabled", json_true(), "pubkey", jwk_pubkey_rsa_pem, "jwks", json_loads(jwk_pubkey_rsa_str, JSON_DECODE_ANY, NULL), "jwks_uri", "http://localhost:7462/jwks");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_request_jwt_delete_client_pubkey)
{
  json_t * j_param = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_PUBKEY_ID, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_request_jwt_delete_module_request_signed)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_client_pubkey_ok)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7462, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks", NULL, 0, &callback_jwks_ok, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_ES256, (unsigned char *)jwk_privkey_ecdsa_pem, o_strlen(jwk_privkey_ecdsa_pem)), 0);
  jwt_add_grant(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  jwt_add_grant(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  jwt_add_header(jwt_request, "kid", KID_PUB);
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf(SERVER_URI "/oidc/auth?g_continue&request=%s", request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "id_token="), 1);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);

  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_client_pubkey_invalid_signature)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7462, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks", NULL, 0, &callback_jwks_ok, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_RS256, (unsigned char *)jwk_privkey_rsa_pem, o_strlen(jwk_privkey_rsa_pem)), 0);
  jwt_add_grant(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  jwt_add_grant(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  jwt_add_header(jwt_request, "kid", KID_PUB);
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf(SERVER_URI "/oidc/auth?g_continue&request=%s", request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);

  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_client_pubkey_invalid_kid)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7462, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks", NULL, 0, &callback_jwks_ok, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_ES256, (unsigned char *)jwk_privkey_ecdsa_pem, o_strlen(jwk_privkey_ecdsa_pem)), 0);
  jwt_add_grant(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  jwt_add_grant(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  jwt_add_header(jwt_request, "kid", "error");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf(SERVER_URI "/oidc/auth?g_continue&request=%s", request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);

  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_client_pubkey_no_kid_ok)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7462, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks", NULL, 0, &callback_jwks_ok, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_ES256, (unsigned char *)jwk_privkey_ecdsa_pem, o_strlen(jwk_privkey_ecdsa_pem)), 0);
  jwt_add_grant(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  jwt_add_grant(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf(SERVER_URI "/oidc/auth?g_continue&request=%s", request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "id_token="), 1);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);

  o_free(url);
  o_free(request);
  jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_request_jwt_response_client_pubkey_test_priority)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  jwt_new(&jwt_request);
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7462, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks", NULL, 0, &callback_jwks_ok, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_ES256, (unsigned char *)jwk_privkey_ecdsa_pem, o_strlen(jwk_privkey_ecdsa_pem)), 0);
  jwt_add_grant(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  jwt_add_grant(jwt_request, "response_type", RESPONSE_TYPE);
  jwt_add_grant(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  jwt_add_grant(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  jwt_add_header(jwt_request, "kid", KID_PUB);
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf(SERVER_URI "/oidc/auth?g_continue&request=%s", request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "id_token="), 1);
  o_free(url);
  o_free(request);
  
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_RS256, (unsigned char *)jwk_privkey_rsa_pem, o_strlen(jwk_privkey_rsa_pem)), 0);
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  url = msprintf(SERVER_URI "/oidc/auth?g_continue&request=%s", request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  ulfius_stop_framework(&instance);
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
  tcase_add_test(tc_core, test_oidc_request_jwt_add_module_request_signed);
  tcase_add_test(tc_core, test_oidc_request_jwt_add_client_pubkey);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_client_pubkey_ok);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_client_pubkey_invalid_signature);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_client_pubkey_no_kid_ok);
  tcase_add_test(tc_core, test_oidc_request_jwt_delete_client_pubkey);
  tcase_add_test(tc_core, test_oidc_request_jwt_add_client_jwks);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_client_pubkey_ok);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_client_pubkey_invalid_signature);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_client_pubkey_invalid_kid);
  tcase_add_test(tc_core, test_oidc_request_jwt_delete_client_pubkey);
  tcase_add_test(tc_core, test_oidc_request_jwt_add_client_jwks_uri);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_client_pubkey_ok);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_client_pubkey_invalid_signature);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_client_pubkey_invalid_kid);
  tcase_add_test(tc_core, test_oidc_request_jwt_delete_client_pubkey);
  tcase_add_test(tc_core, test_oidc_request_jwt_add_client_multiple);
  tcase_add_test(tc_core, test_oidc_request_jwt_response_client_pubkey_test_priority);
  tcase_add_test(tc_core, test_oidc_request_jwt_delete_client_pubkey);
  tcase_add_test(tc_core, test_oidc_request_jwt_delete_module_request_signed);
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
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&scope_req);
  ulfius_clean_request(&register_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

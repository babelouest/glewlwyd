/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <jwt.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define USER_USERNAME "user1"
#define USER2_USERNAME "user2"
#define USER_PASSWORD "password"
#define USER2_PASSWORD "password"
#define PLUGIN_NAME "oidc_claims"
#define SCOPE_LIST "g_profile openid"
#define CLIENT "client1_id"
#define CLIENT_REDIRECT_URI "../../test-oidc.html?param=client1_cb1"
#define RESPONSE_TYPE "id_token token"
#define CLAIM_STR "the-str"
#define CLAIM_NUMBER "42"
#define CLAIM_BOOL_TRUE "1"
#define CLAIM_MANDATORY "I'm aliiiiive!"
#define ADDR_FORMATTED "formatted value"
#define ADDR_STREET_ADDRESS "street_address value"
#define ADDR_LOCALITY "locality value"
#define ADDR_REGION "region value"
#define ADDR_POSTAL_CODE "postal_code value"
#define ADDR_COUNTRY "country value"

struct _u_request admin_req;
struct _u_request user_req, user2_req;

START_TEST(test_oidc_claim_request_add_plugin)
{
  json_t * j_param = json_pack("{sssssss{sssssssssisisisososososososososssss[{sssoss}{sssossss}{sssossssssss}{ssssso}]s{ssssssssssssss}}}",
                                "module",
                                "oidc",
                                "name",
                                PLUGIN_NAME,
                                "display_name",
                                PLUGIN_NAME,
                                "parameters",
                                  "iss",
                                  "https://glewlwyd.tld",
                                  "jwt-type",
                                  "sha",
                                  "jwt-key-size",
                                  "256",
                                  "key",
                                  "secret_" PLUGIN_NAME,
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
                                  "name-claim",
                                  "on-demand",
                                  "email-claim",
                                  "on-demand",
                                  "claims",
                                    "name",
                                    "claim-str",
                                    "on-demand",
                                    json_true(),
                                    "user-property",
                                    "claim-str",
                                    "name",
                                    "claim-number",
                                    "on-demand",
                                    json_true(),
                                    "type",
                                    "number",
                                    "user-property",
                                    "claim-number",
                                    "name",
                                    "claim-bool",
                                    "on-demand",
                                    json_true(),
                                    "type",
                                    "boolean",
                                    "user-property",
                                    "claim-bool",
                                    "boolean-value-true",
                                    "1",
                                    "boolean-value-false",
                                    "0",
                                    "name",
                                    "claim-mandatory",
                                    "user-property",
                                    "claim-mandatory",
                                    "mandatory",
                                    json_true(),
                                  "address-claim",
                                    "type",
                                    "mandatory",
                                    "formatted",
                                    "add-formatted",
                                    "street_address",
                                    "add-street_address",
                                    "locality",
                                    "add-locality",
                                    "region",
                                    "add-region",
                                    "postal_code",
                                    "add-postal_code",
                                    "country",
                                    "add-country");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
  
  j_param = json_pack("{ssssssssssssssssssss}", "claim-str", CLAIM_STR, "claim-number", CLAIM_NUMBER, "claim-bool", CLAIM_BOOL_TRUE, "claim-mandatory", CLAIM_MANDATORY, "add-formatted", ADDR_FORMATTED, "add-street_address", ADDR_STREET_ADDRESS, "add-locality", ADDR_LOCALITY, "add-region", ADDR_REGION, "add-postal_code", ADDR_POSTAL_CODE, "add-country", ADDR_COUNTRY);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USER_USERNAME, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_id_token_no_claim)
{
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0};
  size_t str_payload_len;
  json_t * j_result;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-str"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-number"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), NULL);
  
  free_string_array(id_token_split);
  o_free(id_token);
  json_decref(j_result);
}
END_TEST

START_TEST(test_oidc_claim_request_user2_id_token_no_claim)
{
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0};
  size_t str_payload_len;
  json_t * j_result;
  
  ulfius_init_response(&resp);
  o_free(user2_req.http_url);
  user2_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST);
  o_free(user2_req.http_verb);
  user2_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user2_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-mandatory"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-str"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-number"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "address"), NULL);
  
  free_string_array(id_token_split);
  o_free(id_token);
  json_decref(j_result);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_id_token_claim_invalid)
{
  struct _u_response resp;
  char * claims_str, * claims_str_enc;
  json_t * j_claims;
  
  ulfius_init_response(&resp);
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{so}}", "id_token", "claim-str", json_true())), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_request"), NULL);
  
  ulfius_clean_response(&resp);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_claims);
  
  ulfius_init_response(&resp);
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{si}}}", "id_token", "claim-str", "value", 42)), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_request"), NULL);
  
  ulfius_clean_response(&resp);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_claims);
  
  ulfius_init_response(&resp);
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{ss}}}", "id_token", "claim-str", "value", "")), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_request"), NULL);
  
  ulfius_clean_response(&resp);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_claims);
  
  ulfius_init_response(&resp);
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{s[i]}}}", "id_token", "claim-str", "values", 42)), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_request"), NULL);
  
  ulfius_clean_response(&resp);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_claims);
  
  ulfius_init_response(&resp);
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{s[ss]}}}", "id_token", "claim-str", "values", "plop", "")), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "error=invalid_request"), NULL);
  
  ulfius_clean_response(&resp);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_claims);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_id_token_claim_str_null)
{
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0}, * claims_str, * claims_str_enc;
  size_t str_payload_len;
  json_t * j_result, * j_claims;
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{so}}", "id_token", "claim-str", json_null())), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-str")), CLAIM_STR);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-number"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), NULL);
  
  free_string_array(id_token_split);
  o_free(id_token);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_result);
  json_decref(j_claims);
}
END_TEST

START_TEST(test_oidc_claim_request_user2_id_token_claim_str_null)
{
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0}, * claims_str, * claims_str_enc;
  size_t str_payload_len;
  json_t * j_result, * j_claims;
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{so}}", "id_token", "claim-str", json_null())), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  ulfius_init_response(&resp);
  o_free(user2_req.http_url);
  user2_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user2_req.http_verb);
  user2_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user2_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-mandatory"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-str"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-number"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "address"), NULL);
  
  free_string_array(id_token_split);
  o_free(id_token);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_result);
  json_decref(j_claims);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_id_token_claim_str_value_found)
{
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0}, * claims_str, * claims_str_enc;
  size_t str_payload_len;
  json_t * j_result, * j_claims;
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{ss}}}", "id_token", "claim-str", "value", CLAIM_STR)), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-str")), CLAIM_STR);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-number"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), NULL);
  
  free_string_array(id_token_split);
  o_free(id_token);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_result);
  json_decref(j_claims);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_id_token_claim_str_value_not_found)
{
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0}, * claims_str, * claims_str_enc;
  size_t str_payload_len;
  json_t * j_result, * j_claims;
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{ss}}}", "id_token", "claim-str", "value", CLAIM_STR "error")), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-str"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-number"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), NULL);
  
  free_string_array(id_token_split);
  o_free(id_token);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_result);
  json_decref(j_claims);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_id_token_claim_str_values_found)
{
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0}, * claims_str, * claims_str_enc;
  size_t str_payload_len;
  json_t * j_result, * j_claims;
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{s[sss]}}}", "id_token", "claim-str", "values", "error1", CLAIM_STR, "error2")), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-str")), CLAIM_STR);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-number"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), NULL);
  
  free_string_array(id_token_split);
  o_free(id_token);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_result);
  json_decref(j_claims);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_id_token_claim_str_values_not_found)
{
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0}, * claims_str, * claims_str_enc;
  size_t str_payload_len;
  json_t * j_result, * j_claims;
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{s[sss]}}}", "id_token", "claim-str", "values", "error1", CLAIM_STR "error", "error2")), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-str"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-number"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), NULL);
  
  free_string_array(id_token_split);
  o_free(id_token);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_result);
  json_decref(j_claims);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_id_token_claim_number_value_found)
{
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0}, * claims_str, * claims_str_enc;
  size_t str_payload_len;
  json_t * j_result, * j_claims;
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{ss}}}", "id_token", "claim-number", "value", CLAIM_NUMBER)), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "claim-number")), 42);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-str"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), NULL);
  
  free_string_array(id_token_split);
  o_free(id_token);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_result);
  json_decref(j_claims);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_id_token_claim_number_values_found)
{
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0}, * claims_str, * claims_str_enc;
  size_t str_payload_len;
  json_t * j_result, * j_claims;
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{s[sss]}}}", "id_token", "claim-number", "values", CLAIM_NUMBER, "error1", "error2")), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "claim-number")), 42);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-str"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), NULL);
  
  free_string_array(id_token_split);
  o_free(id_token);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_result);
  json_decref(j_claims);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_id_token_claim_boolean_value_found)
{
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0}, * claims_str, * claims_str_enc;
  size_t str_payload_len;
  json_t * j_result, * j_claims;
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{ss}}}", "id_token", "claim-bool", "value", CLAIM_BOOL_TRUE)), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), json_true());
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-str"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-number"), NULL);
  
  free_string_array(id_token_split);
  o_free(id_token);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_result);
  json_decref(j_claims);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_id_token_claim_boolean_values_found)
{
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0}, * claims_str, * claims_str_enc;
  size_t str_payload_len;
  json_t * j_result, * j_claims;
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{s[sss]}}}", "id_token", "claim-bool", "values", CLAIM_BOOL_TRUE, "error1", "error2")), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), json_true());
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-str"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-number"), NULL);
  
  free_string_array(id_token_split);
  o_free(id_token);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_result);
  json_decref(j_claims);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_id_token_claim_full)
{
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0}, * claims_str, * claims_str_enc;
  size_t str_payload_len;
  json_t * j_result, * j_claims;
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{sososososo}}", "id_token", "claim-str", json_null(), "claim-number", json_null(), "claim-bool", json_null(), "name", json_null(), "email", json_null())), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-str")), CLAIM_STR);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "claim-number")), 42);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), json_true());
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "name")), "Dave Lopper 1");
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "email")), "dev1@glewlwyd");
  
  free_string_array(id_token_split);
  o_free(id_token);
  o_free(claims_str);
  o_free(claims_str_enc);
  json_decref(j_result);
  json_decref(j_claims);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_token_userinfo_claim_str_null)
{
  struct _u_response resp;
  struct _u_request req;
  char * access_token, * claims_str, * claims_str_enc, * bearer;
  json_t * j_result, * j_claims;
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{so}}", "userinfo", "claim-str", json_null())), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  ulfius_init_response(&resp);
  ulfius_init_request(&req);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  access_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "access_token=") + o_strlen("access_token="));
  if (o_strchr(access_token, '&')) {
    *(o_strchr(access_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  bearer = msprintf("Bearer %s", access_token);
  u_map_put(req.map_header, "Authorization", bearer);

  j_result = json_pack("{sssss{ssssssssssss}}", "claim-mandatory", CLAIM_MANDATORY, "claim-str", CLAIM_STR, "address", "formatted", ADDR_FORMATTED, "street_address", ADDR_STREET_ADDRESS, "locality", ADDR_LOCALITY, "country", ADDR_COUNTRY, "postal_code", ADDR_POSTAL_CODE, "region", ADDR_REGION);
  ck_assert_int_eq(run_simple_test(&req, "GET", SERVER_URI "/" PLUGIN_NAME "/userinfo/", NULL, NULL, NULL, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_result);
  
  o_free(claims_str_enc);
  o_free(claims_str);
  o_free(access_token);
  o_free(bearer);
  json_decref(j_claims);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_token_userinfo_claim_full)
{
  struct _u_response resp;
  struct _u_request req;
  char * access_token, * claims_str, * claims_str_enc, * bearer;
  json_t * j_result, * j_claims;
  
  ck_assert_ptr_ne((j_claims = json_pack("{s{sososososo}}", "userinfo", "claim-str", json_null(), "claim-number", json_null(), "claim-bool", json_null(), "name", json_null(), "email", json_null())), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  
  ulfius_init_response(&resp);
  ulfius_init_request(&req);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  access_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "access_token=") + o_strlen("access_token="));
  if (o_strchr(access_token, '&')) {
    *(o_strchr(access_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  bearer = msprintf("Bearer %s", access_token);
  u_map_put(req.map_header, "Authorization", bearer);

  j_result = json_pack("{sssss{ssssssssssss}sisossss}", "claim-mandatory", CLAIM_MANDATORY, "claim-str", CLAIM_STR, "address", "formatted", ADDR_FORMATTED, "street_address", ADDR_STREET_ADDRESS, "locality", ADDR_LOCALITY, "country", ADDR_COUNTRY, "postal_code", ADDR_POSTAL_CODE, "region", ADDR_REGION, "claim-number", 42, "claim-bool", json_true(), "name", "Dave Lopper 1", "email", "dev1@glewlwyd");
  ck_assert_int_eq(run_simple_test(&req, "GET", SERVER_URI "/" PLUGIN_NAME "/userinfo/", NULL, NULL, NULL, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_result);

  o_free(access_token);
  o_free(bearer);
  o_free(claims_str_enc);
  o_free(claims_str);
  json_decref(j_claims);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_code_id_token_userinfo_claim_str_null)
{
  struct _u_response resp;
  struct _u_request req;
  const char * access_token = NULL, * id_token = NULL;
  char * code, * claims_str, * claims_str_enc, ** id_token_split = NULL, str_payload[1024], * bearer = NULL;
  json_t * j_result, * j_claims, * j_body;
  size_t str_payload_len;
  
  ulfius_init_response(&resp);
  ck_assert_ptr_ne((j_claims = json_pack("{s{so}s{so}}", "userinfo", "claim-number", json_null(), "id_token", "claim-str", json_null())), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=code&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code="));
  if (o_strchr(code, '&')) {
    *(o_strchr(code, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = strdup("POST");
  req.http_url = strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "authorization_code");
  u_map_put(req.map_post_body, "client_id", CLIENT);
  u_map_put(req.map_post_body, "redirect_uri", CLIENT_REDIRECT_URI);
  u_map_put(req.map_post_body, "code", code);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_ptr_ne((j_body = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((access_token = json_string_value(json_object_get(j_body, "access_token"))), NULL);
  ck_assert_ptr_ne((id_token = json_string_value(json_object_get(j_body, "id_token"))), NULL);

  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-str")), CLAIM_STR);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-number"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), NULL);
  
  bearer = msprintf("Bearer %s", access_token);
  u_map_put(req.map_header, "Authorization", bearer);

  json_decref(j_result);
  j_result = json_pack("{sssis{ssssssssssss}}", "claim-mandatory", CLAIM_MANDATORY, "claim-number", 42, "address", "formatted", ADDR_FORMATTED, "street_address", ADDR_STREET_ADDRESS, "locality", ADDR_LOCALITY, "country", ADDR_COUNTRY, "postal_code", ADDR_POSTAL_CODE, "region", ADDR_REGION);
  ck_assert_int_eq(run_simple_test(&req, "GET", SERVER_URI "/" PLUGIN_NAME "/userinfo/", NULL, NULL, NULL, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_result);
  
  o_free(bearer);
  o_free(claims_str_enc);
  o_free(claims_str);
  o_free(code);
  json_decref(j_claims);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  free_string_array(id_token_split);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_code_id_token_userinfo_claim_full)
{
  struct _u_response resp;
  struct _u_request req;
  const char * access_token = NULL, * id_token = NULL;
  char * code, * claims_str, * claims_str_enc, ** id_token_split = NULL, str_payload[1024], * bearer = NULL;
  json_t * j_result, * j_claims, * j_body;
  size_t str_payload_len;
  
  ulfius_init_response(&resp);
  ck_assert_ptr_ne((j_claims = json_pack("{s{sososososo}s{sososososo}}", "userinfo", "claim-str", json_null(), "claim-number", json_null(), "claim-bool", json_null(), "name", json_null(), "email", json_null(), "id_token", "claim-str", json_null(), "claim-number", json_null(), "claim-bool", json_null(), "name", json_null(), "email", json_null())), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=code&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code="));
  if (o_strchr(code, '&')) {
    *(o_strchr(code, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = strdup("POST");
  req.http_url = strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "authorization_code");
  u_map_put(req.map_post_body, "client_id", CLIENT);
  u_map_put(req.map_post_body, "redirect_uri", CLIENT_REDIRECT_URI);
  u_map_put(req.map_post_body, "code", code);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_ptr_ne((j_body = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((access_token = json_string_value(json_object_get(j_body, "access_token"))), NULL);
  ck_assert_ptr_ne((id_token = json_string_value(json_object_get(j_body, "id_token"))), NULL);

  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-str")), CLAIM_STR);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "claim-number")), 42);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), json_true());
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "name")), "Dave Lopper 1");
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "email")), "dev1@glewlwyd");
  
  bearer = msprintf("Bearer %s", access_token);
  u_map_put(req.map_header, "Authorization", bearer);

  json_decref(j_result);
  j_result = json_pack("{sssss{ssssssssssss}sisossss}", "claim-mandatory", CLAIM_MANDATORY, "claim-str", CLAIM_STR, "address", "formatted", ADDR_FORMATTED, "street_address", ADDR_STREET_ADDRESS, "locality", ADDR_LOCALITY, "country", ADDR_COUNTRY, "postal_code", ADDR_POSTAL_CODE, "region", ADDR_REGION, "claim-number", 42, "claim-bool", json_true(), "name", "Dave Lopper 1", "email", "dev1@glewlwyd");
  ck_assert_int_eq(run_simple_test(&req, "GET", SERVER_URI "/" PLUGIN_NAME "/userinfo/", NULL, NULL, NULL, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_result);
  
  o_free(bearer);
  o_free(claims_str_enc);
  o_free(claims_str);
  o_free(code);
  json_decref(j_claims);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  free_string_array(id_token_split);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_refresh_token_userinfo_claim_str_null)
{
  struct _u_response resp;
  struct _u_request req;
  const char * access_token = NULL, * refresh_token;
  char * code, * claims_str, * claims_str_enc, * bearer = NULL;
  json_t * j_result, * j_claims, * j_body;
  
  ulfius_init_response(&resp);
  ck_assert_ptr_ne((j_claims = json_pack("{s{so}}", "userinfo", "claim-number", json_null())), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=code&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code="));
  if (o_strchr(code, '&')) {
    *(o_strchr(code, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = strdup("POST");
  req.http_url = strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "authorization_code");
  u_map_put(req.map_post_body, "client_id", CLIENT);
  u_map_put(req.map_post_body, "redirect_uri", CLIENT_REDIRECT_URI);
  u_map_put(req.map_post_body, "code", code);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_ptr_ne((j_body = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((refresh_token = json_string_value(json_object_get(j_body, "refresh_token"))), NULL);
  ulfius_clean_response(&resp);

  u_map_put(req.map_post_body, "grant_type", "refresh_token");
  u_map_put(req.map_post_body, "refresh_token", refresh_token);
  u_map_remove_from_key(req.map_post_body, "client_id");
  u_map_remove_from_key(req.map_post_body, "redirect_uri");
  
  json_decref(j_body);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_ptr_ne((j_body = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((access_token = json_string_value(json_object_get(j_body, "access_token"))), NULL);
  ulfius_clean_response(&resp);

  bearer = msprintf("Bearer %s", access_token);
  u_map_put(req.map_header, "Authorization", bearer);

  j_result = json_pack("{sssis{ssssssssssss}}", "claim-mandatory", CLAIM_MANDATORY, "claim-number", 42, "address", "formatted", ADDR_FORMATTED, "street_address", ADDR_STREET_ADDRESS, "locality", ADDR_LOCALITY, "country", ADDR_COUNTRY, "postal_code", ADDR_POSTAL_CODE, "region", ADDR_REGION);
  ck_assert_int_eq(run_simple_test(&req, "GET", SERVER_URI "/" PLUGIN_NAME "/userinfo/", NULL, NULL, NULL, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_result);
  
  o_free(bearer);
  o_free(code);
  o_free(claims_str_enc);
  o_free(claims_str);
  json_decref(j_claims);
  json_decref(j_body);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_refresh_token_userinfo_claim_full)
{
  struct _u_response resp;
  struct _u_request req;
  const char * access_token = NULL, * refresh_token;
  char * code, * claims_str, * claims_str_enc, * bearer = NULL;
  json_t * j_result, * j_claims, * j_body;
  
  ulfius_init_response(&resp);
  ck_assert_ptr_ne((j_claims = json_pack("{s{sososososo}}", "userinfo", "claim-str", json_null(), "claim-number", json_null(), "claim-bool", json_null(), "name", json_null(), "email", json_null())), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  ck_assert_ptr_ne((claims_str_enc = ulfius_url_encode(claims_str)), NULL);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=code&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s&claims=%s", SERVER_URI, PLUGIN_NAME, CLIENT, CLIENT_REDIRECT_URI, SCOPE_LIST, claims_str_enc);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code="));
  if (o_strchr(code, '&')) {
    *(o_strchr(code, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  req.http_verb = strdup("POST");
  req.http_url = strdup(SERVER_URI "/" PLUGIN_NAME "/token");
  u_map_put(req.map_post_body, "grant_type", "authorization_code");
  u_map_put(req.map_post_body, "client_id", CLIENT);
  u_map_put(req.map_post_body, "redirect_uri", CLIENT_REDIRECT_URI);
  u_map_put(req.map_post_body, "code", code);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_ptr_ne((j_body = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((refresh_token = json_string_value(json_object_get(j_body, "refresh_token"))), NULL);
  ulfius_clean_response(&resp);

  u_map_put(req.map_post_body, "grant_type", "refresh_token");
  u_map_put(req.map_post_body, "refresh_token", refresh_token);
  u_map_remove_from_key(req.map_post_body, "client_id");
  u_map_remove_from_key(req.map_post_body, "redirect_uri");
  
  json_decref(j_body);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_ptr_ne((j_body = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((access_token = json_string_value(json_object_get(j_body, "access_token"))), NULL);
  ulfius_clean_response(&resp);

  bearer = msprintf("Bearer %s", access_token);
  u_map_put(req.map_header, "Authorization", bearer);

  j_result = json_pack("{sssss{ssssssssssss}sisossss}", "claim-mandatory", CLAIM_MANDATORY, "claim-str", CLAIM_STR, "address", "formatted", ADDR_FORMATTED, "street_address", ADDR_STREET_ADDRESS, "locality", ADDR_LOCALITY, "country", ADDR_COUNTRY, "postal_code", ADDR_POSTAL_CODE, "region", ADDR_REGION, "claim-number", 42, "claim-bool", json_true(), "name", "Dave Lopper 1", "email", "dev1@glewlwyd");
  ck_assert_int_eq(run_simple_test(&req, "GET", SERVER_URI "/" PLUGIN_NAME "/userinfo/", NULL, NULL, NULL, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_result);
  
  o_free(bearer);
  o_free(claims_str_enc);
  o_free(code);
  o_free(claims_str);
  json_decref(j_claims);
  json_decref(j_body);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_request_jwt_id_token_claim_str_null)
{
  jwt_t * jwt_request = NULL;
  char * request;
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0}, * claims_str;
  size_t str_payload_len;
  json_t * j_result, * j_claims;
  
  jwt_new(&jwt_request);
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_NONE, NULL, 0), 0);
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{so}}}", "claims", "id_token", "claim-number", json_null())), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  jwt_add_grants_json(jwt_request, claims_str);
  jwt_add_grant(jwt_request, "aud", CLIENT_REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", "id_token");
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", CLIENT_REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_verb);
  o_free(user_req.http_url);
  user_req.http_verb = o_strdup("GET");
  user_req.http_url = msprintf("%s/%s/auth?g_continue&request=%s", SERVER_URI, PLUGIN_NAME, request);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "claim-number")), 42);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-str"), NULL);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), NULL);
  
  o_free(request);
  o_free(id_token);
  o_free(claims_str);
  json_decref(j_result);
  json_decref(j_claims);
  jwt_free(jwt_request);
  free_string_array(id_token_split);
}
END_TEST

START_TEST(test_oidc_claim_request_user1_request_jwt_id_token_claim_full)
{
  jwt_t * jwt_request = NULL;
  char * request;
  struct _u_response resp;
  char * id_token, ** id_token_split, str_payload[1024] = {0}, * claims_str;
  size_t str_payload_len;
  json_t * j_result, * j_claims;
  
  jwt_new(&jwt_request);
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(jwt_set_alg(jwt_request, JWT_ALG_NONE, NULL, 0), 0);
  ck_assert_ptr_ne((j_claims = json_pack("{s{s{sososososo}}}", "claims", "id_token", "claim-str", json_null(), "claim-number", json_null(), "claim-bool", json_null(), "name", json_null(), "email", json_null())), NULL);
  ck_assert_ptr_ne((claims_str = json_dumps(j_claims, JSON_COMPACT)), NULL);
  jwt_add_grants_json(jwt_request, claims_str);
  jwt_add_grant(jwt_request, "aud", CLIENT_REDIRECT_URI);
  jwt_add_grant(jwt_request, "response_type", "id_token");
  jwt_add_grant(jwt_request, "client_id", CLIENT);
  jwt_add_grant(jwt_request, "redirect_uri", CLIENT_REDIRECT_URI);
  jwt_add_grant(jwt_request, "scope", SCOPE_LIST);
  jwt_add_grant(jwt_request, "state", "xyzabcd");
  jwt_add_grant(jwt_request, "nonce", "nonce1234");
  request = jwt_encode_str(jwt_request);
  ck_assert_ptr_ne(request, NULL);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_verb);
  o_free(user_req.http_url);
  user_req.http_verb = o_strdup("GET");
  user_req.http_url = msprintf("%s/%s/auth?g_continue&request=%s", SERVER_URI, PLUGIN_NAME, request);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *(o_strchr(id_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(split_string(id_token, ".", &id_token_split), 3);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)id_token_split[1], o_strlen(id_token_split[1]), (unsigned char *)str_payload, &str_payload_len), 1);
  ck_assert_ptr_ne((j_result = json_loads(str_payload, JSON_DECODE_ANY, NULL)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-mandatory")), CLAIM_MANDATORY);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "claim-str")), CLAIM_STR);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "claim-number")), 42);
  ck_assert_ptr_eq(json_object_get(j_result, "claim-bool"), json_true());
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "formatted")), ADDR_FORMATTED);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "street_address")), ADDR_STREET_ADDRESS);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "locality")), ADDR_LOCALITY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "country")), ADDR_COUNTRY);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "postal_code")), ADDR_POSTAL_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(json_object_get(j_result, "address"), "region")), ADDR_REGION);
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "name")), "Dave Lopper 1");
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "email")), "dev1@glewlwyd");
  
  o_free(request);
  o_free(id_token);
  o_free(claims_str);
  json_decref(j_result);
  json_decref(j_claims);
  jwt_free(jwt_request);
  free_string_array(id_token_split);
}
END_TEST

START_TEST(test_oidc_claim_request_delete_plugin)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  json_t * j_param = json_pack("{sosososososososososo}", "claim-str", json_null(), "claim-number", json_null(), "claim-bool", json_null(), "claim-mandatory", json_null(), "add-formatted", json_null(), "add-street_address", json_null(), "add-locality", json_null(), "add-region", json_null(), "add-postal_code", json_null(), "add-country", json_null());
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USER_USERNAME, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd profile");
  tc_core = tcase_create("test_oidc_claim_request");
  tcase_add_test(tc_core, test_oidc_claim_request_add_plugin);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_id_token_no_claim);
  tcase_add_test(tc_core, test_oidc_claim_request_user2_id_token_no_claim);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_id_token_claim_invalid);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_id_token_claim_str_null);
  tcase_add_test(tc_core, test_oidc_claim_request_user2_id_token_claim_str_null);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_id_token_claim_str_value_found);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_id_token_claim_str_value_not_found);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_id_token_claim_str_values_found);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_id_token_claim_str_values_not_found);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_id_token_claim_number_value_found);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_id_token_claim_number_values_found);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_id_token_claim_boolean_value_found);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_id_token_claim_boolean_values_found);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_id_token_claim_full);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_token_userinfo_claim_str_null);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_token_userinfo_claim_full);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_code_id_token_userinfo_claim_str_null);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_code_id_token_userinfo_claim_full);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_refresh_token_userinfo_claim_str_null);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_refresh_token_userinfo_claim_full);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_request_jwt_id_token_claim_str_null);
  tcase_add_test(tc_core, test_oidc_claim_request_user1_request_jwt_id_token_claim_full);
  tcase_add_test(tc_core, test_oidc_claim_request_delete_plugin);
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
  ulfius_init_request(&user2_req);

  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
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
    ulfius_init_request(&scope_req);
    ulfius_init_response(&scope_resp);
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
        scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
        j_body = json_pack("{ss}", "scope", SCOPE_LIST);
        ulfius_set_json_body_request(&scope_req, j_body);
        json_decref(j_body);
        if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK || scope_resp.status != 200) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
          do_test = 0;
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope OK");
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication user");
      do_test = 0;
    }
    ulfius_clean_response(&auth_resp);
    ulfius_clean_request(&auth_req);
    ulfius_clean_response(&scope_resp);
    ulfius_clean_request(&scope_req);
  }
  
  if (do_test) {
    // Getting a valid session id for authenticated http requests
    ulfius_init_request(&auth_req);
    ulfius_init_response(&auth_resp);
    ulfius_init_request(&scope_req);
    ulfius_init_response(&scope_resp);
    auth_req.http_verb = strdup("POST");
    auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
    j_body = json_pack("{ssss}", "username", USER2_USERNAME, "password", USER2_PASSWORD);
    ulfius_set_json_body_request(&auth_req, j_body);
    json_decref(j_body);
    res = ulfius_send_http_request(&auth_req, &auth_resp);
    if (res == U_OK && auth_resp.status == 200) {
      if (auth_resp.nb_cookies) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "User %s authenticated", USER2_USERNAME);
        cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
        u_map_put(scope_req.map_header, "Cookie", cookie);
        u_map_put(user2_req.map_header, "Cookie", cookie);
        o_free(cookie);

        scope_req.http_verb = strdup("PUT");
        scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
        j_body = json_pack("{ss}", "scope", SCOPE_LIST);
        ulfius_set_json_body_request(&scope_req, j_body);
        json_decref(j_body);
        if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK || scope_resp.status != 200) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
          do_test = 0;
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope OK");
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication user");
      do_test = 0;
    }
    ulfius_clean_response(&auth_resp);
    ulfius_clean_request(&auth_req);
    ulfius_clean_response(&scope_resp);
    ulfius_clean_request(&scope_req);
  }
  
  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  char * url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  j_body = json_pack("{ss}", "scope", "");
  run_simple_test(&user_req, "PUT", url, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
  run_simple_test(&user2_req, "PUT", url, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
  o_free(url);
  json_decref(j_body);
  
  url = msprintf("%s/auth/", SERVER_URI);
  run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  o_free(url);
  
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&user2_req);
  ulfius_clean_request(&scope_req);
  y_close_logs();
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

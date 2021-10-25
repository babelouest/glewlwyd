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
#define SCOPE_LIST "openid"
#define NONCE_TEST "nonce5678"
#define STATE_TEST "abcxyz"

#define PLUGIN_MODULE "oidc"
#define PLUGIN_NAME "oidc_session"
#define PLUGIN_DISPLAY_NAME "oidc with session management"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_ACCESS_TOKEN_DURATION 3600
#define PLUGIN_COOKIE_NAME "GLEWLWYD2_OIDC_SID"
#define PLUGIN_COOKIE_EXPIRATION 2419200
#define CB_KEY "cert/server.key"
#define CB_CRT "cert/server.crt"

#define CLIENT_ID "client_session"
#define CLIENT_ID_1 "client_session_1"
#define CLIENT_ID_2 "client_session_2"
#define CLIENT_ID_3 "client_session_3"
#define CLIENT_ID_4 "client_session_4"
#define CLIENT_NAME "client with session"
#define CLIENT_SECRET "secret with session"
#define CLIENT_ORIGIN "https://client.local"
#define CLIENT_REDIRECT "https://client.local/redirect"
#define CLIENT_REDIRECT_ENC "https%3A%2F%2Fclient.local%2Fredirect"
#define CLIENT_REDIRECT_POST_LOGOUT "https://client.local/logout"
#define CLIENT_REDIRECT_POST_LOGOUT_ENC "https%3A%2F%2Fclient.local%2Flogout"
#define CLIENT_ANOTHER_REDIRECT_POST_LOGOUT "https://anotherclient.local/logout"
#define CLIENT_ANOTHER_REDIRECT_POST_LOGOUT_ENC "https%3A%2F%2Fanotherclient.local%2Flogout"
#define CLIENT_FRONTCHANNEL_LOGOUT "https://localhost:5468/frontLogout?1"
#define CLIENT_FRONTCHANNEL_LOGOUT_2 "https://localhost:5468/frontLogout?2"
#define CLIENT_BACKCHANNEL_LOGOUT "https://localhost:5468/backLogout/1"
#define CLIENT_BACKCHANNEL_LOGOUT_2 "https://localhost:5468/backLogout/2"
#define STATE "stateXyzabcd123"

struct _u_request admin_req;
struct _u_request user_req;
char * cookie_key, * cookie_value;
int counter;

static pthread_mutex_t log_lock;
static pthread_cond_t  log_cond;

json_t * init_session(const char * client_id, char * sid) {
  struct _u_request req;
  struct _u_response resp;
  char * url, * code;
  json_t * j_response, * j_body;
  jwt_t * jwt;

  url = msprintf(SERVER_URI "/auth/grant/%s", client_id);
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", url, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=id_token+code&g_continue&client_id=",
                                                       U_OPT_HTTP_URL_APPEND, client_id,
                                                       U_OPT_HTTP_URL_APPEND, "&redirect_uri=" CLIENT_REDIRECT_ENC "&state="STATE"&nonce=nonce123456&scope=" SCOPE_LIST,
                                                       U_OPT_COOKIE_PARAMETER, cookie_key, cookie_value,
                                                       U_OPT_NONE), U_OK);
  if (o_strlen(sid)) {
    u_map_put(req.map_cookie, PLUGIN_COOKIE_NAME, sid);
  }
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                U_OPT_POST_BODY_PARAMETER, "client_id", client_id,
                                                U_OPT_POST_BODY_PARAMETER, "client_secret", CLIENT_SECRET,
                                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                                U_OPT_POST_BODY_PARAMETER, "code", code,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, jwt = r_jwt_quick_parse(json_string_value(json_object_get(j_response, "id_token")), R_PARSE_NONE, 0));
  ck_assert_ptr_ne(NULL, r_jwt_get_claim_str_value(jwt, "sid"));
  if (o_strlen(sid) != o_strlen(r_jwt_get_claim_str_value(jwt, "sid"))) {
    o_strcpy(sid, r_jwt_get_claim_str_value(jwt, "sid"));
  } else {
    ck_assert_str_eq(sid, r_jwt_get_claim_str_value(jwt, "sid"));
  }
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);

  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", url, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  o_free(url);
  o_free(code);

  return j_response;
}

static int callback_backlogout(const struct _u_request * request, struct _u_response * response, void * user_data) {
  jwt_t * jwt = r_jwt_quick_parse(u_map_get(request->map_post_body, "logout_token"), R_PARSE_NONE, 0);
  
  ck_assert_ptr_ne(NULL, jwt);
  ck_assert_int_eq(R_JWA_ALG_HS256, r_jwt_get_sign_alg(jwt));
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, PLUGIN_ISS,
                                              R_JWT_CLAIM_AUD, *u_map_get(request->map_url, "id")=='1'?CLIENT_ID_3:CLIENT_ID_4,
                                              R_JWT_CLAIM_SUB, NULL,
                                              R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_JTI, NULL,
                                              R_JWT_CLAIM_NOP), RHN_OK);
  if (*u_map_get(request->map_url, "id")=='1') {
    ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_STR, "sid", (const char *)user_data, R_JWT_CLAIM_NOP), RHN_OK);
  }
  counter++;
  r_jwt_free(jwt);
  pthread_mutex_lock(&log_lock);
  pthread_cond_signal(&log_cond);
  pthread_mutex_unlock(&log_lock);
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_oidc_session_management_add_module_ok)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisososososososososososososssisoso}}",
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
                                  "request-parameter-allow", json_true(),
                                  "request-uri-allow-https-non-secure", json_true(),
                                  "introspection-revocation-allowed", json_true(),
                                  "introspection-revocation-allow-target-client", json_true(),
                                  "session-management-allowed", json_true(),
                                  "session-cookie-name", PLUGIN_COOKIE_NAME,
                                  "session-cookie-expiration", PLUGIN_COOKIE_EXPIRATION,
                                  "front-channel-logout-allowed", json_true(),
                                  "back-channel-logout-allowed", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_session_management_add_client_ok)
{
  json_t * j_parameters = json_pack("{sssss[s]s[s]s[sss]so}",
                                "client_id", CLIENT_ID,
                                "clint_name", CLIENT_NAME,
                                "redirect_uri", CLIENT_REDIRECT,
                                "post_logout_redirect_uris", CLIENT_REDIRECT_POST_LOGOUT,
                                "authorization_type", "code", "token", "id_token",
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_session_management_add_client_channel_ok)
{
  json_t * j_parameters = json_pack("{sssss[s]s[s]s[sss]sssssssoso}",
                                    "client_id", CLIENT_ID_1,
                                    "clint_name", CLIENT_NAME,
                                    "redirect_uri", CLIENT_REDIRECT,
                                    "post_logout_redirect_uris", CLIENT_REDIRECT_POST_LOGOUT,
                                    "authorization_type", "code", "token", "id_token",
                                    "frontchannel_logout_uri", CLIENT_FRONTCHANNEL_LOGOUT,
                                    "frontchannel_logout_session_required", "true",
                                    "client_secret", CLIENT_SECRET,
                                    "enabled", json_true(),
                                    "confidential", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  j_parameters = json_pack("{sssss[s]s[s]s[sss]sssssssoso}",
                            "client_id", CLIENT_ID_2,
                            "clint_name", CLIENT_NAME,
                            "redirect_uri", CLIENT_REDIRECT,
                            "post_logout_redirect_uris", CLIENT_REDIRECT_POST_LOGOUT,
                            "authorization_type", "code", "token", "id_token",
                            "frontchannel_logout_uri", CLIENT_FRONTCHANNEL_LOGOUT_2,
                            "frontchannel_logout_session_required", "false",
                            "client_secret", CLIENT_SECRET,
                            "enabled", json_true(),
                            "confidential", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  j_parameters = json_pack("{sssss[s]s[s]s[sss]sssssssoso}",
                            "client_id", CLIENT_ID_3,
                            "clint_name", CLIENT_NAME,
                            "redirect_uri", CLIENT_REDIRECT,
                            "post_logout_redirect_uris", CLIENT_REDIRECT_POST_LOGOUT,
                            "authorization_type", "code", "token", "id_token",
                            "backchannel_logout_uri", CLIENT_BACKCHANNEL_LOGOUT,
                            "backchannel_logout_session_required", "true",
                            "client_secret", CLIENT_SECRET,
                            "enabled", json_true(),
                            "confidential", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  j_parameters = json_pack("{sssss[s]s[s]s[sss]sssssssoso}",
                            "client_id", CLIENT_ID_4,
                            "clint_name", CLIENT_NAME,
                            "redirect_uri", CLIENT_REDIRECT,
                            "post_logout_redirect_uris", CLIENT_REDIRECT_POST_LOGOUT,
                            "authorization_type", "code", "token", "id_token",
                            "backchannel_logout_uri", CLIENT_BACKCHANNEL_LOGOUT_2,
                            "backchannel_logout_session_required", "false",
                            "client_secret", CLIENT_SECRET,
                            "enabled", json_true(),
                            "confidential", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_session_management_delete_module)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_session_management_delete_client)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_session_management_delete_client_channel)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID_1, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID_2, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID_3, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID_4, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_session_management_session_state)
{
  struct _u_request auth_req;
  struct _u_response auth_resp, resp;
  json_t * j_body;
  char * cookie;
  char * session_state, * session_state_dec, * salt, * intermediate;
  unsigned char hash[32] = {0}, hash_b64[128] = {0};
  size_t hash_len = 32, hash_b64_len = 0;
  gnutls_datum_t data;
  
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
  
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  o_free(auth_req.http_verb);
  o_free(auth_req.http_url);
  auth_req.http_url = msprintf("%s/%s/auth?response_type=id_token%%20code&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonceAbcXyz&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  auth_req.http_verb = o_strdup("GET");
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&auth_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(NULL, o_strstr(u_map_get(resp.map_header, "Location"), "session_state="));
  session_state = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "session_state=")+strlen("session_state="));
  if (strchr(session_state, '&') != NULL) {
    *strchr(session_state, '&') = '\0';
  }
  session_state_dec = ulfius_url_decode(session_state);
  salt = o_strstr(session_state, ".")+1;
  ck_assert_ptr_ne(NULL, salt);
  intermediate = msprintf("%s %s %s %s", CLIENT_ID, CLIENT_ORIGIN, USERNAME, salt);
  data.data = (unsigned char *)intermediate;
  data.size = o_strlen(intermediate);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_DIG_SHA256, &data, hash, &hash_len), GNUTLS_E_SUCCESS);
  ck_assert_int_eq(o_base64_encode(hash, hash_len, hash_b64, &hash_b64_len), 1);
  hash_b64[hash_b64_len] = '\0';
  ck_assert_int_eq(0, o_strncmp((const char *)hash_b64, session_state_dec, hash_b64_len));
  
  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&auth_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ck_assert_int_eq(run_simple_test(&auth_req, "GET", SERVER_URI "/" PLUGIN_NAME "/check_session_iframe/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  
  ulfius_clean_response(&resp);
  ulfius_clean_request(&auth_req);
  o_free(cookie);
  o_free(session_state);
  o_free(session_state_dec);
  o_free(intermediate);
}
END_TEST

START_TEST(test_oidc_session_management_end_session_no_post_logout)
{
  struct _u_request req;
  struct _u_response resp;
  char * id_token;
  json_t * j_body;
  
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&state="STATE"&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=")+strlen("id_token="));
  if (strchr(id_token, '&') != NULL) {
    *strchr(id_token, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  o_free(req.http_verb);
  o_free(req.http_url);
  req.http_verb = o_strdup("GET");
  req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/end_session?state="STATE"&id_token_hint=%s", id_token);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), STATE));
  
  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(id_token);
}
END_TEST

START_TEST(test_oidc_session_management_end_session_invalid_post_logout)
{
  struct _u_request req;
  struct _u_response resp;
  char * id_token;
  json_t * j_body;
  
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&state=stateXyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=")+strlen("id_token="));
  if (strchr(id_token, '&') != NULL) {
    *strchr(id_token, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  o_free(req.http_verb);
  o_free(req.http_url);
  req.http_verb = o_strdup("GET");
  req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/end_session?state=stateXyz&post_logout_redirect_uri=%s&id_token_hint=%s", CLIENT_ANOTHER_REDIRECT_POST_LOGOUT_ENC, id_token);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), "stateXyzabcd"));
  ck_assert_ptr_eq(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), CLIENT_ANOTHER_REDIRECT_POST_LOGOUT));
  
  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(id_token);
}
END_TEST

START_TEST(test_oidc_session_management_end_session_valid_post_logout)
{
  struct _u_request req;
  struct _u_response resp;
  char * id_token;
  json_t * j_body;
  
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&state=stateXyzabcd&nonce=nonce123456&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=")+strlen("id_token="));
  if (strchr(id_token, '&') != NULL) {
    *strchr(id_token, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  o_free(req.http_verb);
  o_free(req.http_url);
  req.http_verb = o_strdup("GET");
  req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/end_session?state="STATE"&post_logout_redirect_uri=%s&id_token_hint=%s", CLIENT_REDIRECT_POST_LOGOUT_ENC, id_token);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), STATE));
  ck_assert_ptr_ne(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC));
  
  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(id_token);
}
END_TEST

START_TEST(test_oidc_session_management_end_session_no_state)
{
  struct _u_request req;
  struct _u_response resp;
  char * id_token;
  json_t * j_body;
  
  j_body = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234567&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=")+strlen("id_token="));
  if (strchr(id_token, '&') != NULL) {
    *strchr(id_token, '&') = '\0';
  }
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  o_free(req.http_verb);
  o_free(req.http_url);
  req.http_verb = o_strdup("GET");
  req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/end_session?post_logout_redirect_uri=%s&id_token_hint=%s", CLIENT_REDIRECT_POST_LOGOUT_ENC, id_token);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), "state="));
  ck_assert_ptr_ne(NULL, o_strcasestr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC));
  
  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(id_token);
}
END_TEST

START_TEST(test_oidc_session_management_valid_sid)
{
  char sid[64] = {0};
  json_t * j_result_1, * j_result_2, * j_result_3, * j_result_4;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  j_result_2 = init_session(CLIENT_ID_2, sid);
  j_result_3 = init_session(CLIENT_ID_3, sid);
  j_result_4 = init_session(CLIENT_ID_4, sid);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
  json_decref(j_result_3);
  json_decref(j_result_4);
}
END_TEST

START_TEST(test_oidc_session_management_invalid_sid)
{
  char sid[64] = {0}, sid_2[64] = {0};
  json_t * j_result_1, * j_result_2;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  o_strncpy(sid_2, sid, o_strlen(sid_2)/2);
  j_result_2 = init_session(CLIENT_ID_2, sid_2);
  ck_assert_int_eq(o_strlen(sid), o_strlen(sid_2));
  ck_assert_str_ne(sid, sid_2);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
}
END_TEST

START_TEST(test_oidc_session_management_valid_new_sid)
{
  char sid[64] = {0}, sid_2[64] = {0};
  json_t * j_result_1, * j_result_2, * j_result_3, * j_result_4;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  j_result_2 = init_session(CLIENT_ID_2, sid);
  j_result_3 = init_session(CLIENT_ID_3, sid_2);
  j_result_4 = init_session(CLIENT_ID_4, sid_2);
  
  ck_assert_str_ne(sid, sid_2);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
  json_decref(j_result_3);
  json_decref(j_result_4);
}
END_TEST

START_TEST(test_oidc_session_management_end_session_id_token_post_redirect_state_ok)
{
  char sid[64] = {0};
  json_t * j_result_1;
  struct _u_request req;
  struct _u_response resp;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_HTTP_URL_APPEND, "&post_logout_redirect_uri=" CLIENT_REDIRECT_POST_LOGOUT_ENC,
                                                       U_OPT_HTTP_URL_APPEND, "&state=" STATE,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_1), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_result_1);
}
END_TEST

START_TEST(test_oidc_session_management_end_session_id_token_post_redirect_ok)
{
  char sid[64] = {0};
  json_t * j_result_1;
  struct _u_request req;
  struct _u_response resp;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_HTTP_URL_APPEND, "&post_logout_redirect_uri=" CLIENT_REDIRECT_POST_LOGOUT_ENC,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_1), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_result_1);
}
END_TEST

START_TEST(test_oidc_session_management_end_session_id_token_post_redirect_invalid_state_ok)
{
  char sid[64] = {0};
  json_t * j_result_1;
  struct _u_request req;
  struct _u_response resp;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_HTTP_URL_APPEND, "&post_logout_redirect_uri=" CLIENT_REDIRECT_POST_LOGOUT_ENC "/error",
                                                       U_OPT_HTTP_URL_APPEND, "&state=" STATE,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_1), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_result_1);
}
END_TEST

START_TEST(test_oidc_session_management_end_session_id_token_invalid)
{
  char sid[64] = {0};
  json_t * j_result_1;
  struct _u_request req;
  struct _u_response resp;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, "error",
                                                       U_OPT_HTTP_URL_APPEND, "&post_logout_redirect_uri=" CLIENT_REDIRECT_POST_LOGOUT_ENC,
                                                       U_OPT_HTTP_URL_APPEND, "&state=" STATE,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_1), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=single_logout"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_result_1);
}
END_TEST

START_TEST(test_oidc_session_management_get_session_list_post_redirect_state_ok)
{
  char sid[64] = {0};
  json_t * j_result_1, * j_result_2, * j_result_list;
  struct _u_request req;
  struct _u_response resp;
  size_t i;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  j_result_2 = init_session(CLIENT_ID_2, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_HTTP_URL_APPEND, "&post_logout_redirect_uri=" CLIENT_REDIRECT_POST_LOGOUT_ENC,
                                                       U_OPT_HTTP_URL_APPEND, "&state=" STATE,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_1), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "callback_url="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/session/",
                                                       U_OPT_HTTP_URL_APPEND, sid,
                                                       U_OPT_HTTP_URL_APPEND, "/" CLIENT_ID_1,
                                                       U_OPT_HTTP_URL_APPEND, "?post_redirect_to=" CLIENT_REDIRECT_POST_LOGOUT_ENC,
                                                       U_OPT_COOKIE_PARAMETER, cookie_key, cookie_value,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result_list = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq(sid, json_string_value(json_object_get(j_result_list, "sid")));
  ck_assert_str_eq(CLIENT_ID_1, json_string_value(json_object_get(j_result_list, "client_id")));
  ck_assert_str_eq(CLIENT_REDIRECT_POST_LOGOUT, json_string_value(json_object_get(j_result_list, "post_redirect_to")));
  ck_assert_int_eq(2, json_array_size(json_object_get(j_result_list, "client")));
  for (i=0; i<2; i++) {
    if (0 == o_strcmp(CLIENT_ID_1, json_string_value(json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "client_id")))) {
      ck_assert_str_eq(CLIENT_FRONTCHANNEL_LOGOUT, json_string_value(json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "frontchannel_logout_uri")));
      ck_assert_ptr_eq(json_true(), json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "frontchannel_logout_session_required"));
    } else if (0 == o_strcmp(CLIENT_ID_2, json_string_value(json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "client_id")))) {
      ck_assert_str_eq(CLIENT_FRONTCHANNEL_LOGOUT_2, json_string_value(json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "frontchannel_logout_uri")));
      ck_assert_ptr_eq(json_false(), json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "frontchannel_logout_session_required"));
    } else {
      // This should not happen
      ck_assert_int_eq(0, 1);
    }
  }
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
  json_decref(j_result_list);
}
END_TEST

START_TEST(test_oidc_session_management_get_session_list_post_redirect_ok)
{
  char sid[64] = {0};
  json_t * j_result_1, * j_result_2, * j_result_list;
  struct _u_request req;
  struct _u_response resp;
  size_t i;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  j_result_2 = init_session(CLIENT_ID_2, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_HTTP_URL_APPEND, "&post_logout_redirect_uri=" CLIENT_REDIRECT_POST_LOGOUT_ENC,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_1), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "callback_url="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/session/",
                                                       U_OPT_HTTP_URL_APPEND, sid,
                                                       U_OPT_HTTP_URL_APPEND, "/" CLIENT_ID_1,
                                                       U_OPT_HTTP_URL_APPEND, "?post_redirect_to=" CLIENT_REDIRECT_POST_LOGOUT_ENC,
                                                       U_OPT_COOKIE_PARAMETER, cookie_key, cookie_value,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result_list = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq(sid, json_string_value(json_object_get(j_result_list, "sid")));
  ck_assert_str_eq(CLIENT_ID_1, json_string_value(json_object_get(j_result_list, "client_id")));
  ck_assert_str_eq(CLIENT_REDIRECT_POST_LOGOUT, json_string_value(json_object_get(j_result_list, "post_redirect_to")));
  ck_assert_int_eq(2, json_array_size(json_object_get(j_result_list, "client")));
  for (i=0; i<2; i++) {
    if (0 == o_strcmp(CLIENT_ID_1, json_string_value(json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "client_id")))) {
      ck_assert_str_eq(CLIENT_FRONTCHANNEL_LOGOUT, json_string_value(json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "frontchannel_logout_uri")));
      ck_assert_ptr_eq(json_true(), json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "frontchannel_logout_session_required"));
    } else if (0 == o_strcmp(CLIENT_ID_2, json_string_value(json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "client_id")))) {
      ck_assert_str_eq(CLIENT_FRONTCHANNEL_LOGOUT_2, json_string_value(json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "frontchannel_logout_uri")));
      ck_assert_ptr_eq(json_false(), json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "frontchannel_logout_session_required"));
    } else {
      // This should not happen
      ck_assert_int_eq(0, 1);
    }
  }
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
  json_decref(j_result_list);
}
END_TEST

START_TEST(test_oidc_session_management_get_session_list_ok)
{
  char sid[64] = {0};
  json_t * j_result_1, * j_result_2, * j_result_list;
  struct _u_request req;
  struct _u_response resp;
  size_t i;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  j_result_2 = init_session(CLIENT_ID_2, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_1), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "callback_url="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/session/",
                                                       U_OPT_HTTP_URL_APPEND, sid,
                                                       U_OPT_HTTP_URL_APPEND, "/" CLIENT_ID_1,
                                                       U_OPT_COOKIE_PARAMETER, cookie_key, cookie_value,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result_list = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq(sid, json_string_value(json_object_get(j_result_list, "sid")));
  ck_assert_str_eq(CLIENT_ID_1, json_string_value(json_object_get(j_result_list, "client_id")));
  ck_assert_ptr_eq(NULL, json_string_value(json_object_get(j_result_list, "post_redirect_to")));
  ck_assert_int_eq(2, json_array_size(json_object_get(j_result_list, "client")));
  for (i=0; i<2; i++) {
    if (0 == o_strcmp(CLIENT_ID_1, json_string_value(json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "client_id")))) {
      ck_assert_str_eq(CLIENT_FRONTCHANNEL_LOGOUT, json_string_value(json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "frontchannel_logout_uri")));
      ck_assert_ptr_eq(json_true(), json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "frontchannel_logout_session_required"));
    } else if (0 == o_strcmp(CLIENT_ID_2, json_string_value(json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "client_id")))) {
      ck_assert_str_eq(CLIENT_FRONTCHANNEL_LOGOUT_2, json_string_value(json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "frontchannel_logout_uri")));
      ck_assert_ptr_eq(json_false(), json_object_get(json_array_get(json_object_get(j_result_list, "client"), i), "frontchannel_logout_session_required"));
    } else {
      // This should not happen
      ck_assert_int_eq(0, 1);
    }
  }
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
  json_decref(j_result_list);
}
END_TEST

START_TEST(test_oidc_session_management_get_session_list_sid_invalid)
{
  char sid[64] = {0};
  json_t * j_result_1, * j_result_2;
  struct _u_request req;
  struct _u_response resp;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  j_result_2 = init_session(CLIENT_ID_2, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_HTTP_URL_APPEND, "&post_logout_redirect_uri=" CLIENT_REDIRECT_POST_LOGOUT_ENC,
                                                       U_OPT_HTTP_URL_APPEND, "&state=" STATE,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_1), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "callback_url="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/session/",
                                                       U_OPT_HTTP_URL_APPEND, "error",
                                                       U_OPT_HTTP_URL_APPEND, "/" CLIENT_ID_1,
                                                       U_OPT_HTTP_URL_APPEND, "?post_redirect_to=" CLIENT_REDIRECT_POST_LOGOUT_ENC,
                                                       U_OPT_COOKIE_PARAMETER, cookie_key, cookie_value,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
}
END_TEST

START_TEST(test_oidc_session_management_get_session_list_client_id_invalid)
{
  char sid[64] = {0};
  json_t * j_result_1, * j_result_2;
  struct _u_request req;
  struct _u_response resp;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  j_result_2 = init_session(CLIENT_ID_2, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_HTTP_URL_APPEND, "&post_logout_redirect_uri=" CLIENT_REDIRECT_POST_LOGOUT_ENC,
                                                       U_OPT_HTTP_URL_APPEND, "&state=" STATE,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_1), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "callback_url="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/session/",
                                                       U_OPT_HTTP_URL_APPEND, sid,
                                                       U_OPT_HTTP_URL_APPEND, "/" "error",
                                                       U_OPT_HTTP_URL_APPEND, "?post_redirect_to=" CLIENT_REDIRECT_POST_LOGOUT_ENC,
                                                       U_OPT_COOKIE_PARAMETER, cookie_key, cookie_value,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
}
END_TEST

START_TEST(test_oidc_session_management_get_session_list_invalid_user)
{
  char sid[64] = {0};
  json_t * j_result_1, * j_result_2;
  struct _u_request req;
  struct _u_response resp;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  j_result_2 = init_session(CLIENT_ID_2, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_1), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "callback_url="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/session/",
                                                       U_OPT_HTTP_URL_APPEND, sid,
                                                       U_OPT_HTTP_URL_APPEND, "/" CLIENT_ID_1,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
}
END_TEST

START_TEST(test_oidc_session_management_delete_session_frontchannel_ok)
{
  char sid[64] = {0};
  json_t * j_result_1, * j_result_2, * j_resp;
  struct _u_request req;
  struct _u_response resp;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  j_result_2 = init_session(CLIENT_ID_2, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_1), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "callback_url="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_1
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_1,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_1,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_1,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_2
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_2,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_2,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_2,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "DELETE",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/session/",
                                                       U_OPT_HTTP_URL_APPEND, sid,
                                                       U_OPT_COOKIE_PARAMETER, cookie_key, cookie_value,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_1
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_1,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_false(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_1,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_false(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_1,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_false(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_2
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_2,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_false(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_2,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_false(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_2,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_false(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
}
END_TEST

START_TEST(test_oidc_session_management_delete_session_frontchannel_invalid_sid)
{
  char sid[64] = {0};
  json_t * j_result_1, * j_result_2, * j_resp;
  struct _u_request req;
  struct _u_response resp;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  j_result_2 = init_session(CLIENT_ID_2, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_1), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "callback_url="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "DELETE",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/session/",
                                                       U_OPT_HTTP_URL_APPEND, "error",
                                                       U_OPT_COOKIE_PARAMETER, cookie_key, cookie_value,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_1
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_1,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_1,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_1,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_2
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_2,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_2,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_2,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
}
END_TEST

START_TEST(test_oidc_session_management_delete_session_frontchannel_invalid_user)
{
  char sid[64] = {0};
  json_t * j_result_1, * j_result_2, * j_resp;
  struct _u_request req;
  struct _u_response resp;
  
  j_result_1 = init_session(CLIENT_ID_1, sid);
  j_result_2 = init_session(CLIENT_ID_2, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_1), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "callback_url="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "DELETE",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/session/",
                                                       U_OPT_HTTP_URL_APPEND, sid,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_1
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_1,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_1,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_1,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_2
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_2,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_2,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_2,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
}
END_TEST

START_TEST(test_oidc_session_management_delete_session_backchannel_ok)
{
  char sid[64] = {0};
  json_t * j_result_1, * j_result_2, * j_resp;
  struct _u_request req;
  struct _u_response resp;
  char * key_pem, * cert_pem;
  struct _u_instance instance;
  ck_assert_int_eq(0, pthread_mutex_init(&log_lock, NULL));
  ck_assert_int_eq(0, pthread_cond_init(&log_cond, NULL));
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 5468, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "backLogout/:id", 0, &callback_backlogout, sid), U_OK);
  counter = 0;
  
  key_pem = read_file(CB_KEY);
  cert_pem = read_file(CB_CRT);
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, key_pem, cert_pem), U_OK);
  o_free(key_pem);
  o_free(cert_pem);
  
  j_result_1 = init_session(CLIENT_ID_3, sid);
  j_result_2 = init_session(CLIENT_ID_4, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_3), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "callback_url="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_3
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_3,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_3,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_3,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_4
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_4,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_4,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_4,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "DELETE",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/session/",
                                                       U_OPT_HTTP_URL_APPEND, sid,
                                                       U_OPT_COOKIE_PARAMETER, cookie_key, cookie_value,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_3
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_3,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_false(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_3,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_false(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_3,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_false(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_4
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_4,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_false(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_4,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_false(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_4,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_false(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  while (counter < 2) {
    pthread_mutex_lock(&log_lock);
    pthread_cond_wait(&log_cond, &log_lock);
    pthread_mutex_unlock(&log_lock);
  }
  ck_assert_int_eq(2, counter);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  pthread_mutex_destroy(&log_lock);
  pthread_cond_destroy(&log_cond);
}
END_TEST

START_TEST(test_oidc_session_management_delete_session_backchannel_invalid_sid)
{
  char sid[64] = {0};
  json_t * j_result_1, * j_result_2, * j_resp;
  struct _u_request req;
  struct _u_response resp;
  
  j_result_1 = init_session(CLIENT_ID_3, sid);
  j_result_2 = init_session(CLIENT_ID_4, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_3), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "callback_url="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "DELETE",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/session/",
                                                       U_OPT_HTTP_URL_APPEND, "error",
                                                       U_OPT_COOKIE_PARAMETER, cookie_key, cookie_value,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_3
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_3,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_3,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_3,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_4
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_4,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_4,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_4,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
}
END_TEST

START_TEST(test_oidc_session_management_delete_session_backchannel_invalid_user)
{
  char sid[64] = {0};
  json_t * j_result_1, * j_result_2, * j_resp;
  struct _u_request req;
  struct _u_response resp;
  
  j_result_1 = init_session(CLIENT_ID_3, sid);
  j_result_2 = init_session(CLIENT_ID_4, sid);
  ck_assert_ptr_ne(NULL, json_object_get(j_result_1, "id_token"));
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/end_session?id_token_hint=",
                                                       U_OPT_HTTP_URL_APPEND, json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "sid="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), sid), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "plugin="PLUGIN_NAME), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "client_id="CLIENT_ID_3), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "prompt=end_session"), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "callback_url="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), STATE), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), CLIENT_REDIRECT_POST_LOGOUT_ENC), NULL);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "DELETE",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/session/",
                                                       U_OPT_HTTP_URL_APPEND, sid,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_3
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_3,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_3,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_1, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_3,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // CLIENT_ID_4
  // Introspect id_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "id_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_4,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect access_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "access_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_4,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  // Introspect refresh_token
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                       U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result_2, "refresh_token")),
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_4,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_eq(json_true(), json_object_get(j_resp, "active"));
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  json_decref(j_result_1);
  json_decref(j_result_2);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc session management");
  tc_core = tcase_create("test_oidc_session_management");
  tcase_add_test(tc_core, test_oidc_session_management_add_module_ok);
  tcase_add_test(tc_core, test_oidc_session_management_add_client_ok);
  tcase_add_test(tc_core, test_oidc_session_management_session_state);
  tcase_add_test(tc_core, test_oidc_session_management_end_session_no_post_logout);
  tcase_add_test(tc_core, test_oidc_session_management_end_session_invalid_post_logout);
  tcase_add_test(tc_core, test_oidc_session_management_end_session_valid_post_logout);
  tcase_add_test(tc_core, test_oidc_session_management_end_session_no_state);
  tcase_add_test(tc_core, test_oidc_session_management_delete_client);
  tcase_add_test(tc_core, test_oidc_session_management_add_client_channel_ok);
  tcase_add_test(tc_core, test_oidc_session_management_valid_sid);
  tcase_add_test(tc_core, test_oidc_session_management_invalid_sid);
  tcase_add_test(tc_core, test_oidc_session_management_valid_new_sid);
  tcase_add_test(tc_core, test_oidc_session_management_end_session_id_token_post_redirect_state_ok);
  tcase_add_test(tc_core, test_oidc_session_management_end_session_id_token_post_redirect_ok);
  tcase_add_test(tc_core, test_oidc_session_management_end_session_id_token_post_redirect_invalid_state_ok);
  tcase_add_test(tc_core, test_oidc_session_management_end_session_id_token_invalid);
  tcase_add_test(tc_core, test_oidc_session_management_get_session_list_post_redirect_state_ok);
  tcase_add_test(tc_core, test_oidc_session_management_get_session_list_post_redirect_ok);
  tcase_add_test(tc_core, test_oidc_session_management_get_session_list_ok);
  tcase_add_test(tc_core, test_oidc_session_management_get_session_list_sid_invalid);
  tcase_add_test(tc_core, test_oidc_session_management_get_session_list_client_id_invalid);
  tcase_add_test(tc_core, test_oidc_session_management_get_session_list_invalid_user);
  tcase_add_test(tc_core, test_oidc_session_management_delete_session_frontchannel_ok);
  tcase_add_test(tc_core, test_oidc_session_management_delete_session_frontchannel_invalid_sid);
  tcase_add_test(tc_core, test_oidc_session_management_delete_session_frontchannel_invalid_user);
  tcase_add_test(tc_core, test_oidc_session_management_delete_session_backchannel_ok);
  tcase_add_test(tc_core, test_oidc_session_management_delete_session_backchannel_invalid_sid);
  tcase_add_test(tc_core, test_oidc_session_management_delete_session_backchannel_invalid_user);
  tcase_add_test(tc_core, test_oidc_session_management_delete_client_channel);
  tcase_add_test(tc_core, test_oidc_session_management_delete_module);
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
  struct _u_response auth_resp, scope_resp;
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
      char * cookie_adm = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(admin_req.map_header, "Cookie", cookie_adm);
      o_free(cookie_adm);
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
      cookie_key = o_strdup(auth_resp.map_cookie[i].key);
      cookie_value = o_strdup(auth_resp.map_cookie[i].value);
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(user_req.map_header, "Cookie", cookie);
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
  
  //run_simple_test(&user_req, "DELETE", SERVER_URI "/auth/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  o_free(cookie_key);
  o_free(cookie_value);
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&admin_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

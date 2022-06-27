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
#define PLUGIN_NAME "oidc_dpop"
#define SCOPE_LIST "g_profile openid"
#define SCOPE_1 "g_profile"
#define SCOPE_2 "openid"
#define CLIENT "client1_id"
#define RESPONSE_TYPE "code"
#define PLUGIN_PAR_PREFIX "urn:ietf:params:oauth:request_uri:"
#define PLUGIN_PAR_DURATION 90
#define DPOP_NONCE_COUNTER 5
#define DPOP_IAT_GAP 5
#define PLUGIN_CIBA_DEFAULT_EXPIRATION 600
#define PLUGIN_CIBA_MAXIMUM_EXPIRATION 1200
#define CIBA_CLIENT_NOTIFICATION_TOKEN "ZBMDEshXMWMv8KUbBSUnbRgEYpvM8LyA"
#define CB_KEY "cert/server.key"
#define CB_CRT "cert/server.crt"

#define CLIENT_ID "client_dpop"
#define CLIENT_NAME "client for DPoP"
#define CLIENT_SECRET "very-secret"
#define CLIENT_REDIRECT "../../test-oidc.html?param=client1_cb1"
#define STATE "state1234Abcd"
#define NONCE "nonce1234Abcd"

const char jwk_pubkey_sign_str[] = "{\"kty\":\"RSA\",\"n\":\"ANgV1GxZbGBMIqqX5QsNrQQnPLk8UpkqH_60EuaHsI8YnUkPmPVXJ_4z_ziqZizvvjp_RhhXX2DnHEQuYwI-SZaBlK1VJiiWH9"\
                                    "EXrUeazcpEryFUR0I5iBROcgRJfHSvRvC7D83-xg9xC-NGVvIQ2llduYzmaK8rfuiHWlGqow3O2m5os9NTortdQf7BeTniStDokFvZy-I4i24UFkemoNPWZ9MC"\
                                    "N0WTea8n_TQmq9sVHGQtLIFqfblLxbSz_7m4g7_o3WfqlwXkVmCIu1wdzAjZV5BspBGrL0ed5Whpk9-bX69nUDvpcMAaPhuRwZ43e9koVRbVwXCNkne98VAs0_"\
                                    "U\",\"e\":\"AQAB\",\"kid\":\"3\"}";
const char jwk_privkey_sign_str[] = "{\"kty\":\"RSA\",\"n\":\"ANgV1GxZbGBMIqqX5QsNrQQnPLk8UpkqH_60EuaHsI8YnUkPmPVXJ_4z_ziqZizvvjp_RhhXX2DnHEQuYwI-SZaBlK1VJiiWH"\
                                    "9EXrUeazcpEryFUR0I5iBROcgRJfHSvRvC7D83-xg9xC-NGVvIQ2llduYzmaK8rfuiHWlGqow3O2m5os9NTortdQf7BeTniStDokFvZy-I4i24UFkemoNPWZ9M"\
                                    "CN0WTea8n_TQmq9sVHGQtLIFqfblLxbSz_7m4g7_o3WfqlwXkVmCIu1wdzAjZV5BspBGrL0ed5Whpk9-bX69nUDvpcMAaPhuRwZ43e9koVRbVwXCNkne98VAs0"\
                                    "_U\",\"e\":\"AQAB\",\"d\":\"AKOVsyDreb5VJRFcuIrrqYWxZqkc37MQTvR1wrE_HAzYp4n-AuAJQT-Sga6WYY-3V53VaG1ZB93GWIHNVCsImJEWPEYUZj"\
                                    "TnoeKbOBUzPoPYB3UF5oReJYSp9msEbvGvF9d65fYe4DYkcMl4IK5Uz9hDugrPC4VBOmwyu8-DjLkP8OH-N2-KhJvX_kLKgivfzD3KOp6wryLnKuZYn8N4E6rC"\
                                    "iNSfKMgoM60bSHRNi0QHYB2jwqMU5T5EzdpD3Tu_ow6a-sXrW6SG1dtbuStck9hFcQ-QtRCeWoM5pFN8cKOsWBZd1unq-X3gMlCjdXUBUW7BYP44lpYsg1v9l_"\
                                    "Ww64E\",\"p\":\"ANmlFUVM-836aC-wK-DekE3s3gl7GZ-9Qca8iKnaIeMszgyaLYkkbYNPpjjsiQHc37IG3axCaywK40PZqODzovL5PnUpwfNrnlMaI042rN"\
                                    "af8q1L4kvaBTkbO9Wbj0sTLMPt1frLQKBRsNDsYamRcL1SwvTC4aI7cgZBrNIBdPiR\",\"q\":\"AP4qYxRNGaI3aeZh5hgKPSGW82X8Ai2MzIKjzSDYmKGcD"\
                                    "9HPRV0dAUmDCvqyjwCD6tL9iMtZKPz7VK66-KvV1n91WLMDtRzWs_eFFyDY7BYw47o6IQoZ2RxBT3-7WLhlFflaEner8k23zpGOjZbyzt0SIWRAYR0zlb7LrS_"\
                                    "X4fcl\",\"qi\":\"fnlvhYXAn6V0X6gmlwooZUWo9bR7ObChNhrUzMVDOReUVOrzOhlzGhBW1TEFBBr8k44ZWBCTeVEQh--LFHwVvCgEjDBxfjUPUMkeyKZzL"\
                                    "hpIUB_cFBAgI7Fyy0yuPpY0mS1PfMt5Y4b6g_JvdBWZZ8VhTcCVG7qDqoH_IJMXPNg\",\"dp\":\"EAsiQUSGf02JJpLG-UGOw5_FUk-XuPW7honZTSP-QX_J"\
                                    "BJbM6oIb7IUPjLyq8M82Uio9ZvhSbCG1VQgTcdmj1mNXHk3gtS_msNuJZLeVEBEkU2_3k33TyrzeMUXRT0hvkVXT4zPeZLMA5LW4EUbeV6ZlJqPC_DGDm0B2G9"\
                                    "jtpXE\",\"dq\":\"AMTictPUEcpOILO9HG985vPxKeTTfaBpVDbSymDqR_nQmZSOeg3yHQAkCco_rXTZu3rruR7El3K5AlVEMsNxp3IepbIuagrH6qsPpuXkA"\
                                    "6YBAzdMNjHL6hnwIbQxnT1h2M7KzklzogRAIT0x706CEmq_06wEDvZ-8j3VKvhHxBwd\",\"kid\":\"3\"}";
const char jwk_pubkey_sign_str_2[] = "{\"kty\":\"RSA\",\"n\":\"ALZfFvsvNegnsnjhAydGJ17C9Ny5-M1UqRbcgaPUFRqvfn2P2Yz5rjGTnfFKe9E6xANSNzKRdb5ltNeeJT0inSi2meACAXE6"\
                                    "8Ud7d2JvlkxQPvz1tJyCKvQFktGwlqwW5F8r_spfT1qJsf_DpZWjsXFrkY7sdrHJdoeQZDIYx0fsGdzlA0uGoGimPlCCExYLcqsjjh3Dqv8V1xJ4jm5S8198v3"\
                                    "FJXXm5BN_GWAmExuDOq6ul8MqcECXBQ4LavxFlB5kGgPsxvFjTK72_2YdNDQPkKmV56vShm50BaEqzXU0A2MYeTyabX7d4goI_B7IeX5tGqMjBrlX6hNS-VfqG"\
                                    "MVM\",\"e\":\"AQAB\",\"kid\":\"4\"}";
const char jwk_privkey_sign_str_2[] = "{\"kty\":\"RSA\",\"n\":\"ALZfFvsvNegnsnjhAydGJ17C9Ny5-M1UqRbcgaPUFRqvfn2P2Yz5rjGTnfFKe9E6xANSNzKRdb5ltNeeJT0inSi2meACAXE"\
                                    "68Ud7d2JvlkxQPvz1tJyCKvQFktGwlqwW5F8r_spfT1qJsf_DpZWjsXFrkY7sdrHJdoeQZDIYx0fsGdzlA0uGoGimPlCCExYLcqsjjh3Dqv8V1xJ4jm5S8198v"\
                                    "3FJXXm5BN_GWAmExuDOq6ul8MqcECXBQ4LavxFlB5kGgPsxvFjTK72_2YdNDQPkKmV56vShm50BaEqzXU0A2MYeTyabX7d4goI_B7IeX5tGqMjBrlX6hNS-Vfq"\
                                    "GMVM\",\"e\":\"AQAB\",\"d\":\"HyIUlkT0-vDr8t7W3vmG9xJpItVMuCDfzNtP9lvaTnfvLBhGl154clY0_GAuywUxOS_r5GIYq6xJNxX0XX9vPOgPVMKC"\
                                    "5IWfcwiM1O0fx19boWuArcc69fWNnuZ6kl5GFkk4cevbbCVdkcAgoG8Vd7tZWgDcMnWmGnZ35GV-f7Rw3kQTxge4V7T5-I5preMxRAV2YZ1zafIDpYXaOXWL9b"\
                                    "X0vAApb5Vie1btPiOj7lZ_J0ChkkdIW-ZTiQZ0sTRo6c6qLVNHQLKAJ_I6QLMfiHAT8xFir3fgiUxNwxxifYOts_akh3-wJEs4r4G92hohmIiIKp2TABDc3Wrm"\
                                    "FDafYQ\",\"p\":\"ANVUDxAxNuR8Ds5W_3xpGgOKzypYGfimDrU_kRzXsdXOz4EkSYXG2SR7V854vvcgJDzFIihmaI_65LN_pk_6ZE1ddd8Qrud9nMtd5n9ne"\
                                    "EkOGTCsTO-TM4gLjyZQ3FCo_oCsJ6MiQRlOTw5pf1yH69q3QUd5e_5c75MYr4G0fPwn\",\"q\":\"ANrZ0K-ZdBt9uP1Bt0G7YmW3j41wFt1JnmOkX86YX6Q3"\
                                    "wrI4YqiRfolVexAtQ1a1iRVY7ZGXhy_q0rDLPIpfYAy9LSS1NZHb_vu7C-p8hCALxKa6bTGLeT4Z5LABHPBoMVCyKhlANMHhcUeNY76p4JwT1zwT7FIHamKgVK"\
                                    "zv_CD1\",\"qi\":\"GUmL7fbgnNa2IQ13i3Xi3A5dXzgqBeVHb2HjAzCJhNCcg8jslpU4rmMoGAq_WagT-U3_NuUVnGWnHTPWHjFe9MkwxPpSIISbMRorOhsZ"\
                                    "Mrlzg4vdyZ2Kt_zs3yNTb_KOYx6YxU3_93IdFU2XjlnUf4mDThVoTSRfNh-NMJgwLUw\",\"dp\":\"ALBi7IGK78RD_0oFDQIlNOkw4NI2PmMliou6n5Wlktk"\
                                    "iQtiY1GHUZL6Rbay-kcdrwAqvROr6ogJKhMcWCMGgW0bMvCVQeg3WAsr0PR2ixAZDrfhcvtBoefdG93nK6h-XW7ewoKV2MTVnVl6oRDKSACW72DHs9OUAmuaZR"\
                                    "qSMQ7uJ\",\"dq\":\"AIgWpDddtB6YOl157Ov6CwD3eVPZXM50RgLuJwmAJREn_3D1sRvjhYz-08zGaLZVoo3cw7YiRNVeL2_yoY3mKwMg7B6EdHBkHhYJRSq"\
                                    "mDT8kMj__c4E4mscsMNHlj0pLcEce0yDqlSPu_ZMh7-GTH3HOwKvCM9T6eYQk8SKtBNq1\",\"kid\":\"4\"}";

struct _u_request admin_req;
struct _u_request user_req;

char * rand_jti(char * str) {
  unsigned int x;
  
  gnutls_rnd(GNUTLS_RND_NONCE, &x, sizeof(unsigned int));
  sprintf(str, "%u", x);
  return str;
}

START_TEST(test_oidc_dpop_add_plugin)
{
  json_t * j_param = json_pack("{sssssss{sssssssssisisisosososososososososososssisosisisssoso sosisisosososososo}}",
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
                                  "auth-type-password-enabled", json_true(),
                                  "oauth-par-allowed", json_true(),
                                  "oauth-par-required", json_false(),
                                  "oauth-par-request_uri-prefix", PLUGIN_PAR_PREFIX,
                                  "oauth-par-duration", PLUGIN_PAR_DURATION,
                                  "oauth-dpop-allowed", json_true(),
                                  "oauth-dpop-iat-duration", 60,
                                  "oauth-dpop-iat-gap-duration", DPOP_IAT_GAP,
                                  "oauth-dpop-dpop_bound_access_tokens-property", "dpop_client_bound",
                                  "introspection-revocation-allowed", json_true(),
                                  "introspection-revocation-allow-target-client", json_true(),
                                  "oauth-ciba-allowed", json_true(),
                                  "oauth-ciba-default-expiry", PLUGIN_CIBA_DEFAULT_EXPIRATION,
                                  "oauth-ciba-maximum-expiry", PLUGIN_CIBA_MAXIMUM_EXPIRATION,
                                  "oauth-ciba-mode-poll-allowed", json_true(),
                                  "oauth-ciba-mode-ping-allowed", json_true(),
                                  "oauth-ciba-mode-push-allowed", json_true(),
                                  "oauth-ciba-allow-https-non-secure", json_true(),
                                  "oauth-ciba-user-code-allowed", json_false(),
                                  "oauth-ciba-email-allowed", json_false());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_dpop_add_plugin_nonce)
{
  json_t * j_param = json_pack("{sssssss{sssssssssisisisosososososososososososssisosisisssosisoso}}",
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
                                  "auth-type-password-enabled", json_true(),
                                  "oauth-par-allowed", json_true(),
                                  "oauth-par-required", json_false(),
                                  "oauth-par-request_uri-prefix", PLUGIN_PAR_PREFIX,
                                  "oauth-par-duration", PLUGIN_PAR_DURATION,
                                  "oauth-dpop-allowed", json_true(),
                                  "oauth-dpop-iat-duration", 60,
                                  "oauth-dpop-iat-gap-duration", DPOP_IAT_GAP,
                                  "oauth-dpop-dpop_bound_access_tokens-property", "dpop_client_bound",
                                  "oauth-dpop-nonce-mandatory", json_true(),
                                  "oauth-dpop-nonce-counter", DPOP_NONCE_COUNTER,
                                  "introspection-revocation-allowed", json_true(),
                                  "introspection-revocation-allow-target-client", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_dpop_add_client_confidential_ok)
{
  json_t * j_parameters = json_pack("{sssssssos[sssss]s[s]s[ss]sssos[s]}",
                                    "client_id", CLIENT_ID,
                                    "client_name", CLIENT_NAME,
                                    "client_secret", CLIENT_SECRET,
                                    "confidential", json_true(),
                                    "authorization_type", 
                                      "device_authorization",
                                      "code",
                                      "client_credentials",
                                      "password",
                                      "urn:openid:params:grant-type:ciba",
                                    "redirect_uri",
                                      CLIENT_REDIRECT,
                                    "scope",
                                      SCOPE_1,
                                      SCOPE_2,
                                    "backchannel_token_delivery_mode", "poll",
                                    "enabled", json_true(),
                                    "token_endpoint_auth_method", "client_secret_basic");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_dpop_add_client_confidential_dpop_mandatory_ok)
{
  json_t * j_parameters = json_pack("{sssssssos[ssss]s[s]s[ss]sssos[s]}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "client_secret", CLIENT_SECRET,
                                "confidential", json_true(),
                                "authorization_type", 
                                  "device_authorization",
                                  "code",
                                  "client_credentials",
                                  "password",
                                "redirect_uri",
                                  CLIENT_REDIRECT,
                                "scope",
                                  SCOPE_1,
                                  SCOPE_2,
                                "dpop_client_bound", "1",
                                "enabled", json_true(),
                                "token_endpoint_auth_method", "client_secret_basic");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_dpop_get_at_with_jkt_invalid)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token;
  json_t * j_dpop_pub, * j_dpop_priv;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_ptr_ne(NULL, j_dpop_priv = json_loads(jwk_privkey_sign_str, JSON_DECODE_ANY, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  
  // No jti
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // jti non string
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "jti", 42), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // Invalid htm
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "GET"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // No htm
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // Non string htm
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "htm", 42), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // Invalid htu
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/error"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // Non string htu
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "htu", 42), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // No htu
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // Non int iat
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "iat", "error"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // iat too big
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)+30), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // iat too low
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)-300), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // No iat
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "iat", NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // Non string typ
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_int_value(jwt_dpop, "typ", 42), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // Invalid typ
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "error"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // No typ
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // Invalid jwk
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "jwk", "error"), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // Invalid jwk
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_int_value(jwt_dpop, "jwk", 42), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  
  // Invalid jwk
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_priv), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  json_decref(j_dpop_pub);
  json_decref(j_dpop_priv);
  o_free(code);
  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_get_at_with_jkt_jti_replay)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_result);
  json_decref(j_dpop_pub);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(code);
  r_jwt_free(jwt_dpop);
  r_jwt_free(jwt_at);
  r_jwk_free(jwk_dpop_pub);

  ulfius_init_response(&resp);
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
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  o_free(dpop_token);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  o_free(code);
}
END_TEST

START_TEST(test_oidc_dpop_get_at_with_jkt)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_result);
  json_decref(j_dpop_pub);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(code);
  o_free(dpop_token);
  r_jwt_free(jwt_dpop);
  r_jwt_free(jwt_at);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_refresh_at_with_jkt)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  r_jwt_free(jwt_at);
  
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                 U_OPT_POST_BODY_PARAMETER, "refresh_token", json_string_value(json_object_get(j_result, "refresh_token")),
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  json_decref(j_result);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  r_jwt_free(jwt_at);
  
  json_decref(j_result);
  json_decref(j_dpop_pub);
  o_free(code);
  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_refresh_at_with_invalid_jkt)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  r_jwt_free(jwt_at);
  r_jwt_free(jwt_dpop);
  
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str_2, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                 U_OPT_POST_BODY_PARAMETER, "refresh_token", json_string_value(json_object_get(j_result, "refresh_token")),
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  
  json_decref(j_result);
  json_decref(j_dpop_pub);
  o_free(code);
  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_refresh_at_without_jkt)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  r_jwt_free(jwt_at);
  r_jwt_free(jwt_dpop);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                 U_OPT_POST_BODY_PARAMETER, "refresh_token", json_string_value(json_object_get(j_result, "refresh_token")),
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  json_decref(j_result);
  json_decref(j_dpop_pub);
  o_free(code);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_get_at_with_jkt_in_auth)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token, * dpop_jkt;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub, * jwk_dpop_priv;
  
  ck_assert_ptr_ne(NULL, jwk_dpop_priv = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_sign_str));
  ck_assert_ptr_ne(NULL, dpop_jkt = r_jwk_thumbprint(jwk_dpop_priv, R_JWK_THUMB_SHA256, 0));
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s&dpop_jkt=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST, dpop_jkt);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_result);
  json_decref(j_dpop_pub);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(code);
  o_free(dpop_token);
  o_free(dpop_jkt);
  r_jwt_free(jwt_dpop);
  r_jwt_free(jwt_at);
  r_jwk_free(jwk_dpop_pub);
  r_jwk_free(jwk_dpop_priv);
}
END_TEST

START_TEST(test_oidc_dpop_get_at_with_jkt_in_auth_invalid)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token, * dpop_jkt;
  json_t * j_dpop_pub;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub, * jwk_dpop_priv;
  
  ck_assert_ptr_ne(NULL, jwk_dpop_priv = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_sign_str_2));
  ck_assert_ptr_ne(NULL, dpop_jkt = r_jwk_thumbprint(jwk_dpop_priv, R_JWK_THUMB_SHA256, 0));
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s&dpop_jkt=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST, dpop_jkt);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  json_decref(j_dpop_pub);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(code);
  o_free(dpop_token);
  o_free(dpop_jkt);
  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
  r_jwk_free(jwk_dpop_priv);
}
END_TEST

START_TEST(test_oidc_dpop_userinfo_with_jkt_invalid)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token, * bearer;
  json_t * j_result, * j_dpop_pub;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub;
  unsigned char ath[32] = {0}, ath_enc[64] = {0};
  size_t ath_len = 32, ath_enc_len = 64;
  gnutls_datum_t hash_data;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  
  hash_data.data = (unsigned char*)json_string_value(json_object_get(j_result, "access_token"));
  hash_data.size = json_string_length(json_object_get(j_result, "access_token"));
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_DIG_SHA256, &hash_data, ath, &ath_len), GNUTLS_E_SUCCESS);
  ck_assert_int_eq(o_base64url_encode(ath, ath_len, ath_enc, &ath_enc_len), 1);
  ath_enc[ath_enc_len] = '\0';

  ck_assert_ptr_ne(NULL, bearer = msprintf("DPoP %s", json_string_value(json_object_get(j_result, "access_token"))));
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "GET",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/userinfo",
                                                 U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "ath", (const char *)ath_enc), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "GET"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/userinfo"), RHN_OK);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "GET",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/userinfo",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "htm", 42), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", NULL), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "GET"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", "error"), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "htu", 42), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", NULL), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/userinfo"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "iat", "error"), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)+30), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)-600), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "iat", NULL), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "error"), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_header_int_value(jwt_dpop, "typ", 42), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", NULL), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "jwk", "error"), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_header_int_value(jwt_dpop, "jwk", 42), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "jwk", NULL), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "ath", "error"), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "ath", NULL), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  
  r_jwk_free(jwk_dpop_pub);
  json_decref(j_dpop_pub);
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str_2), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ulfius_init_response(&resp);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  r_jwk_free(jwk_dpop_pub);
  r_jwt_free(jwt_dpop);
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str_2), RHN_OK);
  json_decref(j_dpop_pub);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str_2, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "ath", (const char *)ath_enc), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ulfius_init_response(&resp);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  r_jwk_free(jwk_dpop_pub);
  
  json_decref(j_result);
  json_decref(j_dpop_pub);
  ulfius_clean_request(&req);
  o_free(code);
  o_free(bearer);
  r_jwt_free(jwt_dpop);
}
END_TEST

START_TEST(test_oidc_dpop_userinfo_with_jkt)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token, * bearer;
  json_t * j_result, * j_dpop_pub;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub;
  unsigned char ath[32] = {0}, ath_enc[64] = {0};
  size_t ath_len = 32, ath_enc_len = 64;
  gnutls_datum_t hash_data;

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "token_type")), "DPoP");
  hash_data.data = (unsigned char*)json_string_value(json_object_get(j_result, "access_token"));
  hash_data.size = json_string_length(json_object_get(j_result, "access_token"));
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_DIG_SHA256, &hash_data, ath, &ath_len), GNUTLS_E_SUCCESS);
  ck_assert_int_eq(o_base64url_encode(ath, ath_len, ath_enc, &ath_enc_len), 1);
  ath_enc[ath_enc_len] = '\0';

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "GET"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/userinfo"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "ath", (const char *)ath_enc), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_ptr_ne(NULL, bearer = msprintf("DPoP %s", json_string_value(json_object_get(j_result, "access_token"))));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "GET",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/userinfo",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  
  json_decref(j_result);
  json_decref(j_dpop_pub);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(code);
  o_free(bearer);
  o_free(dpop_token);
  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_userinfo_with_jkt_jti_replay)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token, * bearer;
  json_t * j_result, * j_dpop_pub;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub;
  unsigned char ath[32] = {0}, ath_enc[64] = {0};
  size_t ath_len = 32, ath_enc_len = 64;
  gnutls_datum_t hash_data;

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  
  hash_data.data = (unsigned char*)json_string_value(json_object_get(j_result, "access_token"));
  hash_data.size = json_string_length(json_object_get(j_result, "access_token"));
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_DIG_SHA256, &hash_data, ath, &ath_len), GNUTLS_E_SUCCESS);
  ck_assert_int_eq(o_base64url_encode(ath, ath_len, ath_enc, &ath_enc_len), 1);
  ath_enc[ath_enc_len] = '\0';

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "GET"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/userinfo"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "ath", (const char *)ath_enc), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  ck_assert_ptr_ne(NULL, bearer = msprintf("DPoP %s", json_string_value(json_object_get(j_result, "access_token"))));
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "GET",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/userinfo",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_response(&resp);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  
  json_decref(j_result);
  json_decref(j_dpop_pub);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(code);
  o_free(bearer);
  o_free(dpop_token);
  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_introspection)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token, * jkt;
  json_t * j_result, * j_dpop_pub, * j_result_introspect;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub;
  unsigned char ath[32] = {0}, ath_enc[64] = {0};
  size_t ath_len = 32, ath_enc_len = 64;
  gnutls_datum_t hash_data;

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT_ID, SCOPE_LIST);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_ptr_ne(NULL, jkt = r_jwk_thumbprint(jwk_dpop_pub, R_JWK_THUMB_SHA256, 0));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  
  ck_assert_str_eq(json_string_value(json_object_get(j_result, "token_type")), "DPoP");
  hash_data.data = (unsigned char*)json_string_value(json_object_get(j_result, "access_token"));
  hash_data.size = json_string_length(json_object_get(j_result, "access_token"));
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_DIG_SHA256, &hash_data, ath, &ath_len), GNUTLS_E_SUCCESS);
  ck_assert_int_eq(o_base64url_encode(ath, ath_len, ath_enc, &ath_enc_len), 1);
  ath_enc[ath_enc_len] = '\0';

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_POST_BODY_PARAMETER, "token", json_string_value(json_object_get(j_result, "access_token")),
                                                 U_OPT_POST_BODY_PARAMETER, "token_type_hint", "access_token",
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result_introspect = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, o_strstr(json_string_value(json_object_get(j_result_introspect, "token_type")), "DPoP"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result_introspect, "cnf"));
  ck_assert_ptr_ne(NULL, json_object_get(json_object_get(j_result_introspect, "cnf"), "jkt"));
  ck_assert_str_eq(jkt, json_string_value(json_object_get(json_object_get(j_result_introspect, "cnf"), "jkt")));
  
  json_decref(j_result);
  json_decref(j_result_introspect);
  json_decref(j_dpop_pub);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(code);
  o_free(jkt);
  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_device_verification_with_jkt_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_grant;
  const char * code, * redirect_uri, * device_code;
  char jti[17], * dpop_token, * dpop_jkt;
  json_t * j_dpop_pub;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub, * jwk_dpop_priv;
  
  ck_assert_ptr_ne(NULL, jwk_dpop_priv = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_sign_str_2));
  ck_assert_ptr_ne(NULL, dpop_jkt = r_jwk_thumbprint(jwk_dpop_priv, R_JWK_THUMB_SHA256, 0));
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  u_map_put(req.map_post_body, "dpop_jkt", dpop_jkt);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  u_map_put(req.map_header, "DPoP", dpop_token);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(403, resp.status);

  json_decref(j_resp);
  json_decref(j_dpop_pub);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  o_free(dpop_jkt);
  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
  r_jwk_free(jwk_dpop_priv);
}
END_TEST

START_TEST(test_oidc_dpop_device_verification_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_grant;
  const char * code, * redirect_uri, * device_code;
  jwt_t * jwt;
  char jti[17], * dpop_token;
  json_t * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;
  
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  u_map_put(req.map_header, "DPoP", dpop_token);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  ck_assert_ptr_ne(json_object_get(j_resp, "refresh_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "id_token"), NULL);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq(SCOPE_LIST, r_jwt_get_claim_str_value(jwt, "aud"));
  r_jwt_free(jwt);
  
  json_decref(j_resp);
  json_decref(j_cnf);
  json_decref(j_dpop_pub);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
  r_jwt_free(jwt_at);
}
END_TEST

START_TEST(test_oidc_dpop_device_verification_with_jkt_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_grant;
  const char * code, * redirect_uri, * device_code;
  jwt_t * jwt;
  char jti[17], * dpop_token, * dpop_jkt;
  json_t * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub, * jwk_dpop_priv;
  
  ck_assert_ptr_ne(NULL, jwk_dpop_priv = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_sign_str));
  ck_assert_ptr_ne(NULL, dpop_jkt = r_jwk_thumbprint(jwk_dpop_priv, R_JWK_THUMB_SHA256, 0));
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/device_authorization/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "device_authorization");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "scope", SCOPE_LIST);
  u_map_put(req.map_post_body, "dpop_jkt", dpop_jkt);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT_ID);
  u_map_put(req.map_post_body, "device_code", device_code);
  u_map_put(req.map_header, "DPoP", dpop_token);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  ck_assert_ptr_ne(json_object_get(j_resp, "refresh_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "id_token"), NULL);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq(SCOPE_LIST, r_jwt_get_claim_str_value(jwt, "aud"));
  r_jwt_free(jwt);
  
  json_decref(j_resp);
  json_decref(j_cnf);
  json_decref(j_dpop_pub);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(dpop_token);
  o_free(dpop_jkt);
  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
  r_jwk_free(jwk_dpop_priv);
  r_jwt_free(jwt_at);
}
END_TEST

START_TEST(test_oidc_dpop_par_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_response;
  char * code, jti[17], * dpop_token;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "response_type", RESPONSE_TYPE,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                U_OPT_POST_BODY_PARAMETER, "state", STATE,
                                U_OPT_POST_BODY_PARAMETER, "nonce", NONCE,
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

  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_result);
  json_decref(j_dpop_pub);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(code);
  o_free(dpop_token);
  r_jwt_free(jwt_dpop);
  r_jwt_free(jwt_at);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_par_with_jkt_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_response;
  char * code, jti[17], * dpop_token, * dpop_jkt;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub, * jwk_dpop_priv;

  ck_assert_ptr_ne(NULL, jwk_dpop_priv = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_sign_str));
  ck_assert_ptr_ne(NULL, dpop_jkt = r_jwk_thumbprint(jwk_dpop_priv, R_JWK_THUMB_SHA256, 0));

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "response_type", RESPONSE_TYPE,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                U_OPT_POST_BODY_PARAMETER, "state", STATE,
                                U_OPT_POST_BODY_PARAMETER, "nonce", NONCE,
                                U_OPT_POST_BODY_PARAMETER, "dpop_jkt", dpop_jkt,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(201, resp.status);
  ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_response, "request_uri")), o_strlen(PLUGIN_PAR_PREFIX));
  ck_assert_int_eq(0, o_strncmp(json_string_value(json_object_get(j_response, "request_uri")), PLUGIN_PAR_PREFIX, o_strlen(PLUGIN_PAR_PREFIX)));
  ck_assert_int_eq(PLUGIN_PAR_DURATION, json_integer_value(json_object_get(j_response, "expires_in")));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_jkt);

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

  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_result);
  json_decref(j_dpop_pub);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  r_jwt_free(jwt_dpop);
  r_jwt_free(jwt_at);
  r_jwk_free(jwk_dpop_pub);
  r_jwk_free(jwk_dpop_priv);
  o_free(code);
}
END_TEST

START_TEST(test_oidc_dpop_par_with_dpop_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_response;
  char * code, jti[17], * dpop_token;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;

  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/par"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  r_jwt_free(jwt_dpop);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "response_type", RESPONSE_TYPE,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                U_OPT_POST_BODY_PARAMETER, "state", STATE,
                                U_OPT_POST_BODY_PARAMETER, "nonce", NONCE,
                                U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                U_OPT_NONE);
  o_free(dpop_token);
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

  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_result);
  json_decref(j_dpop_pub);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  r_jwt_free(jwt_dpop);
  r_jwt_free(jwt_at);
  r_jwk_free(jwk_dpop_pub);
  o_free(code);
}
END_TEST

START_TEST(test_oidc_dpop_par_with_dpop_jtk_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_response;
  char * code, jti[17], * dpop_token, * dpop_jkt;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub, * jwk_dpop_priv;

  ck_assert_ptr_ne(NULL, jwk_dpop_priv = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_sign_str));
  ck_assert_ptr_ne(NULL, dpop_jkt = r_jwk_thumbprint(jwk_dpop_priv, R_JWK_THUMB_SHA256, 0));

  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/par"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  r_jwt_free(jwt_dpop);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "response_type", RESPONSE_TYPE,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                U_OPT_POST_BODY_PARAMETER, "state", STATE,
                                U_OPT_POST_BODY_PARAMETER, "nonce", NONCE,
                                U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                U_OPT_POST_BODY_PARAMETER, "dpop_jkt", dpop_jkt,
                                U_OPT_NONE);
  o_free(dpop_token);
  o_free(dpop_jkt);
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

  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_result);
  json_decref(j_dpop_pub);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  r_jwt_free(jwt_dpop);
  r_jwt_free(jwt_at);
  r_jwk_free(jwk_dpop_pub);
  r_jwk_free(jwk_dpop_priv);
  o_free(code);
}
END_TEST

START_TEST(test_oidc_dpop_par_with_dpop_jtk_inconsistent)
{
  struct _u_request req;
  struct _u_response resp;
  char jti[17], * dpop_token, * dpop_jkt;
  json_t * j_dpop_pub;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub, * jwk_dpop_priv;

  ck_assert_ptr_ne(NULL, jwk_dpop_priv = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_sign_str_2));
  ck_assert_ptr_ne(NULL, dpop_jkt = r_jwk_thumbprint(jwk_dpop_priv, R_JWK_THUMB_SHA256, 0));

  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/par"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "response_type", RESPONSE_TYPE,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                U_OPT_POST_BODY_PARAMETER, "state", STATE,
                                U_OPT_POST_BODY_PARAMETER, "nonce", NONCE,
                                U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                U_OPT_POST_BODY_PARAMETER, "dpop_jkt", dpop_jkt,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);

  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  o_free(dpop_jkt);
  json_decref(j_dpop_pub);
  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
  r_jwk_free(jwk_dpop_priv);
}
END_TEST

START_TEST(test_oidc_dpop_par_with_jkt_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_response;
  char * code, jti[17], * dpop_token, * dpop_jkt;
  json_t * j_dpop_pub;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub, * jwk_dpop_priv;

  ck_assert_ptr_ne(NULL, jwk_dpop_priv = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_sign_str_2));
  ck_assert_ptr_ne(NULL, dpop_jkt = r_jwk_thumbprint(jwk_dpop_priv, R_JWK_THUMB_SHA256, 0));

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req, 
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, (SERVER_URI "/" PLUGIN_NAME "/par"),
                                U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                U_OPT_POST_BODY_PARAMETER, "response_type", RESPONSE_TYPE,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                U_OPT_POST_BODY_PARAMETER, "state", STATE,
                                U_OPT_POST_BODY_PARAMETER, "nonce", NONCE,
                                U_OPT_POST_BODY_PARAMETER, "dpop_jkt", dpop_jkt,
                                U_OPT_NONE);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(201, resp.status);
  ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_response, "request_uri")), o_strlen(PLUGIN_PAR_PREFIX));
  ck_assert_int_eq(0, o_strncmp(json_string_value(json_object_get(j_response, "request_uri")), PLUGIN_PAR_PREFIX, o_strlen(PLUGIN_PAR_PREFIX)));
  ck_assert_int_eq(PLUGIN_PAR_DURATION, json_integer_value(json_object_get(j_response, "expires_in")));
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_jkt);

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

  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  json_decref(j_dpop_pub);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
  r_jwk_free(jwk_dpop_priv);
  o_free(code);
}
END_TEST

START_TEST(test_oidc_dpop_client_credentials_at_with_jkt)
{
  struct _u_response resp;
  struct _u_request req;
  char jti[17], * dpop_token;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_1,
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_result);
  json_decref(j_dpop_pub);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  r_jwt_free(jwt_dpop);
  r_jwt_free(jwt_at);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_client_credentials_at_with_jkt_iat_gap)
{
  struct _u_response resp;
  struct _u_request req;
  char jti[17], * dpop_token;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)-(DPOP_IAT_GAP)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_1,
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_result);
  json_decref(j_dpop_pub);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  r_jwt_free(jwt_dpop);
  r_jwt_free(jwt_at);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_password_at_with_jkt)
{
  struct _u_response resp;
  struct _u_request req;
  char jti[17], * dpop_token;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "password",
                                                 U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_1,
                                                 U_OPT_POST_BODY_PARAMETER, "username", USER_USERNAME,
                                                 U_OPT_POST_BODY_PARAMETER, "password", USER_PASSWORD,
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_result);
  json_decref(j_dpop_pub);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);
  r_jwt_free(jwt_dpop);
  r_jwt_free(jwt_at);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_client_credentials_at_without_jkt_error)
{
  struct _u_response resp;
  struct _u_request req;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_1,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_oidc_dpop_get_at_with_jkt_and_nonce)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  json_decref(j_dpop_pub);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  o_free(dpop_token);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_ptr_ne(NULL, u_map_get(resp.map_header, "DPoP-Nonce"));
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "nonce", u_map_get(resp.map_header, "DPoP-Nonce")), RHN_OK);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_result);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);

  o_free(code);
  r_jwt_free(jwt_dpop);
  r_jwt_free(jwt_at);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_get_at_with_jkt_invalid_nonce)
{
  struct _u_response resp;
  struct _u_request req;
  char * code, jti[17], * dpop_token;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=..%%2f..%%2ftest-oidc.html%%3fparam%%3dclient1_cb1&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE, CLIENT, SCOPE_LIST);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "nonce", "error"), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  json_decref(j_dpop_pub);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  o_free(dpop_token);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_ptr_ne(NULL, u_map_get(resp.map_header, "DPoP-Nonce"));
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "nonce", u_map_get(resp.map_header, "DPoP-Nonce")), RHN_OK);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "code", code,
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client1_cb1",
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  json_decref(j_result);
  json_decref(j_cnf);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  o_free(dpop_token);

  o_free(code);
  r_jwt_free(jwt_dpop);
  r_jwt_free(jwt_at);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_client_credentials_at_with_jkt_and_nonce_and_nonce_updated)
{
  struct _u_response resp;
  struct _u_request req;
  char jti[17], * dpop_token;
  json_t * j_result, * j_dpop_pub, * j_cnf;
  jwt_t * jwt_dpop, * jwt_at;
  jwk_t * jwk_dpop_pub;
  size_t i;
  int nonce_changed = 0;
  
  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  json_decref(j_dpop_pub);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                 U_OPT_HTTP_VERB, "POST",
                                                 U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                 U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                 U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                 U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                 U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                 U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_1,
                                                 U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                 U_OPT_NONE), U_OK);
  o_free(dpop_token);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 400);
  ck_assert_ptr_ne(NULL, u_map_get(resp.map_header, "DPoP-Nonce"));
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "nonce", u_map_get(resp.map_header, "DPoP-Nonce")), RHN_OK);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  for (i=0; i<DPOP_NONCE_COUNTER+1; i++) {
    rand_jti(jti);
    ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
    ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));

    ulfius_init_request(&req);
    ulfius_init_response(&resp);
    ck_assert_int_eq(ulfius_set_request_properties(&req, 
                                                   U_OPT_HTTP_VERB, "POST",
                                                   U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                   U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                   U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                   U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                   U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                   U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_1,
                                                   U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                   U_OPT_NONE), U_OK);
    ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
    ck_assert_int_eq(resp.status, 200);
    if (u_map_get(resp.map_header, "DPoP-Nonce") != NULL) {
      nonce_changed = 1;
      ck_assert_str_ne(u_map_get(resp.map_header, "DPoP-Nonce"), r_jwt_get_claim_str_value(jwt_dpop, "nonce"));
      ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "nonce", u_map_get(resp.map_header, "DPoP-Nonce")), RHN_OK);
    }
    ck_assert_ptr_ne(NULL, j_result = ulfius_get_json_body_response(&resp, NULL));
    ck_assert_int_eq(r_jwt_init(&jwt_at), RHN_OK);
    ck_assert_int_eq(r_jwt_parse(jwt_at, json_string_value(json_object_get(j_result, "access_token")), 0), RHN_OK);
    ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt_at, "cnf"));
    ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
    json_decref(j_result);
    json_decref(j_cnf);
    ulfius_clean_response(&resp);
    ulfius_clean_request(&req);
    o_free(dpop_token);
    r_jwt_free(jwt_at);
  }
  ck_assert_int_eq(nonce_changed, 1);
  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
}
END_TEST

START_TEST(test_oidc_dpop_ciba_poll_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body, * j_cnf, * j_dpop_pub;
  char * url, * auth_req_id, jti[17], * dpop_token;
  jwt_t * jwt;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub, * jwk_dpop_priv;

  ck_assert_ptr_ne(NULL, jwk_dpop_priv = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_sign_str));

  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/ciba"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  r_jwk_free(j_dpop_pub);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                       U_OPT_NONE), U_OK);
  o_free(dpop_token);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, auth_req_id = o_strdup(json_string_value(json_object_get(j_body, "auth_req_id"))));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  url = msprintf("%s&g_continue", json_string_value(json_object_get(json_array_get(j_body, 0), "connect_uri")));
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "ciba_message=complete"), 1);
  o_free(url);
  json_decref(j_body);

  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                                       U_OPT_POST_BODY_PARAMETER, "auth_req_id", auth_req_id,
                                                       U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                       U_OPT_NONE), U_OK);
  o_free(dpop_token);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq(auth_req_id, json_string_value(json_object_get(j_body, "auth_req_id")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "access_token")));
  ck_assert_str_eq("DPoP", json_string_value(json_object_get(j_body, "token_type")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "refresh_token")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "id_token")));
  ck_assert_ptr_ne(NULL, jwt = r_jwt_quick_parse(json_string_value(json_object_get(j_body, "access_token")), R_PARSE_NONE, 0));
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  ck_assert_str_eq(SCOPE_LIST, r_jwt_get_claim_str_value(jwt, "scope"));
  r_jwt_free(jwt);

  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
  r_jwk_free(jwk_dpop_priv);
  o_free(auth_req_id);
  json_decref(j_body);
  json_decref(j_cnf);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_dpop_ciba_poll_with_jkt_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body, * j_cnf, * j_dpop_pub;
  char * url, * auth_req_id, jti[17], * dpop_token, * dpop_jkt;
  jwt_t * jwt;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub, * jwk_dpop_priv;

  ck_assert_ptr_ne(NULL, jwk_dpop_priv = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_sign_str));
  ck_assert_ptr_ne(NULL, dpop_jkt = r_jwk_thumbprint(jwk_dpop_priv, R_JWK_THUMB_SHA256, 0));

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_POST_BODY_PARAMETER, "dpop_jkt", dpop_jkt,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, auth_req_id = o_strdup(json_string_value(json_object_get(j_body, "auth_req_id"))));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_body);
  o_free(dpop_jkt);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  url = msprintf("%s&g_continue", json_string_value(json_object_get(json_array_get(j_body, 0), "connect_uri")));
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "ciba_message=complete"), 1);
  o_free(url);
  json_decref(j_body);

  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  r_jwk_free(j_dpop_pub);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                                       U_OPT_POST_BODY_PARAMETER, "auth_req_id", auth_req_id,
                                                       U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                       U_OPT_NONE), U_OK);
  o_free(dpop_token);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq(auth_req_id, json_string_value(json_object_get(j_body, "auth_req_id")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "access_token")));
  ck_assert_str_eq("DPoP", json_string_value(json_object_get(j_body, "token_type")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "refresh_token")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "id_token")));
  ck_assert_ptr_ne(NULL, jwt = r_jwt_quick_parse(json_string_value(json_object_get(j_body, "access_token")), R_PARSE_NONE, 0));
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  ck_assert_str_eq(SCOPE_LIST, r_jwt_get_claim_str_value(jwt, "scope"));
  r_jwt_free(jwt);

  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
  r_jwk_free(jwk_dpop_priv);
  o_free(auth_req_id);
  json_decref(j_body);
  json_decref(j_cnf);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_dpop_ciba_poll_with_jkt_and_dpop_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body, * j_cnf, * j_dpop_pub;
  char * url, * auth_req_id, jti[17], * dpop_token, * dpop_jkt;
  jwt_t * jwt;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub, * jwk_dpop_priv;

  ck_assert_ptr_ne(NULL, jwk_dpop_priv = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_sign_str));
  ck_assert_ptr_ne(NULL, dpop_jkt = r_jwk_thumbprint(jwk_dpop_priv, R_JWK_THUMB_SHA256, 0));

  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/ciba"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  r_jwk_free(j_dpop_pub);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                       U_OPT_POST_BODY_PARAMETER, "dpop_jkt", dpop_jkt,
                                                       U_OPT_NONE), U_OK);
  o_free(dpop_token);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, auth_req_id = o_strdup(json_string_value(json_object_get(j_body, "auth_req_id"))));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_body);
  o_free(dpop_jkt);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  url = msprintf("%s&g_continue", json_string_value(json_object_get(json_array_get(j_body, 0), "connect_uri")));
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "ciba_message=complete"), 1);
  o_free(url);
  json_decref(j_body);

  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                                       U_OPT_POST_BODY_PARAMETER, "auth_req_id", auth_req_id,
                                                       U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                       U_OPT_NONE), U_OK);
  o_free(dpop_token);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq(auth_req_id, json_string_value(json_object_get(j_body, "auth_req_id")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "access_token")));
  ck_assert_str_eq("DPoP", json_string_value(json_object_get(j_body, "token_type")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "refresh_token")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "id_token")));
  ck_assert_ptr_ne(NULL, jwt = r_jwt_quick_parse(json_string_value(json_object_get(j_body, "access_token")), R_PARSE_NONE, 0));
  ck_assert_ptr_ne(NULL, j_cnf = r_jwt_get_claim_json_t_value(jwt, "cnf"));
  ck_assert_int_gt(json_string_length(json_object_get(j_cnf, "jkt")), 0);
  ck_assert_str_eq(SCOPE_LIST, r_jwt_get_claim_str_value(jwt, "scope"));
  r_jwt_free(jwt);

  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_pub);
  r_jwk_free(jwk_dpop_priv);
  o_free(auth_req_id);
  json_decref(j_body);
  json_decref(j_cnf);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_dpop_ciba_poll_with_jkt_and_dpop_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_dpop_pub;
  char jti[17], * dpop_token, * dpop_jkt;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub, * jwk_dpop_priv;

  ck_assert_ptr_ne(NULL, jwk_dpop_pub = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_pubkey_sign_str_2));
  ck_assert_ptr_ne(NULL, dpop_jkt = r_jwk_thumbprint(jwk_dpop_pub, R_JWK_THUMB_SHA256, 0));
  r_jwk_free(jwk_dpop_pub);
  ck_assert_ptr_ne(NULL, jwk_dpop_priv = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_sign_str));

  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/ciba"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  r_jwk_free(jwk_dpop_pub);
  r_jwk_free(j_dpop_pub);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                       U_OPT_POST_BODY_PARAMETER, "dpop_jkt", dpop_jkt,
                                                       U_OPT_NONE), U_OK);
  o_free(dpop_token);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(dpop_jkt);

  r_jwt_free(jwt_dpop);
  r_jwk_free(jwk_dpop_priv);
}
END_TEST

START_TEST(test_oidc_dpop_ciba_poll_inconsistent)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body, * j_dpop_pub;
  char * url, * auth_req_id, jti[17], * dpop_token;
  jwt_t * jwt_dpop;
  jwk_t * jwk_dpop_pub;

  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  r_jwk_free(jwk_dpop_pub);
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/ciba"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  r_jwt_free(jwt_dpop);
  r_jwk_free(j_dpop_pub);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                       U_OPT_NONE), U_OK);
  o_free(dpop_token);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, auth_req_id = o_strdup(json_string_value(json_object_get(j_body, "auth_req_id"))));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  url = msprintf("%s&g_continue", json_string_value(json_object_get(json_array_get(j_body, 0), "connect_uri")));
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "ciba_message=complete"), 1);
  o_free(url);
  json_decref(j_body);

  ck_assert_int_eq(r_jwk_init(&jwk_dpop_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dpop_pub, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(NULL, j_dpop_pub = r_jwk_export_to_json_t(jwk_dpop_pub));
  ck_assert_int_eq(r_jwt_init(&jwt_dpop), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_dpop, jwk_privkey_sign_str_2, NULL), RHN_OK);
  rand_jti(jti);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_dpop, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "jti", jti), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htm", "POST"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt_dpop, "htu", SERVER_URI "/" PLUGIN_NAME "/token"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub), RHN_OK);
  ck_assert_ptr_ne(NULL, dpop_token = r_jwt_serialize_signed(jwt_dpop, NULL, 0));
  r_jwt_free(jwt_dpop);
  r_jwk_free(j_dpop_pub);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                                       U_OPT_POST_BODY_PARAMETER, "auth_req_id", auth_req_id,
                                                       U_OPT_HEADER_PARAMETER, "DPoP", dpop_token,
                                                       U_OPT_NONE), U_OK);
  o_free(dpop_token);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);

  r_jwk_free(jwk_dpop_pub);
  o_free(auth_req_id);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_dpop_delete_client)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_dpop_delete_plugin)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc dpop");
  tc_core = tcase_create("test_oidc_dpop");
  tcase_add_test(tc_core, test_oidc_dpop_add_plugin);
  tcase_add_test(tc_core, test_oidc_dpop_add_client_confidential_ok);
  tcase_add_test(tc_core, test_oidc_dpop_get_at_with_jkt_invalid);
  tcase_add_test(tc_core, test_oidc_dpop_get_at_with_jkt_jti_replay);
  tcase_add_test(tc_core, test_oidc_dpop_get_at_with_jkt);
  tcase_add_test(tc_core, test_oidc_dpop_refresh_at_with_jkt);
  tcase_add_test(tc_core, test_oidc_dpop_refresh_at_with_invalid_jkt);
  tcase_add_test(tc_core, test_oidc_dpop_refresh_at_without_jkt);
  tcase_add_test(tc_core, test_oidc_dpop_get_at_with_jkt_in_auth);
  tcase_add_test(tc_core, test_oidc_dpop_get_at_with_jkt_in_auth_invalid);
  tcase_add_test(tc_core, test_oidc_dpop_userinfo_with_jkt_invalid);
  tcase_add_test(tc_core, test_oidc_dpop_userinfo_with_jkt);
  tcase_add_test(tc_core, test_oidc_dpop_userinfo_with_jkt_jti_replay);
  tcase_add_test(tc_core, test_oidc_dpop_introspection);
  tcase_add_test(tc_core, test_oidc_dpop_device_verification_valid);
  tcase_add_test(tc_core, test_oidc_dpop_device_verification_with_jkt_invalid);
  tcase_add_test(tc_core, test_oidc_dpop_device_verification_with_jkt_valid);
  tcase_add_test(tc_core, test_oidc_dpop_par_valid);
  tcase_add_test(tc_core, test_oidc_dpop_par_with_jkt_valid);
  tcase_add_test(tc_core, test_oidc_dpop_par_with_dpop_valid);
  tcase_add_test(tc_core, test_oidc_dpop_par_with_dpop_jtk_valid);
  tcase_add_test(tc_core, test_oidc_dpop_par_with_dpop_jtk_inconsistent);
  tcase_add_test(tc_core, test_oidc_dpop_par_with_jkt_invalid);
  tcase_add_test(tc_core, test_oidc_dpop_client_credentials_at_with_jkt);
  tcase_add_test(tc_core, test_oidc_dpop_password_at_with_jkt);
  tcase_add_test(tc_core, test_oidc_dpop_ciba_poll_ok);
  tcase_add_test(tc_core, test_oidc_dpop_ciba_poll_with_jkt_ok);
  tcase_add_test(tc_core, test_oidc_dpop_ciba_poll_with_jkt_and_dpop_ok);
  tcase_add_test(tc_core, test_oidc_dpop_ciba_poll_with_jkt_and_dpop_invalid);
  tcase_add_test(tc_core, test_oidc_dpop_ciba_poll_inconsistent);
  tcase_add_test(tc_core, test_oidc_dpop_delete_client);
  tcase_add_test(tc_core, test_oidc_dpop_add_client_confidential_dpop_mandatory_ok);
  tcase_add_test(tc_core, test_oidc_dpop_client_credentials_at_with_jkt_iat_gap);
  tcase_add_test(tc_core, test_oidc_dpop_client_credentials_at_without_jkt_error);
  tcase_add_test(tc_core, test_oidc_dpop_delete_plugin);
  tcase_add_test(tc_core, test_oidc_dpop_add_plugin_nonce);
  tcase_add_test(tc_core, test_oidc_dpop_get_at_with_jkt_and_nonce);
  tcase_add_test(tc_core, test_oidc_dpop_get_at_with_jkt_invalid_nonce);
  tcase_add_test(tc_core, test_oidc_dpop_client_credentials_at_with_jkt_and_nonce_and_nonce_updated);
  tcase_add_test(tc_core, test_oidc_dpop_delete_client);
  tcase_add_test(tc_core, test_oidc_dpop_delete_plugin);
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
        ulfius_clean_response(&scope_resp);
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
  
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&scope_req, j_body);
  json_decref(j_body);
  if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
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

/* Public domain, no copyright. Use at your own risk. */

/**
 *
 * This test is used to validate one user backend module that will be created upon start and deleted after
 * The user backend must be in write mode
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"
#include "../src/glewlwyd-common.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define PLUGIN_NAME "oidc_claims"
#define INTROSPECT_SCOPE "g_admin"

struct _u_request admin_req;

START_TEST(test_oidc_discovery_default_test)
{
  json_t * j_result = json_loads("{\"issuer\":\"https://glewlwyd.tld\",\"authorization_endpoint\":\"http://localhost:4593/api/oidc/auth\",\"token_endpoint\":\"http://localhost:4593/api/oidc/token\",\"userinfo_endpoint\":\"http://localhost:4593/api/oidc/userinfo\",\"jwks_uri\":\"http://localhost:4593/api/oidc/jwks\",\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"],\"id_token_signing_alg_values_supported\":[\"HS256\"],\"scopes_supported\":[\"openid\"],\"response_types_supported\":[\"code\",\"id_token\",\"token id_token\",\"code id_token\",\"code token id_token\",\"none\",\"password\",\"token\",\"client_credentials\",\"refresh_token\"],\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\"],\"grant_types_supported\":[\"authorization_code\",\"implicit\"],\"display_values_supported\":[\"page\",\"popup\",\"touch\",\"wap\"],\"claim_types_supported\":[\"normal\"],\"claims_parameter_supported\":true,\"claims_supported\":[],\"ui_locales_supported\":[\"en\",\"fr\",\"nl\"],\"request_parameter_supported\":true,\"request_uri_parameter_supported\":true,\"require_request_uri_registration\":false,\"subject_types_supported\":[\"public\"]}", JSON_DECODE_ANY, NULL);
  
  ck_assert_ptr_ne(j_result, NULL);
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/oidc/.well-known/openid-configuration", NULL, NULL, NULL, NULL, 200, j_result, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/oidc/jwks", NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  json_decref(j_result);
}
END_TEST

START_TEST(test_oidc_discovery_add_plugin)
{
  json_t * j_param = json_pack("{sssssss{sssssssssssisisisososososososososssss[{ssssso}{ssssso}]sssss{ssss}s[ssss]s[s]sosososos[s]so}}",
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
                                  "rsa",
                                  "jwt-key-size",
                                  "256",
                                  "key",
                                  "-----BEGIN PRIVATE KEY-----\n"
                                  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDC2kwAziXUf33m\n"
                                  "iqWp0yG6o259+nj7hpQLC4UT0Hmz0wmvreDJ/yNbSgOvsxvVdvzL2IaRZ+Gi5mo0\n"
                                  "lswWvL6IGz7PZO0kXTq9sdBnNqMOx27HddV9e/2/p0MgibJTbgywY2Sk23QYhJpq\n"
                                  "Kq/nU0xlBfSaI5ddZ2RC9ZNkVeGawUKYksTruhAVJqviHN8BoK6VowP5vcxyyOWH\n"
                                  "TK9KruDqzCIhqwRTeo0spokBkTN/LCuhVivcHAzUiJVtB4qAiTI9L/zkzhjpKz9P\n"
                                  "45aLU54rj011gG8U/6E1USh5nMnPkr+d3oLfkhfS3Zs3kJVdyFQWZpQxiTaI92Fd\n"
                                  "2wLvbS0HAgMBAAECggEAD8dTnkETSSjlzhRuI9loAtAXM3Zj86JLPLW7GgaoxEoT\n"
                                  "n7lJ2bGicFMHB2ROnbOb9vnas82gtOtJsGaBslmoaCckp/C5T1eJWTEb+i+vdpPp\n"
                                  "wZcmKZovyyRFSE4+NYlU17fEv6DRvuaGBpDcW7QgHJIl45F8QWEM+msee2KE+V4G\n"
                                  "z/9vAQ+sOlvsb4mJP1tJIBx9Lb5loVREwCRy2Ha9tnWdDNar8EYkOn8si4snPT+E\n"
                                  "3ZCy8mlcZyUkZeiS/HdtydxZfoiwrSRYamd1diQpPhWCeRteQ802a7ds0Y2YzgfF\n"
                                  "UaYjNuRQm7zA//hwbXS7ELPyNMU15N00bajlG0tUOQKBgQDnLy01l20OneW6A2cI\n"
                                  "DIDyYhy5O7uulsaEtJReUlcjEDMkin8b767q2VZHb//3ZH+ipnRYByUUyYUhdOs2\n"
                                  "DYRGGeAebnH8wpTT4FCYxUsIUpDfB7RwfdBONgaKewTJz/FPswy1Ye0b5H2c6vVi\n"
                                  "m2FZ33HQcoZ3wvFFqyGVnMzpOwKBgQDXxL95yoxUGKa8vMzcE3Cn01szh0dFq0sq\n"
                                  "cFpM+HWLVr84CItuG9H6L0KaStEEIOiJsxOVpcXfFFhsJvOGhMA4DQTwH4WuXmXp\n"
                                  "1PoVMDlV65PYqvhzwL4+QhvZO2bsrEunITXOmU7CI6kilnAN3LuP4HbqZgoX9lqP\n"
                                  "I31VYzLupQKBgGEYck9w0s/xxxtR9ILv5XRnepLdoJzaHHR991aKFKjYU/KD7JDK\n"
                                  "INfoAhGs23+HCQhCCtkx3wQVA0Ii/erM0II0ueluD5fODX3TV2ZibnoHW2sgrEsW\n"
                                  "vFcs36BnvIIaQMptc+f2QgSV+Z/fGsKYadG6Q+39O7au/HB7SHayzWkjAoGBAMgt\n"
                                  "Fzslp9TpXd9iBWjzfCOnGUiP65Z+GWkQ/SXFqD+SRir0+m43zzGdoNvGJ23+Hd6K\n"
                                  "TdQbDJ0uoe4MoQeepzoZEgi4JeykVUZ/uVfo+nh06yArVf8FxTm7WVzLGGzgV/uA\n"
                                  "+wtl/cRtEyAsk1649yW/KHPEIP8kJdYAJeoO8xSlAoGAERMrkFR7KGYZG1eFNRdV\n"
                                  "mJMq+Ibxyw8ks/CbiI+n3yUyk1U8962ol2Q0T4qjBmb26L5rrhNQhneM4e8mo9FX\n"
                                  "LlQapYkPvkdrqW0Bp72A/UNAvcGTmN7z5OCJGMUutx2hmEAlrYmpLKS8pM/p9zpK\n"
                                  "tEOtzsP5GMDYVlEp1jYSjzQ=\n"
                                  "-----END PRIVATE KEY-----",
                                  "cert",
                                  "-----BEGIN PUBLIC KEY-----\n"
                                  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtpMAM4l1H995oqlqdMh\n"
                                  "uqNuffp4+4aUCwuFE9B5s9MJr63gyf8jW0oDr7Mb1Xb8y9iGkWfhouZqNJbMFry+\n"
                                  "iBs+z2TtJF06vbHQZzajDsdux3XVfXv9v6dDIImyU24MsGNkpNt0GISaaiqv51NM\n"
                                  "ZQX0miOXXWdkQvWTZFXhmsFCmJLE67oQFSar4hzfAaCulaMD+b3Mcsjlh0yvSq7g\n"
                                  "6swiIasEU3qNLKaJAZEzfywroVYr3BwM1IiVbQeKgIkyPS/85M4Y6Ss/T+OWi1Oe\n"
                                  "K49NdYBvFP+hNVEoeZzJz5K/nd6C35IX0t2bN5CVXchUFmaUMYk2iPdhXdsC720t\n"
                                  "BwIDAQAB\n"
                                  "-----END PUBLIC KEY-----",
                                  "access-token-duration",
                                  3600,
                                  "refresh-token-duration",
                                  1209600,
                                  "code-duration",
                                  600,
                                  "refresh-token-rolling",
                                  json_true(),
                                  "allow-non-oidc",
                                  json_false(),
                                  "auth-type-code-enabled",
                                  json_true(),
                                  "auth-type-token-enabled",
                                  json_true(),
                                  "auth-type-none-enabled",
                                  json_true(),
                                  "auth-type-id-token-enabled",
                                  json_true(),
                                  "auth-type-refresh-enabled",
                                  json_true(),
                                  "request-parameter-allow",
                                  json_true(),
                                  "client-pubkey-parameter",
                                  "pubkey",
                                  "subject-type",
                                  "pairwise",
                                  "claims",
                                    "name",
                                    "claim1",
                                    "user-property",
                                    "claim1",
                                    "mandatory",
                                    json_true(),
                                    "name",
                                    "claim2",
                                    "user-property",
                                    "claim2",
                                    "on-demand",
                                    json_true(),
                                  "name-claim",
                                  "mandatory",
                                  "email-claim",
                                  "on-demand",
                                  "address-claim",
                                    "type",
                                    "on-demand",
                                    "formatted",
                                    "formatted-property",
                                  "allowed-scope",
                                    "openid",
                                    "g_profile",
                                    "scope1",
                                    "scope2",
                                  "jwks-x5c",
                                    "-----BEGIN PUBLIC KEY-----\n"
                                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtpMAM4l1H995oqlqdMh\n"
                                    "uqNuffp4+4aUCwuFE9B5s9MJr63gyf8jW0oDr7Mb1Xb8y9iGkWfhouZqNJbMFry+\n"
                                    "iBs+z2TtJF06vbHQZzajDsdux3XVfXv9v6dDIImyU24MsGNkpNt0GISaaiqv51NM\n"
                                    "ZQX0miOXXWdkQvWTZFXhmsFCmJLE67oQFSar4hzfAaCulaMD+b3Mcsjlh0yvSq7g\n"
                                    "6swiIasEU3qNLKaJAZEzfywroVYr3BwM1IiVbQeKgIkyPS/85M4Y6Ss/T+OWi1Oe\n"
                                    "K49NdYBvFP+hNVEoeZzJz5K/nd6C35IX0t2bN5CVXchUFmaUMYk2iPdhXdsC720t\n"
                                    "BwIDAQAB\n"
                                    "-----END PUBLIC KEY-----",
                                  "pkce-allowed",
                                  json_true(),
                                  "pkce-method-plain-allowed",
                                  json_true(),
                                  "introspection-revocation-allowed",
                                  json_true(),
                                  "introspection-revocation-allow-target-client",
                                  json_true(),
                                  "introspection-revocation-auth-scope",
                                  INTROSPECT_SCOPE,
                                  "register-client-allowed",
                                  json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_discovery_new_plugin_test)
{
  json_t * j_result = json_loads("{\"issuer\":\"https://glewlwyd.tld\",\"authorization_endpoint\":\"http://localhost:4593/api/oidc_claims/auth\",\"token_endpoint\":\"http://localhost:4593/api/oidc_claims/token\",\"userinfo_endpoint\":\"http://localhost:4593/api/oidc_claims/userinfo\",\"jwks_uri\":\"http://localhost:4593/api/oidc_claims/jwks\",\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\",\"private_key_jwt\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"userinfo_signing_alg_values_supported\":[\"RS256\"],\"userinfo_encryption_alg_values_supported\":[\"RSA1_5\",\"A128KW\",\"A256KW\",\"dir\"],\"userinfo_encryption_enc_values_supported\":[\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\",\"A128GCM\",\"A256GCM\"],\"request_object_signing_alg_values_supported\":[\"none\",\"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\",\"EdDSA\",\"PS256\",\"PS384\",\"PS512\"],\"request_object_encryption_alg_values_supported\":[\"RSA1_5\",\"A128KW\",\"A256KW\",\"dir\"],\"request_object_encryption_enc_values_supported\":[\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\",\"A128GCM\",\"A256GCM\"],\"token_endpoint_auth_signing_alg_values_supported\":[\"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\",\"EdDSA\",\"PS256\",\"PS384\",\"PS512\"],\"scopes_supported\":[\"openid\",\"g_profile\",\"scope1\",\"scope2\"],\"response_types_supported\":[\"code\",\"id_token\",\"token id_token\",\"code id_token\",\"code token id_token\",\"none\",\"refresh_token\"],\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\"],\"grant_types_supported\":[\"authorization_code\",\"implicit\"],\"display_values_supported\":[\"page\",\"popup\",\"touch\",\"wap\"],\"claim_types_supported\":[\"normal\"],\"claims_parameter_supported\":true,\"claims_supported\":[\"claim1\",\"claim2\",\"name\",\"email\",\"address\"],\"ui_locales_supported\":[\"en\",\"fr\",\"nl\"],\"request_parameter_supported\":true,\"request_uri_parameter_supported\":true,\"require_request_uri_registration\":false,\"subject_types_supported\":[\"pairwise\"],\"code_challenge_methods_supported\":[\"S256\",\"plain\"],\"revocation_endpoint\":\"http://localhost:4593/api/oidc_claims/revoke\",\"introspection_endpoint\":\"http://localhost:4593/api/oidc_claims/introspect\",\"revocation_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"bearer\"],\"introspection_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"bearer\"],\"registration_endpoint\":\"http://localhost:4593/api/oidc_claims/register\"}", JSON_DECODE_ANY, NULL),
  * j_key = json_loads("{\"keys\":[{\"use\":\"sig\",\"alg\":\"RS256\",\"x5c\":[\"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtpMAM4l1H995oqlqdMh\\nuqNuffp4+4aUCwuFE9B5s9MJr63gyf8jW0oDr7Mb1Xb8y9iGkWfhouZqNJbMFry+\\niBs+z2TtJF06vbHQZzajDsdux3XVfXv9v6dDIImyU24MsGNkpNt0GISaaiqv51NM\\nZQX0miOXXWdkQvWTZFXhmsFCmJLE67oQFSar4hzfAaCulaMD+b3Mcsjlh0yvSq7g\\n6swiIasEU3qNLKaJAZEzfywroVYr3BwM1IiVbQeKgIkyPS/85M4Y6Ss/T+OWi1Oe\\nK49NdYBvFP+hNVEoeZzJz5K/nd6C35IX0t2bN5CVXchUFmaUMYk2iPdhXdsC720t\\nBwIDAQAB\\n-----END PUBLIC KEY-----\"],\"kid\":\"h7uJEqXw_h4UXW_wCm3oBuboSGyuxf7XucGDKohPwxo\",\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"AMLaTADOJdR_feaKpanTIbqjbn36ePuGlAsLhRPQebPTCa-t4Mn_I1tKA6-zG9V2_MvYhpFn4aLmajSWzBa8vogbPs9k7SRdOr2x0Gc2ow7Hbsd11X17_b-nQyCJslNuDLBjZKTbdBiEmmoqr-dTTGUF9Jojl11nZEL1k2RV4ZrBQpiSxOu6EBUmq-Ic3wGgrpWjA_m9zHLI5YdMr0qu4OrMIiGrBFN6jSymiQGRM38sK6FWK9wcDNSIlW0HioCJMj0v_OTOGOkrP0_jlotTniuPTXWAbxT_oTVRKHmcyc-Sv53egt-SF9LdmzeQlV3IVBZmlDGJNoj3YV3bAu9tLQc\"}]}", JSON_DECODE_ANY, NULL);
  
  ck_assert_ptr_ne(j_result, NULL);
  ck_assert_ptr_ne(j_key, NULL);
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/" PLUGIN_NAME "/.well-known/openid-configuration", NULL, NULL, NULL, NULL, 200, j_result, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/" PLUGIN_NAME "/jwks", NULL, NULL, NULL, NULL, 200, j_key, NULL, NULL), 1);
  
  json_decref(j_result);
  json_decref(j_key);
}
END_TEST

START_TEST(test_oidc_discovery_delete_plugin)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc discovery");
  tc_core = tcase_create("test_oidc_discovery");
  tcase_add_test(tc_core, test_oidc_discovery_default_test);
  tcase_add_test(tc_core, test_oidc_discovery_add_plugin);
  tcase_add_test(tc_core, test_oidc_discovery_new_plugin_test);
  tcase_add_test(tc_core, test_oidc_discovery_delete_plugin);
  tcase_set_timeout(tc_core, 90);
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
  int res, do_test = 0;
  json_t * j_body;
  char * cookie;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  ulfius_init_request(&admin_req);
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
      cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
      u_map_put(admin_req.map_header, "Cookie", cookie);
      o_free(cookie);
      do_test = 1;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
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
    
  ulfius_clean_request(&admin_req);
  y_close_logs();
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>
#include <iddawc.h>
#include <orcania.h>
#include <yder.h>
#include <iddawc_resource.h>

#include "unit-tests.h"

#define PORT 8080
#define SCOPE "scope_auth"
#define MAX_IAT 600
#define ISSUER "https://glewlwyd.tld"
#define EXPIRES_IN 3600
#define CLIENT_ID "client1"

const char access_token_pattern[] =
"{\"iat\":%lld"
",\"exp\":%lld"
",\"iss\":\"%s\""
",\"sub\":\"wRNaPT1UBIw4Cl9eo3yOzoH7vE81Phfu\""
",\"client_id\":\""CLIENT_ID"\""
",\"scope\":\""SCOPE"\""
",\"jti\":\"vE81Phfuw3yOzoH7RNaPT1UBIw4Cl9eo\"}";

const char jwk_pubkey_rsa_str_1[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                    "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                    "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                    ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str_1[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                     "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                     "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                     "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                                     "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                                     "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                                     "C8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                                     "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                                     "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                                     "k\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                                     "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                                     "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                                     "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                     "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_pubkey_fool_str[] = "{\"kty\":\"RSA\",\"n\":\"ANgV1GxZbGBMIqqX5QsNrQQnPLk8UpkqH_60EuaHsI8YnUkPmPVXJ_4z_ziqZizvvjp_RhhXX2DnHEQuYwI-SZaBlK1VJiiWH9E"\
                                   "XrUeazcpEryFUR0I5iBROcgRJfHSvRvC7D83-xg9xC-NGVvIQ2llduYzmaK8rfuiHWlGqow3O2m5os9NTortdQf7BeTniStDokFvZy-I4i24UFkemoNPWZ9MCN0"\
                                    "WTea8n_TQmq9sVHGQtLIFqfblLxbSz_7m4g7_o3WfqlwXkVmCIu1wdzAjZV5BspBGrL0ed5Whpk9-bX69nUDvpcMAaPhuRwZ43e9koVRbVwXCNkne98VAs0_U\""\
                                   ",\"e\":\"AQAB\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_fool_str[] = "{\"kty\":\"RSA\",\"n\":\"ANgV1GxZbGBMIqqX5QsNrQQnPLk8UpkqH_60EuaHsI8YnUkPmPVXJ_4z_ziqZizvvjp_RhhXX2DnHEQuYwI-SZaBlK1VJiiWH9E"\
                                    "XrUeazcpEryFUR0I5iBROcgRJfHSvRvC7D83-xg9xC-NGVvIQ2llduYzmaK8rfuiHWlGqow3O2m5os9NTortdQf7BeTniStDokFvZy-I4i24UFkemoNPWZ9MCN0"\
                                    "WTea8n_TQmq9sVHGQtLIFqfblLxbSz_7m4g7_o3WfqlwXkVmCIu1wdzAjZV5BspBGrL0ed5Whpk9-bX69nUDvpcMAaPhuRwZ43e9koVRbVwXCNkne98VAs0_U\""\
                                    ",\"e\":\"AQAB\",\"d\":\"AKOVsyDreb5VJRFcuIrrqYWxZqkc37MQTvR1wrE_HAzYp4n-AuAJQT-Sga6WYY-3V53VaG1ZB93GWIHNVCsImJEWPEYUZjTnoeK"\
                                    "bOBUzPoPYB3UF5oReJYSp9msEbvGvF9d65fYe4DYkcMl4IK5Uz9hDugrPC4VBOmwyu8-DjLkP8OH-N2-KhJvX_kLKgivfzD3KOp6wryLnKuZYn8N4E6rCiNSfKM"\
                                    "goM60bSHRNi0QHYB2jwqMU5T5EzdpD3Tu_ow6a-sXrW6SG1dtbuStck9hFcQ-QtRCeWoM5pFN8cKOsWBZd1unq-X3gMlCjdXUBUW7BYP44lpYsg1v9l_Ww64E\""\
                                    ",\"p\":\"ANmlFUVM-836aC-wK-DekE3s3gl7GZ-9Qca8iKnaIeMszgyaLYkkbYNPpjjsiQHc37IG3axCaywK40PZqODzovL5PnUpwfNrnlMaI042rNaf8q1L4k"\
                                    "vaBTkbO9Wbj0sTLMPt1frLQKBRsNDsYamRcL1SwvTC4aI7cgZBrNIBdPiR\",\"q\":\"AP4qYxRNGaI3aeZh5hgKPSGW82X8Ai2MzIKjzSDYmKGcD9HPRV0dAU"\
                                    "mDCvqyjwCD6tL9iMtZKPz7VK66-KvV1n91WLMDtRzWs_eFFyDY7BYw47o6IQoZ2RxBT3-7WLhlFflaEner8k23zpGOjZbyzt0SIWRAYR0zlb7LrS_X4fcl\",\""\
                                    "qi\":\"fnlvhYXAn6V0X6gmlwooZUWo9bR7ObChNhrUzMVDOReUVOrzOhlzGhBW1TEFBBr8k44ZWBCTeVEQh--LFHwVvCgEjDBxfjUPUMkeyKZzLhpIUB_cFBAg"\
                                    "I7Fyy0yuPpY0mS1PfMt5Y4b6g_JvdBWZZ8VhTcCVG7qDqoH_IJMXPNg\",\"dp\":\"EAsiQUSGf02JJpLG-UGOw5_FUk-XuPW7honZTSP-QX_JBJbM6oIb7IUP"\
                                    "jLyq8M82Uio9ZvhSbCG1VQgTcdmj1mNXHk3gtS_msNuJZLeVEBEkU2_3k33TyrzeMUXRT0hvkVXT4zPeZLMA5LW4EUbeV6ZlJqPC_DGDm0B2G9jtpXE\",\"dq"\
                                    "\":\"AMTictPUEcpOILO9HG985vPxKeTTfaBpVDbSymDqR_nQmZSOeg3yHQAkCco_rXTZu3rruR7El3K5AlVEMsNxp3IepbIuagrH6qsPpuXkA6YBAzdMNjHL6h"\
                                    "nwIbQxnT1h2M7KzklzogRAIT0x706CEmq_06wEDvZ-8j3VKvhHxBwd\",\"kid\":\"2011-04-29\"}";

int callback_asset (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, "Hello World!");
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_resource_no_auth)
{
  struct _u_instance instance;
  struct _iddawc_resource_config iddawc_resource_config;
  jwks_t * j_jwks;
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_ptr_ne(NULL, j_jwks = r_jwks_quick_import(R_IMPORT_JSON_STR, jwk_pubkey_rsa_str_1, R_IMPORT_NONE));
  ck_assert_int_eq(i_jwt_profile_access_token_init_config(&iddawc_resource_config, I_METHOD_HEADER, NULL, NULL, SCOPE, NULL, MAX_IAT), I_TOKEN_OK);
  ck_assert_int_ne(i_jwt_profile_access_token_load_jwks(&iddawc_resource_config, j_jwks, ISSUER), 0);
  ck_assert_int_eq(ulfius_init_instance(&instance, PORT, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/asset", 1, &callback_asset, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "*", NULL, "*", 0, &callback_check_jwt_profile_access_token, (void*)&iddawc_resource_config), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", "",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", "Bearer ",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", "Bearer none",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", "Bearer none.error.help",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  r_jwks_free(j_jwks);
  i_jwt_profile_access_token_close_config(&iddawc_resource_config);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_resource_valid_token)
{
  struct _u_instance instance;
  struct _iddawc_resource_config iddawc_resource_config;
  jwks_t * j_jwks;
  struct _u_request req;
  struct _u_response resp;
  jwt_t * jwt;
  jwk_t * jwk;
  char * token, * bearer, * grants;
  time_t now;
  
  ck_assert_ptr_ne(NULL, j_jwks = r_jwks_quick_import(R_IMPORT_JSON_STR, jwk_pubkey_rsa_str_1, R_IMPORT_NONE));
  ck_assert_int_eq(i_jwt_profile_access_token_init_config(&iddawc_resource_config, I_METHOD_HEADER, NULL, NULL, SCOPE, NULL, MAX_IAT), I_TOKEN_OK);
  ck_assert_int_ne(i_jwt_profile_access_token_load_jwks(&iddawc_resource_config, j_jwks, ISSUER), 0);
  ck_assert_int_eq(ulfius_init_instance(&instance, PORT, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/asset", 1, &callback_asset, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "*", NULL, "*", 0, &callback_check_jwt_profile_access_token, (void*)&iddawc_resource_config), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "scope", SCOPE " scope2"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "scope", "scope2 " SCOPE), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "scope", "scope3 " SCOPE " scope2"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  r_jwks_free(j_jwks);
  i_jwt_profile_access_token_close_config(&iddawc_resource_config);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_resource_invalid_signature)
{
  struct _u_instance instance;
  struct _iddawc_resource_config iddawc_resource_config;
  jwks_t * j_jwks;
  struct _u_request req;
  struct _u_response resp;
  jwt_t * jwt;
  jwk_t * jwk;
  char * token, * token_sig, * bearer, * grants;
  time_t now;
  json_t * j_jwk;
  
  ck_assert_ptr_ne(NULL, j_jwks = r_jwks_quick_import(R_IMPORT_JSON_STR, jwk_pubkey_rsa_str_1, R_IMPORT_NONE));
  ck_assert_int_eq(i_jwt_profile_access_token_init_config(&iddawc_resource_config, I_METHOD_HEADER, NULL, NULL, SCOPE, NULL, MAX_IAT), I_TOKEN_OK);
  ck_assert_int_ne(i_jwt_profile_access_token_load_jwks(&iddawc_resource_config, j_jwks, ISSUER), 0);
  ck_assert_int_eq(ulfius_init_instance(&instance, PORT, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/asset", 1, &callback_asset, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "*", NULL, "*", 0, &callback_check_jwt_profile_access_token, (void*)&iddawc_resource_config), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_fool_str), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne(j_jwk = json_loads(jwk_pubkey_fool_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt, "jwk", j_jwk), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  json_decref(j_jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "scope", "error"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne(token_sig = o_strrchr(token, '.'), NULL);
  token_sig[1] = 'e';
  token_sig[1] = 'r';
  token_sig[1] = 'r';
  token_sig[1] = 'o';
  token_sig[1] = 'r';
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne(token_sig = o_strrchr(token, '.'), NULL);
  token_sig[1] = '\0';
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  r_jwks_free(j_jwks);
  i_jwt_profile_access_token_close_config(&iddawc_resource_config);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_resource_invalid_claims)
{
  struct _u_instance instance;
  struct _iddawc_resource_config iddawc_resource_config;
  jwks_t * j_jwks;
  struct _u_request req;
  struct _u_response resp;
  jwt_t * jwt;
  jwk_t * jwk;
  char * token, * bearer, * grants;
  time_t now;
  
  ck_assert_ptr_ne(NULL, j_jwks = r_jwks_quick_import(R_IMPORT_JSON_STR, jwk_pubkey_rsa_str_1, R_IMPORT_NONE));
  ck_assert_int_eq(i_jwt_profile_access_token_init_config(&iddawc_resource_config, I_METHOD_HEADER, NULL, NULL, SCOPE, NULL, MAX_IAT), I_TOKEN_OK);
  ck_assert_int_ne(i_jwt_profile_access_token_load_jwks(&iddawc_resource_config, j_jwks, ISSUER), 0);
  ck_assert_int_eq(ulfius_init_instance(&instance, PORT, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/asset", 1, &callback_asset, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "*", NULL, "*", 0, &callback_check_jwt_profile_access_token, (void*)&iddawc_resource_config), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  r_jwt_set_claim_str_value(jwt, "iat", NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  r_jwt_set_claim_str_value(jwt, "exp", NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  r_jwt_set_claim_str_value(jwt, "iss", NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  r_jwt_set_claim_str_value(jwt, "sub", NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  r_jwt_set_claim_str_value(jwt, "client_id", NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  r_jwt_set_claim_str_value(jwt, "scope", NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  r_jwt_set_claim_str_value(jwt, "scope", "error");
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  r_jwt_set_claim_str_value(jwt, "jti", NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "kid", "error"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "iat", now+10), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "iat", "error"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "iat", now-60), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "exp", now-10), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "exp", "error"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "iss", "error"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "iss", 42), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "sub", 42), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "client_id", 42), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "scope", "error"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_ptr_ne(jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str_1), NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "scope", 42), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  ck_assert_ptr_ne((bearer = msprintf("Bearer %s", token)), NULL);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, "http://localhost:8080/asset",
                                                       U_OPT_HEADER_PARAMETER, "Authorization", bearer,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 401);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(grants);
  o_free(bearer);
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);

  r_jwks_free(j_jwks);
  i_jwt_profile_access_token_close_config(&iddawc_resource_config);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc resource API authentication tests");
  tc_core = tcase_create("test_iddawc_resource");
  tcase_add_test(tc_core, test_iddawc_resource_no_auth);
  tcase_add_test(tc_core, test_iddawc_resource_valid_token);
  tcase_add_test(tc_core, test_iddawc_resource_invalid_signature);
  tcase_add_test(tc_core, test_iddawc_resource_invalid_claims);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;

  y_init_logs("Iddawc resource test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc resource test");

  s = glewlwyd_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

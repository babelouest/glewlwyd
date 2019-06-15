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
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <cbor.h>
#include <jwt.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api/"
#define USERNAME "user1"
#define PASSWORD "password"
#define SCOPE_LIST "scope1 scope2"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define MODULE_MODULE "webauthn"
#define MODULE_NAME "test_webauthn"
#define MODULE_NAME_2 "test_webauthn_2"
#define MODULE_DISPLAY_NAME "Webauthn scheme for test"
#define MODULE_EXPIRATION 600
#define MODULE_MAX_USE 0

unsigned char credential_id[] = {0x8C, 0x0A, 0x26, 0xFF, 0x22, 0x91, 0xC1, 0xE9, 0xB9, 0x4E, 0x2E, 0x17, 0x1A, 0x98, 0x6A, 0x73, 0x71, 0x9D, 0x43, 0x48, 0xD5, 0xA7, 0x6A, 0x15, 0x7E, 0x38, 0x94, 0x52, 0x77, 0x97, 0x0F, 0xEF, 0x79, 0x50, 0x68, 0x71, 0xDA, 0xEE, 0xEE, 0xB9, 0x94, 0xC3, 0xC2, 0x15, 0x67, 0x65, 0x26, 0x22, 0xE3, 0xF3, 0xAB, 0x3B, 0x78, 0x2E, 0xD5, 0x6F, 0x81, 0x26, 0xE2, 0xA6, 0x01, 0x7D, 0x74, 0x50};
#define WEBAUTHN_CREDENTIAL_ID_LEN 64
#define WEBAUTHN_SESSION_MANDATORY json_false()
#define WEBAUTHN_SEED "8t2w0niodyntwma0wdu8kfdvbcugr4s5s"
#define WEBAUTHN_CHALLENGE_LEN 64
#define WEBAUTHN_CREDENTIAL_EXPIRATION 120
#define WEBAUTHN_CREDENTIAL_ASSERTION 120
#define WEBAUTHN_RP_ORIGIN "https://www.glewlwyd.tld"
#define WEBAUTHN_RP_ID "www.glewlwyd.tld"
#define WEBAUTHN_PUBKEY_CRED_ECDSA_256 -7
#define WEBAUTHN_PUBKEY_CRED_ECDSA_384 -35
#define WEBAUTHN_PUBKEY_CRED_ECDSA_512 -36
#define WEBAUTHN_CTS_PROFILE_MATCH 1
#define WEBAUTHN_BASIC_INTEGRITY 1
#define WEBAUTHN_GOOGLE_ROOT_CA_R2 ""
#define WEBAUTHN_CREDENTIAL_NEW_NAME "new_name"

#define FLAG_USER_PRESENT 0x01
#define FLAG_USER_VERIFY 0x04
#define FLAG_AT 0x40
#define AAGUID {0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57}
#define AAGUID_LEN 16
#define AUTH_DATA_SIZE 1024
#define AUTHENTICATOR_DATA_SIZE 128
#define NONCE_SIZE 256

#define FIDO_CERT_FAKE "-----BEGIN CERTIFICATE-----\
MIIBejCCASGgAwIBAgIUUmwvBcKwJSWZMLC9xtUYQhh/YicwCgYIKoZIzj0EAwIw\
EzERMA8GA1UEAwwIZ2xld2x3eWQwHhcNMTkwNjEyMTY0MjExWhcNMjkwNjA5MTY0\
MjExWjATMREwDwYDVQQDDAhnbGV3bHd5ZDBZMBMGByqGSM49AgEGCCqGSM49AwEH\
A0IABKP9Eu2Rzt15pKqriLiniryG9zsabCq+aNneB+mmIDwRkjaqpKeGwztLEHBG\
TrHh9poToHkaxUuFE/wVD+9GscGjUzBRMB0GA1UdDgQWBBQQv5dX9gxGFfEDD2Zu\
jZQT3FTitDAfBgNVHSMEGDAWgBQQv5dX9gxGFfEDD2ZujZQT3FTitDAPBgNVHRMB\
Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIBqkd3kqcKZ/gEsnAVi5sQR3gB04\
U8JNjzPwv//HmV/FAiBT45X52j1G6QGPg82twWR7CZiHbJPe26drWkkoDeT/QQ==\
-----END CERTIFICATE-----"
#define FIDO_KEY_FAKE "-----BEGIN EC PRIVATE KEY-----\
MHcCAQEEIPXYkuP2+oERZkj7H5AaKrXnCoUaOFnmLx+HFTYqmJUmoAoGCCqGSM49\
AwEHoUQDQgAEo/0S7ZHO3XmkqquIuKeKvIb3OxpsKr5o2d4H6aYgPBGSNqqkp4bD\
O0sQcEZOseH2mhOgeRrFS4UT/BUP70axwQ==\
-----END EC PRIVATE KEY-----"
#define ANDROID_SAFETYNET_CERT_FAKE "-----BEGIN CERTIFICATE-----\
MIIBjjCCATWgAwIBAgIUBBVE8xVCyFVkAKc/ff5IYVGRd4owCgYIKoZIzj0EAwIw\
HTEbMBkGA1UEAwwSYXR0ZXN0LmFuZHJvaWQuY29tMB4XDTE5MDYxMzE3MDcwOVoX\
DTI5MDYxMDE3MDcwOVowHTEbMBkGA1UEAwwSYXR0ZXN0LmFuZHJvaWQuY29tMFkw\
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnPsYjh4EWEVdhKCOI9lPkcRvxbNiTys9\
FNXcuTmru+ezUZBYC8/lrP+ixoAonGXmFHqLk9cO4o4aGHo0/iQbG6NTMFEwHQYD\
VR0OBBYEFNf2H7DiHhwNitBYAYL0naWYtgtJMB8GA1UdIwQYMBaAFNf2H7DiHhwN\
itBYAYL0naWYtgtJMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIg\
IoPfHSMerjoWwZZyK+sUY/2KISXEGV+1eMA1tEJGuxQCIFNUcg86sVutsnc7kg6T\
GlbFDIPM76WpNvWi6HYt1D1H\
-----END CERTIFICATE-----"
#define ANDROID_SAFETYNET_KEY_FAKE "-----BEGIN EC PRIVATE KEY-----\
MHcCAQEEIE6yCbMycRFIsyJVpUAeUB5x38yhVx2H1BYuEjEJnBBEoAoGCCqGSM49\
AwEHoUQDQgAEnPsYjh4EWEVdhKCOI9lPkcRvxbNiTys9FNXcuTmru+ezUZBYC8/l\
rP+ixoAonGXmFHqLk9cO4o4aGHo0/iQbGw==\
-----END EC PRIVATE KEY-----"

#define CREDENTIAL_PRIVATE_KEY "-----BEGIN EC PRIVATE KEY-----\
MHcCAQEEIOIr1e/cc961GGJciBw5vuN2tb+Ys1yIw/Aw7u6L41BSoAoGCCqGSM49\
AwEHoUQDQgAEeP5NOxZTvLehKgiEKn9mtfMB4fnGx73nSDe05IWj44TNtN39dOLs\
EVDDxd9+z2IOshiNs+DSccYGlJUtU7f9FQ==\
-----END EC PRIVATE KEY-----"
#define CREDENTIAL_PUBLIC_KEY "-----BEGIN PUBLIC KEY-----\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeP5NOxZTvLehKgiEKn9mtfMB4fnG\
x73nSDe05IWj44TNtN39dOLsEVDDxd9+z2IOshiNs+DSccYGlJUtU7f9FQ==\
-----END PUBLIC KEY-----"

struct _u_request user_req;
struct _u_request admin_req;

START_TEST(test_glwd_scheme_webauthn_irl_module_add)
{
  json_t * j_parameters = json_pack("{sssssssisis{sosssisisisss[iii]sisiss}}", 
                                    "module", MODULE_MODULE, 
                                    "name", MODULE_NAME, 
                                    "display_name", MODULE_DISPLAY_NAME, 
                                    "expiration", MODULE_EXPIRATION, 
                                    "max_use", MODULE_MAX_USE, 
                                    "parameters", 
                                      "session-mandatory", WEBAUTHN_SESSION_MANDATORY, 
                                      "seed", WEBAUTHN_SEED, 
                                      "challenge-length", WEBAUTHN_CHALLENGE_LEN, 
                                      "credential-expiration", WEBAUTHN_CREDENTIAL_EXPIRATION, 
                                      "credential-assertion", WEBAUTHN_CREDENTIAL_ASSERTION, 
                                      "rp-origin", WEBAUTHN_RP_ORIGIN, 
                                      "pubKey-cred-params", WEBAUTHN_PUBKEY_CRED_ECDSA_256, WEBAUTHN_PUBKEY_CRED_ECDSA_384, WEBAUTHN_PUBKEY_CRED_ECDSA_512, 
                                      "ctsProfileMatch", WEBAUTHN_CTS_PROFILE_MATCH, 
                                      "basicIntegrity", WEBAUTHN_BASIC_INTEGRITY, 
                                      "google-root-ca-r2", WEBAUTHN_GOOGLE_ROOT_CA_R2);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/mod/scheme/" MODULE_NAME, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error)
{
  json_t * j_params;
  
  j_params = json_pack("{sssssss{ss}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "error");
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);
  
  j_params = json_pack("{sssssss{so}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", json_null());
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_new_credential)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * jwt_response = json_pack("{s[{sssi}{sssi}{sssi}]ss}",
                                  "pubKey-cred-params",
                                    "type", "public-key",
                                    "alg", WEBAUTHN_PUBKEY_CRED_ECDSA_256,
                                    "type", "public-key",
                                    "alg", WEBAUTHN_PUBKEY_CRED_ECDSA_384,
                                    "type", "public-key",
                                    "alg", WEBAUTHN_PUBKEY_CRED_ECDSA_512,
                                  "rpId", WEBAUTHN_RP_ORIGIN),
         * j_result, * j_result2;
  struct _u_response resp;
  size_t challenge_len;
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 200, jwt_response, NULL, NULL), 1);
  
  ulfius_init_response(&resp);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  ulfius_clean_response(&resp);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_result2 = ulfius_get_json_body_response(&resp, NULL);
  
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), NULL, &challenge_len), 1);
  ck_assert_int_eq(challenge_len, WEBAUTHN_CHALLENGE_LEN);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result2, "challenge")), json_string_length(json_object_get(j_result2, "challenge")), NULL, &challenge_len), 1);
  ck_assert_int_eq(challenge_len, WEBAUTHN_CHALLENGE_LEN);
  ck_assert_str_ne(json_string_value(json_object_get(j_result, "session")), "");
  ck_assert_str_ne(json_string_value(json_object_get(j_result, "session")), json_string_value(json_object_get(j_result2, "session")));
  ck_assert_str_ne(json_string_value(json_object_get(j_result, "challenge")), json_string_value(json_object_get(j_result2, "challenge")));
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_result2);
  json_decref(jwt_response);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_bad_formed_response)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_credential;
  struct _u_response resp;
  const char * session;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN];
  size_t challenge_dec_len;
  
  ulfius_init_response(&resp);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss ss ss s{ss ss}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", "error",
                              "rawId", "error",
                              "type", "public-key",
                              "response",
                                "attestationObject", "error",
                                "clientDataJSON", "error");
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, NULL, NULL, NULL), 1);

  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_client_data_json_challenge)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{sss{}ssssss}",
                            "challenge",
                            "error",
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("clientDataJSON.challenge invalid");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_client_data_json_hash_alg)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "error",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  ck_assert_ptr_ne(j_client_data, NULL);
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("clientDataJSON.alg invalid");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_client_data_json_rp_origin)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            "error",
                            "type",
                            "webauthn.create");
  ck_assert_ptr_ne(j_client_data, NULL);
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("clientDataJSON.origin invalid - Client send https://www.glewlwyd.tld, required error");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_client_data_json_type)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "error");
  ck_assert_ptr_ne(j_client_data, NULL);
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("clientDataJSON.type invalid");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_rpid)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  auth_data[0]++;
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("authData.rpIdHash invalid");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_flag_at)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT;// | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("authData.Attested credential data not set");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_flag_user_present)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("authData.userPresent not set");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_credential_id)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data[auth_data_len]++;
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("auth_data invalid size");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_credential_id_content)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data[auth_data_len]++;
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid rawId");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_cose_key_invalid_map)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  //cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  cose_pair.value = cbor_build_string("error");
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid COSE key");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_cose_key_invalid_alg)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(42);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid COSE key");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_data_cose_key_key_x_sign)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  //cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid COSE key");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_data_cose_key_key_x_type)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_string("error");
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid COSE key");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_data_cose_key_key_alg)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(42);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid COSE key");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_cose_key_invalid_dump)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data[auth_data_len]++;
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid COSE key");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_att_stmt_map_size)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(5);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("error");
  cose_pair.value = cbor_build_string("error");
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);

  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("CBOR map value 'attStmt' invalid format");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_att_stmt_cert_key)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("error");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("CBOR map value 'x5c' invalid format");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_att_stmt_x5c_size)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(2);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("CBOR map value 'attStmt' invalid format");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_prefix)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 1;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid signature");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_rpid)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data[1]++;
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid signature");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_client_data_hash)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data[verification_data_offset]++;
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid signature");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_client_id)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data[verification_data_offset]++;
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid signature");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_key_prefix)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x05, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid signature");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_key_x)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data[verification_data_offset]++;
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data[verification_data_offset]++;
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid signature");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_key_y)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data[verification_data_offset]++;
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data[verification_data_offset]++;
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid signature");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_size)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data[verification_data_offset]++;
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset-1;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid signature");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_content)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data[verification_data_offset]++;
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  signature.data[0]++;
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Invalid signature");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_key)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data[verification_data_offset]++;
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("error");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("Error sig is not a bytestring");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_att_obj_size)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data[verification_data_offset]++;
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(4);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("attestationObject invalid cbor item");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_auth_data_key)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data[verification_data_offset]++;
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("error");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("authData invalid");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_att_stmt_key)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(3);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data[verification_data_offset]++;
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("error");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  j_error = json_string("CBOR map value 'attStmt' invalid format");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_u2f_success)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, verification_data_offset = 0, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len, rp_id_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, key_x, key_y, signature;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  rp_id_len = auth_data_len;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)FIDO_CERT_FAKE;
  key_data.size = o_strlen(FIDO_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  cose_pair.key = cbor_build_string("x5c");
  cose_pair.value = cbor_new_definite_array(1);
  cbor_array_set(cose_pair.value, 0, cbor_build_bytestring(cert_der, cert_der_len));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, client_data_hash, &client_data_hash_len), GNUTLS_E_SUCCESS);
  verification_data[0] = 0;
  verification_data_offset = 1;
  
  memcpy(verification_data+verification_data_offset, auth_data, rp_id_len);
  verification_data_offset += rp_id_len;
  
  memcpy(verification_data+verification_data_offset, client_data_hash, client_data_hash_len);
  verification_data_offset += client_data_hash_len;
  
  memcpy(verification_data+verification_data_offset, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  verification_data_offset += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  memset(verification_data+verification_data_offset, 0x04, 1);
  verification_data_offset++;
  
  memcpy(verification_data+verification_data_offset, key_x.data, key_x.size);
  verification_data_offset += key_x.size;
  
  memcpy(verification_data+verification_data_offset, key_y.data, key_y.size);
  verification_data_offset += key_y.size;
  
  key_data.data = verification_data;
  key_data.size = verification_data_offset;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  cose_pair.key = cbor_build_string("sig");
  cose_pair.value = cbor_build_bytestring(signature.data, signature.size);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("fido-u2f");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 200, NULL, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_test_assertion_trigger_error_session_invalid)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "trigger-assertion");

  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);

  json_decref(j_params);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_test_assertion_error_session_invalid)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "trigger-assertion"),
         * j_result, * j_client_data, * j_attestation;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTHENTICATOR_DATA_SIZE], auth_data_enc[AUTHENTICATOR_DATA_SIZE*2], * signature_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, client_data_json_hash_len = 32, auth_data_enc_len, signature_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, signature;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.get");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PRIVATE_KEY;
  key_data.size = o_strlen(CREDENTIAL_PRIVATE_KEY);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);

  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTHENTICATOR_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;

  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  client_data_json_hash_len = AUTHENTICATOR_DATA_SIZE - auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, (auth_data+auth_data_len), &client_data_json_hash_len), GNUTLS_E_SUCCESS);
  auth_data_len += client_data_json_hash_len;
  
  ck_assert_int_eq(o_base64_encode(auth_data, 37, auth_data_enc, &auth_data_enc_len), 1);
  
  key_data.data = auth_data;
  key_data.size = auth_data_len;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, NULL, &signature_enc_len), 1);
  ck_assert_ptr_ne((signature_enc = o_malloc(signature_enc_len+1)), NULL);
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, signature_enc, &signature_enc_len), 1);
  
  j_attestation = json_pack("{ss ss ss s{ss ss s{ss% ss% ss s{ss ss ss}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "validate-assertion",
                            "session", session,
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "clientDataJSON", client_data_json_enc,
                                "authenticatorData", auth_data_enc,
                                "signature", signature_enc);
  
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_attestation, NULL, 401, NULL, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_attestation);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_test_assertion_invalid_challenge)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "trigger-assertion"),
         * j_result, * j_client_data, * j_attestation;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTHENTICATOR_DATA_SIZE], auth_data_enc[AUTHENTICATOR_DATA_SIZE*2], * signature_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, client_data_json_hash_len = 32, auth_data_enc_len, signature_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, signature;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{sss{}ssssss}",
                            "challenge",
                            "error",
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.get");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PRIVATE_KEY;
  key_data.size = o_strlen(CREDENTIAL_PRIVATE_KEY);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);

  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTHENTICATOR_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;

  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  client_data_json_hash_len = AUTHENTICATOR_DATA_SIZE - auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, (auth_data+auth_data_len), &client_data_json_hash_len), GNUTLS_E_SUCCESS);
  auth_data_len += client_data_json_hash_len;
  
  ck_assert_int_eq(o_base64_encode(auth_data, 37, auth_data_enc, &auth_data_enc_len), 1);
  
  key_data.data = auth_data;
  key_data.size = auth_data_len;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, NULL, &signature_enc_len), 1);
  ck_assert_ptr_ne((signature_enc = o_malloc(signature_enc_len+1)), NULL);
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, signature_enc, &signature_enc_len), 1);
  
  j_attestation = json_pack("{ss ss ss s{ss ss s{ss% ss% ss s{ss ss ss}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "validate-assertion",
                            "session", session,
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "clientDataJSON", client_data_json_enc,
                                "authenticatorData", auth_data_enc,
                                "signature", signature_enc);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_attestation, NULL, 400, NULL, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_attestation);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_test_assertion_invalid_origin)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "trigger-assertion"),
         * j_result, * j_client_data, * j_attestation;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTHENTICATOR_DATA_SIZE], auth_data_enc[AUTHENTICATOR_DATA_SIZE*2], * signature_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, client_data_json_hash_len = 32, auth_data_enc_len, signature_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, signature;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            "error",
                            "type",
                            "webauthn.get");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PRIVATE_KEY;
  key_data.size = o_strlen(CREDENTIAL_PRIVATE_KEY);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);

  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTHENTICATOR_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;

  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  client_data_json_hash_len = AUTHENTICATOR_DATA_SIZE - auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, (auth_data+auth_data_len), &client_data_json_hash_len), GNUTLS_E_SUCCESS);
  auth_data_len += client_data_json_hash_len;
  
  ck_assert_int_eq(o_base64_encode(auth_data, 37, auth_data_enc, &auth_data_enc_len), 1);
  
  key_data.data = auth_data;
  key_data.size = auth_data_len;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, NULL, &signature_enc_len), 1);
  ck_assert_ptr_ne((signature_enc = o_malloc(signature_enc_len+1)), NULL);
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, signature_enc, &signature_enc_len), 1);
  
  j_attestation = json_pack("{ss ss ss s{ss ss s{ss% ss% ss s{ss ss ss}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "validate-assertion",
                            "session", session,
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "clientDataJSON", client_data_json_enc,
                                "authenticatorData", auth_data_enc,
                                "signature", signature_enc);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_attestation, NULL, 400, NULL, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_attestation);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_test_assertion_invalid_client_data_type)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "trigger-assertion"),
         * j_result, * j_client_data, * j_attestation;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTHENTICATOR_DATA_SIZE], auth_data_enc[AUTHENTICATOR_DATA_SIZE*2], * signature_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, client_data_json_hash_len = 32, auth_data_enc_len, signature_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, signature;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "error");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PRIVATE_KEY;
  key_data.size = o_strlen(CREDENTIAL_PRIVATE_KEY);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);

  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTHENTICATOR_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;

  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  client_data_json_hash_len = AUTHENTICATOR_DATA_SIZE - auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, (auth_data+auth_data_len), &client_data_json_hash_len), GNUTLS_E_SUCCESS);
  auth_data_len += client_data_json_hash_len;
  
  ck_assert_int_eq(o_base64_encode(auth_data, 37, auth_data_enc, &auth_data_enc_len), 1);
  
  key_data.data = auth_data;
  key_data.size = auth_data_len;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, NULL, &signature_enc_len), 1);
  ck_assert_ptr_ne((signature_enc = o_malloc(signature_enc_len+1)), NULL);
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, signature_enc, &signature_enc_len), 1);
  
  j_attestation = json_pack("{ss ss ss s{ss ss s{ss% ss% ss s{ss ss ss}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "validate-assertion",
                            "session", session,
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "clientDataJSON", client_data_json_enc,
                                "authenticatorData", auth_data_enc,
                                "signature", signature_enc);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_attestation, NULL, 400, NULL, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_attestation);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_test_assertion_invalid_client_data_encoded)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "trigger-assertion"),
         * j_result, * j_client_data, * j_attestation;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTHENTICATOR_DATA_SIZE], auth_data_enc[AUTHENTICATOR_DATA_SIZE*2], * signature_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, client_data_json_hash_len = 32, auth_data_enc_len, signature_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, signature;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.get");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  client_data_json[0]++;
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PRIVATE_KEY;
  key_data.size = o_strlen(CREDENTIAL_PRIVATE_KEY);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);

  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTHENTICATOR_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;

  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  client_data_json_hash_len = AUTHENTICATOR_DATA_SIZE - auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, (auth_data+auth_data_len), &client_data_json_hash_len), GNUTLS_E_SUCCESS);
  auth_data_len += client_data_json_hash_len;
  
  ck_assert_int_eq(o_base64_encode(auth_data, 37, auth_data_enc, &auth_data_enc_len), 1);
  
  key_data.data = auth_data;
  key_data.size = auth_data_len;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, NULL, &signature_enc_len), 1);
  ck_assert_ptr_ne((signature_enc = o_malloc(signature_enc_len+1)), NULL);
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, signature_enc, &signature_enc_len), 1);
  
  j_attestation = json_pack("{ss ss ss s{ss ss s{ss% ss% ss s{ss ss ss}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "validate-assertion",
                            "session", session,
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "clientDataJSON", client_data_json_enc,
                                "authenticatorData", auth_data_enc,
                                "signature", signature_enc);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_attestation, NULL, 400, NULL, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_attestation);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_test_assertion_invalid_rp_id_hash)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "trigger-assertion"),
         * j_result, * j_client_data, * j_attestation;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTHENTICATOR_DATA_SIZE], auth_data_enc[AUTHENTICATOR_DATA_SIZE*2], * signature_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, client_data_json_hash_len = 32, auth_data_enc_len, signature_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, signature;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.get");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PRIVATE_KEY;
  key_data.size = o_strlen(CREDENTIAL_PRIVATE_KEY);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);

  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTHENTICATOR_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  auth_data[0]++;
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;

  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  client_data_json_hash_len = AUTHENTICATOR_DATA_SIZE - auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, (auth_data+auth_data_len), &client_data_json_hash_len), GNUTLS_E_SUCCESS);
  auth_data_len += client_data_json_hash_len;
  
  ck_assert_int_eq(o_base64_encode(auth_data, 37, auth_data_enc, &auth_data_enc_len), 1);
  
  key_data.data = auth_data;
  key_data.size = auth_data_len;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, NULL, &signature_enc_len), 1);
  ck_assert_ptr_ne((signature_enc = o_malloc(signature_enc_len+1)), NULL);
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, signature_enc, &signature_enc_len), 1);
  
  j_attestation = json_pack("{ss ss ss s{ss ss s{ss% ss% ss s{ss ss ss}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "validate-assertion",
                            "session", session,
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "clientDataJSON", client_data_json_enc,
                                "authenticatorData", auth_data_enc,
                                "signature", signature_enc);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_attestation, NULL, 400, NULL, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_attestation);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_test_assertion_invalid_flag_user_present)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "trigger-assertion"),
         * j_result, * j_client_data, * j_attestation;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTHENTICATOR_DATA_SIZE], auth_data_enc[AUTHENTICATOR_DATA_SIZE*2], * signature_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, client_data_json_hash_len = 32, auth_data_enc_len, signature_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, signature;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.get");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PRIVATE_KEY;
  key_data.size = o_strlen(CREDENTIAL_PRIVATE_KEY);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);

  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTHENTICATOR_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = 0;
  auth_data_len += 5;

  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  client_data_json_hash_len = AUTHENTICATOR_DATA_SIZE - auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, (auth_data+auth_data_len), &client_data_json_hash_len), GNUTLS_E_SUCCESS);
  auth_data_len += client_data_json_hash_len;
  
  ck_assert_int_eq(o_base64_encode(auth_data, 37, auth_data_enc, &auth_data_enc_len), 1);
  
  key_data.data = auth_data;
  key_data.size = auth_data_len;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, NULL, &signature_enc_len), 1);
  ck_assert_ptr_ne((signature_enc = o_malloc(signature_enc_len+1)), NULL);
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, signature_enc, &signature_enc_len), 1);
  
  j_attestation = json_pack("{ss ss ss s{ss ss s{ss% ss% ss s{ss ss ss}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "validate-assertion",
                            "session", session,
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "clientDataJSON", client_data_json_enc,
                                "authenticatorData", auth_data_enc,
                                "signature", signature_enc);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_attestation, NULL, 400, NULL, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_attestation);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_test_assertion_invalid_client_data_hash)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "trigger-assertion"),
         * j_result, * j_client_data, * j_attestation;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTHENTICATOR_DATA_SIZE], auth_data_enc[AUTHENTICATOR_DATA_SIZE*2], * signature_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, client_data_json_hash_len = 32, auth_data_enc_len, signature_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, signature;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.get");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PRIVATE_KEY;
  key_data.size = o_strlen(CREDENTIAL_PRIVATE_KEY);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);

  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTHENTICATOR_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;

  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  client_data_json_hash_len = AUTHENTICATOR_DATA_SIZE - auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, (auth_data+auth_data_len), &client_data_json_hash_len), GNUTLS_E_SUCCESS);
  auth_data[auth_data_len]++;
  auth_data_len += client_data_json_hash_len;
  
  ck_assert_int_eq(o_base64_encode(auth_data, 37, auth_data_enc, &auth_data_enc_len), 1);
  
  key_data.data = auth_data;
  key_data.size = auth_data_len;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, NULL, &signature_enc_len), 1);
  ck_assert_ptr_ne((signature_enc = o_malloc(signature_enc_len+1)), NULL);
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, signature_enc, &signature_enc_len), 1);
  
  j_attestation = json_pack("{ss ss ss s{ss ss s{ss% ss% ss s{ss ss ss}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "validate-assertion",
                            "session", session,
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "clientDataJSON", client_data_json_enc,
                                "authenticatorData", auth_data_enc,
                                "signature", signature_enc);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_attestation, NULL, 401, NULL, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_attestation);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_test_assertion_invalid_signature)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "trigger-assertion"),
         * j_result, * j_client_data, * j_attestation;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTHENTICATOR_DATA_SIZE], auth_data_enc[AUTHENTICATOR_DATA_SIZE*2], * signature_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, client_data_json_hash_len = 32, auth_data_enc_len, signature_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, signature;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.get");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PRIVATE_KEY;
  key_data.size = o_strlen(CREDENTIAL_PRIVATE_KEY);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);

  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTHENTICATOR_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;

  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  client_data_json_hash_len = AUTHENTICATOR_DATA_SIZE - auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, (auth_data+auth_data_len), &client_data_json_hash_len), GNUTLS_E_SUCCESS);
  auth_data_len += client_data_json_hash_len;
  
  ck_assert_int_eq(o_base64_encode(auth_data, 37, auth_data_enc, &auth_data_enc_len), 1);
  
  key_data.data = auth_data;
  key_data.size = auth_data_len;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  signature.data[0]++;
  
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, NULL, &signature_enc_len), 1);
  ck_assert_ptr_ne((signature_enc = o_malloc(signature_enc_len+1)), NULL);
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, signature_enc, &signature_enc_len), 1);
  
  j_attestation = json_pack("{ss ss ss s{ss ss s{ss% ss% ss s{ss ss ss}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "validate-assertion",
                            "session", session,
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "clientDataJSON", client_data_json_enc,
                                "authenticatorData", auth_data_enc,
                                "signature", signature_enc);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_attestation, NULL, 401, NULL, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_attestation);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_test_assertion_success)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "trigger-assertion"),
         * j_result, * j_client_data, * j_attestation;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTHENTICATOR_DATA_SIZE], auth_data_enc[AUTHENTICATOR_DATA_SIZE*2], * signature_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, client_data_json_hash_len = 32, auth_data_enc_len, signature_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, signature;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.get");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PRIVATE_KEY;
  key_data.size = o_strlen(CREDENTIAL_PRIVATE_KEY);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);

  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTHENTICATOR_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;

  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  client_data_json_hash_len = AUTHENTICATOR_DATA_SIZE - auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, (auth_data+auth_data_len), &client_data_json_hash_len), GNUTLS_E_SUCCESS);
  auth_data_len += client_data_json_hash_len;
  
  ck_assert_int_eq(o_base64_encode(auth_data, 37, auth_data_enc, &auth_data_enc_len), 1);
  
  key_data.data = auth_data;
  key_data.size = auth_data_len;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, NULL, &signature_enc_len), 1);
  ck_assert_ptr_ne((signature_enc = o_malloc(signature_enc_len+1)), NULL);
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, signature_enc, &signature_enc_len), 1);
  
  j_attestation = json_pack("{ss ss ss s{ss ss s{ss% ss% ss s{ss ss ss}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "validate-assertion",
                            "session", session,
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "clientDataJSON", client_data_json_enc,
                                "authenticatorData", auth_data_enc,
                                "signature", signature_enc);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_attestation, NULL, 200, NULL, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_attestation);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_auth_success)
{
  json_t * j_params = json_pack("{ssssss}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME),
         * j_result, * j_client_data, * j_attestation;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTHENTICATOR_DATA_SIZE], auth_data_enc[AUTHENTICATOR_DATA_SIZE*2], * signature_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, client_data_json_hash_len = 32, auth_data_enc_len, signature_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json;
  gnutls_datum_t key_data, signature;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  struct _u_request request;
  
  ulfius_init_request(&request);
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  request.http_verb = o_strdup("POST");
  request.http_url = o_strdup(SERVER_URI "/auth/scheme/trigger/");
  ck_assert_int_eq(ulfius_set_json_body_request(&request, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&request, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.get");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PRIVATE_KEY;
  key_data.size = o_strlen(CREDENTIAL_PRIVATE_KEY);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);

  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTHENTICATOR_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;

  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  client_data_json_hash_len = AUTHENTICATOR_DATA_SIZE - auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, (auth_data+auth_data_len), &client_data_json_hash_len), GNUTLS_E_SUCCESS);
  auth_data_len += client_data_json_hash_len;
  
  ck_assert_int_eq(o_base64_encode(auth_data, 37, auth_data_enc, &auth_data_enc_len), 1);
  
  key_data.data = auth_data;
  key_data.size = auth_data_len;
  
  ck_assert_int_eq(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &key_data, &signature), 0);
  
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, NULL, &signature_enc_len), 1);
  ck_assert_ptr_ne((signature_enc = o_malloc(signature_enc_len+1)), NULL);
  ck_assert_int_eq(o_base64_encode(signature.data, signature.size, signature_enc, &signature_enc_len), 1);
  
  j_attestation = json_pack("{ss ss ss s{ss ss s{ss% ss% ss s{ss ss ss}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "validate-assertion",
                            "session", session,
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "clientDataJSON", client_data_json_enc,
                                "authenticatorData", auth_data_enc,
                                "signature", signature_enc);
  
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "auth/", NULL, NULL, j_attestation, NULL, 200, NULL, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_attestation);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_remove_credential_success)
{
  json_t * j_params;
  unsigned char credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2];
  size_t credential_id_enc_len;
  
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  j_params = json_pack("{sssssss{ssss%}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "remove-credential",
                        "credential_id", credential_id_enc, credential_id_enc_len);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_safetynet_ver_key)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], * att_obj_ser, * att_obj_ser_enc, nonce[NONCE_SIZE], nonce_hash[32], nonce_hash_enc[64], * cert_der_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, att_obj_ser_len, att_obj_ser_enc_len, nonce_len, nonce_hash_len = 32, nonce_hash_enc_len, cert_der_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json, * str_grant, * str_response;
  gnutls_datum_t key_data, key_x, key_y;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  jwt_t * jwt_response;
  json_t  * j_grant;
    
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  cose_pair.key = cbor_build_string("error");
  cose_pair.value = cbor_build_string("14366018");
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)ANDROID_SAFETYNET_CERT_FAKE;
  key_data.size = o_strlen(ANDROID_SAFETYNET_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, NULL, &cert_der_enc_len), 1);
  cert_der_enc = o_malloc(cert_der_enc_len+1);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, cert_der_enc, &cert_der_enc_len), 1);

  ck_assert_int_eq(jwt_new(&jwt_response), 0);
  ck_assert_int_eq(jwt_set_alg(jwt_response, JWT_ALG_ES256, (unsigned char *)ANDROID_SAFETYNET_KEY_FAKE, o_strlen(ANDROID_SAFETYNET_KEY_FAKE)), 0);
  j_grant = json_pack("{sss[s]}",
                      "alg",
                      "RS256",
                      "x5c",
                        cert_der_enc);
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_headers_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  memcpy(nonce, auth_data, auth_data_len);
  nonce_len = NONCE_SIZE-auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce+auth_data_len, &nonce_len), GNUTLS_E_SUCCESS);
  nonce_len += auth_data_len;
  key_data.data = nonce;
  key_data.size = nonce_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce_hash, &nonce_hash_len), GNUTLS_E_SUCCESS);
  
  ck_assert_int_eq(o_base64_encode(nonce_hash, nonce_hash_len, nonce_hash_enc, &nonce_hash_enc_len), 1);
  j_grant = json_pack("{sssisssssosos[s]}",
                      "nonce", nonce_hash_enc,
                      "timestampMs", time(NULL)*1000,
                      "apkPackageName", "com.google.android.gms",
                      "apkDigestSha256", "cGxlYXNlZG9udGRlY29kZW1laW1ub3RhcmVhbGhhc2gK",
                      "ctsProfileMatch", json_true(),
                      "basicIntegrity", json_true(),
                      "apkCertificateDigestSha256",
                        "cGxlYXNlZG9udGRlY29kZW1lZWl0aGVyaXRzZmFrZSEK");
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_grants_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  ck_assert_ptr_ne((str_response = jwt_encode_str(jwt_response)), NULL);
  
  cose_pair.key = cbor_build_string("response");
  cose_pair.value = cbor_build_bytestring((unsigned char *)str_response, o_strlen(str_response));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("android-safetynet");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  j_error = json_string("version invalid");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_safetynet_ver_type)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], * att_obj_ser, * att_obj_ser_enc, nonce[NONCE_SIZE], nonce_hash[32], nonce_hash_enc[64], * cert_der_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, att_obj_ser_len, att_obj_ser_enc_len, nonce_len, nonce_hash_len = 32, nonce_hash_enc_len, cert_der_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json, * str_grant, * str_response;
  gnutls_datum_t key_data, key_x, key_y;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  jwt_t * jwt_response;
  json_t  * j_grant;
    
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  cose_pair.key = cbor_build_string("ver");
  cose_pair.value = cbor_build_uint8(42);
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)ANDROID_SAFETYNET_CERT_FAKE;
  key_data.size = o_strlen(ANDROID_SAFETYNET_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, NULL, &cert_der_enc_len), 1);
  cert_der_enc = o_malloc(cert_der_enc_len+1);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, cert_der_enc, &cert_der_enc_len), 1);

  ck_assert_int_eq(jwt_new(&jwt_response), 0);
  ck_assert_int_eq(jwt_set_alg(jwt_response, JWT_ALG_ES256, (unsigned char *)ANDROID_SAFETYNET_KEY_FAKE, o_strlen(ANDROID_SAFETYNET_KEY_FAKE)), 0);
  j_grant = json_pack("{sss[s]}",
                      "alg",
                      "RS256",
                      "x5c",
                        cert_der_enc);
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_headers_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  memcpy(nonce, auth_data, auth_data_len);
  nonce_len = NONCE_SIZE-auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce+auth_data_len, &nonce_len), GNUTLS_E_SUCCESS);
  nonce_len += auth_data_len;
  key_data.data = nonce;
  key_data.size = nonce_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce_hash, &nonce_hash_len), GNUTLS_E_SUCCESS);
  
  ck_assert_int_eq(o_base64_encode(nonce_hash, nonce_hash_len, nonce_hash_enc, &nonce_hash_enc_len), 1);
  j_grant = json_pack("{sssisssssosos[s]}",
                      "nonce", nonce_hash_enc,
                      "timestampMs", time(NULL)*1000,
                      "apkPackageName", "com.google.android.gms",
                      "apkDigestSha256", "cGxlYXNlZG9udGRlY29kZW1laW1ub3RhcmVhbGhhc2gK",
                      "ctsProfileMatch", json_true(),
                      "basicIntegrity", json_true(),
                      "apkCertificateDigestSha256",
                        "cGxlYXNlZG9udGRlY29kZW1lZWl0aGVyaXRzZmFrZSEK");
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_grants_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  ck_assert_ptr_ne((str_response = jwt_encode_str(jwt_response)), NULL);
  
  cose_pair.key = cbor_build_string("response");
  cose_pair.value = cbor_build_bytestring((unsigned char *)str_response, o_strlen(str_response));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("android-safetynet");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  j_error = json_string("version invalid");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_safetynet_cert)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], * att_obj_ser, * att_obj_ser_enc, nonce[NONCE_SIZE], nonce_hash[32], nonce_hash_enc[64], * cert_der_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, att_obj_ser_len, att_obj_ser_enc_len, nonce_len, nonce_hash_len = 32, nonce_hash_enc_len, cert_der_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json, * str_grant, * str_response;
  gnutls_datum_t key_data, key_x, key_y;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  jwt_t * jwt_response;
  json_t  * j_grant;
    
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  cose_pair.key = cbor_build_string("ver");
  cose_pair.value = cbor_build_string("14366018");
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)ANDROID_SAFETYNET_CERT_FAKE;
  key_data.size = o_strlen(ANDROID_SAFETYNET_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, NULL, &cert_der_enc_len), 1);
  cert_der_enc = o_malloc(cert_der_enc_len+1);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, cert_der_enc, &cert_der_enc_len), 1);
  cert_der_enc[0]++;

  ck_assert_int_eq(jwt_new(&jwt_response), 0);
  ck_assert_int_eq(jwt_set_alg(jwt_response, JWT_ALG_ES256, (unsigned char *)ANDROID_SAFETYNET_KEY_FAKE, o_strlen(ANDROID_SAFETYNET_KEY_FAKE)), 0);
  j_grant = json_pack("{sss[s]}",
                      "alg",
                      "RS256",
                      "x5c",
                        cert_der_enc);
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_headers_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  memcpy(nonce, auth_data, auth_data_len);
  nonce_len = NONCE_SIZE-auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce+auth_data_len, &nonce_len), GNUTLS_E_SUCCESS);
  nonce_len += auth_data_len;
  key_data.data = nonce;
  key_data.size = nonce_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce_hash, &nonce_hash_len), GNUTLS_E_SUCCESS);
  
  ck_assert_int_eq(o_base64_encode(nonce_hash, nonce_hash_len, nonce_hash_enc, &nonce_hash_enc_len), 1);
  j_grant = json_pack("{sssisssssosos[s]}",
                      "nonce", nonce_hash_enc,
                      "timestampMs", time(NULL)*1000,
                      "apkPackageName", "com.google.android.gms",
                      "apkDigestSha256", "cGxlYXNlZG9udGRlY29kZW1laW1ub3RhcmVhbGhhc2gK",
                      "ctsProfileMatch", json_true(),
                      "basicIntegrity", json_true(),
                      "apkCertificateDigestSha256",
                        "cGxlYXNlZG9udGRlY29kZW1lZWl0aGVyaXRzZmFrZSEK");
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_grants_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  ck_assert_ptr_ne((str_response = jwt_encode_str(jwt_response)), NULL);
  
  cose_pair.key = cbor_build_string("response");
  cose_pair.value = cbor_build_bytestring((unsigned char *)str_response, o_strlen(str_response));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("android-safetynet");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  j_error = json_string("Error importing x509 certificate");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_safetynet_cert_missing)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], * att_obj_ser, * att_obj_ser_enc, nonce[NONCE_SIZE], nonce_hash[32], nonce_hash_enc[64], * cert_der_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, att_obj_ser_len, att_obj_ser_enc_len, nonce_len, nonce_hash_len = 32, nonce_hash_enc_len, cert_der_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json, * str_grant, * str_response;
  gnutls_datum_t key_data, key_x, key_y;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  jwt_t * jwt_response;
  json_t  * j_grant;
    
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  cose_pair.key = cbor_build_string("ver");
  cose_pair.value = cbor_build_string("14366018");
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)ANDROID_SAFETYNET_CERT_FAKE;
  key_data.size = o_strlen(ANDROID_SAFETYNET_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, NULL, &cert_der_enc_len), 1);
  cert_der_enc = o_malloc(cert_der_enc_len+1);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, cert_der_enc, &cert_der_enc_len), 1);

  ck_assert_int_eq(jwt_new(&jwt_response), 0);
  ck_assert_int_eq(jwt_set_alg(jwt_response, JWT_ALG_ES256, (unsigned char *)ANDROID_SAFETYNET_KEY_FAKE, o_strlen(ANDROID_SAFETYNET_KEY_FAKE)), 0);
  j_grant = json_pack("{sss[]}",
                      "alg",
                      "RS256",
                      "x5c");
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_headers_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  memcpy(nonce, auth_data, auth_data_len);
  nonce_len = NONCE_SIZE-auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce+auth_data_len, &nonce_len), GNUTLS_E_SUCCESS);
  nonce_len += auth_data_len;
  key_data.data = nonce;
  key_data.size = nonce_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce_hash, &nonce_hash_len), GNUTLS_E_SUCCESS);
  
  ck_assert_int_eq(o_base64_encode(nonce_hash, nonce_hash_len, nonce_hash_enc, &nonce_hash_enc_len), 1);
  j_grant = json_pack("{sssisssssosos[s]}",
                      "nonce", nonce_hash_enc,
                      "timestampMs", time(NULL)*1000,
                      "apkPackageName", "com.google.android.gms",
                      "apkDigestSha256", "cGxlYXNlZG9udGRlY29kZW1laW1ub3RhcmVhbGhhc2gK",
                      "ctsProfileMatch", json_true(),
                      "basicIntegrity", json_true(),
                      "apkCertificateDigestSha256",
                        "cGxlYXNlZG9udGRlY29kZW1lZWl0aGVyaXRzZmFrZSEK");
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_grants_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  ck_assert_ptr_ne((str_response = jwt_encode_str(jwt_response)), NULL);
  
  cose_pair.key = cbor_build_string("response");
  cose_pair.value = cbor_build_bytestring((unsigned char *)str_response, o_strlen(str_response));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("android-safetynet");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  j_error = json_string("response invalid");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_safetynet_nonce_invalid)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], * att_obj_ser, * att_obj_ser_enc, nonce[NONCE_SIZE], nonce_hash[32], nonce_hash_enc[64], * cert_der_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, att_obj_ser_len, att_obj_ser_enc_len, nonce_len, nonce_hash_len = 32, nonce_hash_enc_len, cert_der_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json, * str_grant, * str_response;
  gnutls_datum_t key_data, key_x, key_y;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  jwt_t * jwt_response;
  json_t  * j_grant;
    
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  cose_pair.key = cbor_build_string("ver");
  cose_pair.value = cbor_build_string("14366018");
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)ANDROID_SAFETYNET_CERT_FAKE;
  key_data.size = o_strlen(ANDROID_SAFETYNET_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, NULL, &cert_der_enc_len), 1);
  cert_der_enc = o_malloc(cert_der_enc_len+1);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, cert_der_enc, &cert_der_enc_len), 1);

  ck_assert_int_eq(jwt_new(&jwt_response), 0);
  ck_assert_int_eq(jwt_set_alg(jwt_response, JWT_ALG_ES256, (unsigned char *)ANDROID_SAFETYNET_KEY_FAKE, o_strlen(ANDROID_SAFETYNET_KEY_FAKE)), 0);
  j_grant = json_pack("{sss[s]}",
                      "alg",
                      "RS256",
                      "x5c",
                        cert_der_enc);
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_headers_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  memcpy(nonce, auth_data, auth_data_len);
  nonce_len = NONCE_SIZE-auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce+auth_data_len, &nonce_len), GNUTLS_E_SUCCESS);
  nonce_len += auth_data_len;
  key_data.data = nonce;
  key_data.size = nonce_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce_hash, &nonce_hash_len), GNUTLS_E_SUCCESS);
  
  ck_assert_int_eq(o_base64_encode(nonce_hash, nonce_hash_len, nonce_hash_enc, &nonce_hash_enc_len), 1);
  nonce_hash_enc[0]++;
  j_grant = json_pack("{sssisssssosos[s]}",
                      "nonce", nonce_hash_enc,
                      "timestampMs", time(NULL)*1000,
                      "apkPackageName", "com.google.android.gms",
                      "apkDigestSha256", "cGxlYXNlZG9udGRlY29kZW1laW1ub3RhcmVhbGhhc2gK",
                      "ctsProfileMatch", json_true(),
                      "basicIntegrity", json_true(),
                      "apkCertificateDigestSha256",
                        "cGxlYXNlZG9udGRlY29kZW1lZWl0aGVyaXRzZmFrZSEK");
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_grants_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  ck_assert_ptr_ne((str_response = jwt_encode_str(jwt_response)), NULL);
  
  cose_pair.key = cbor_build_string("response");
  cose_pair.value = cbor_build_bytestring((unsigned char *)str_response, o_strlen(str_response));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("android-safetynet");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  j_error = json_string("response invalid");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_safetynet_jws_invalid)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], * att_obj_ser, * att_obj_ser_enc, nonce[NONCE_SIZE], nonce_hash[32], nonce_hash_enc[64], * cert_der_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, att_obj_ser_len, att_obj_ser_enc_len, nonce_len, nonce_hash_len = 32, nonce_hash_enc_len, cert_der_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json, * str_grant, * str_response;
  gnutls_datum_t key_data, key_x, key_y;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  jwt_t * jwt_response;
  json_t  * j_grant;
    
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  cose_pair.key = cbor_build_string("ver");
  cose_pair.value = cbor_build_string("14366018");
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)ANDROID_SAFETYNET_CERT_FAKE;
  key_data.size = o_strlen(ANDROID_SAFETYNET_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, NULL, &cert_der_enc_len), 1);
  cert_der_enc = o_malloc(cert_der_enc_len+1);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, cert_der_enc, &cert_der_enc_len), 1);

  ck_assert_int_eq(jwt_new(&jwt_response), 0);
  ck_assert_int_eq(jwt_set_alg(jwt_response, JWT_ALG_ES256, (unsigned char *)ANDROID_SAFETYNET_KEY_FAKE, o_strlen(ANDROID_SAFETYNET_KEY_FAKE)), 0);
  j_grant = json_pack("{sss[s]}",
                      "alg",
                      "RS256",
                      "x5c",
                        cert_der_enc);
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_headers_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  memcpy(nonce, auth_data, auth_data_len);
  nonce_len = NONCE_SIZE-auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce+auth_data_len, &nonce_len), GNUTLS_E_SUCCESS);
  nonce_len += auth_data_len;
  key_data.data = nonce;
  key_data.size = nonce_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce_hash, &nonce_hash_len), GNUTLS_E_SUCCESS);
  
  ck_assert_int_eq(o_base64_encode(nonce_hash, nonce_hash_len, nonce_hash_enc, &nonce_hash_enc_len), 1);
  j_grant = json_pack("{sssisssssosos[s]}",
                      "nonce", nonce_hash_enc,
                      "timestampMs", time(NULL)*1000,
                      "apkPackageName", "com.google.android.gms",
                      "apkDigestSha256", "cGxlYXNlZG9udGRlY29kZW1laW1ub3RhcmVhbGhhc2gK",
                      "ctsProfileMatch", json_true(),
                      "basicIntegrity", json_true(),
                      "apkCertificateDigestSha256",
                        "cGxlYXNlZG9udGRlY29kZW1lZWl0aGVyaXRzZmFrZSEK");
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_grants_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  ck_assert_ptr_ne((str_response = jwt_encode_str(jwt_response)), NULL);
  str_response[0]++;
  
  cose_pair.key = cbor_build_string("response");
  cose_pair.value = cbor_build_bytestring((unsigned char *)str_response, o_strlen(str_response));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("android-safetynet");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  j_error = json_string("response invalid");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_safetynet_fmt_invalid_key)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], * att_obj_ser, * att_obj_ser_enc, nonce[NONCE_SIZE], nonce_hash[32], nonce_hash_enc[64], * cert_der_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, att_obj_ser_len, att_obj_ser_enc_len, nonce_len, nonce_hash_len = 32, nonce_hash_enc_len, cert_der_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json, * str_grant, * str_response;
  gnutls_datum_t key_data, key_x, key_y;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  jwt_t * jwt_response;
  json_t  * j_grant;
    
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  cose_pair.key = cbor_build_string("ver");
  cose_pair.value = cbor_build_string("14366018");
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)ANDROID_SAFETYNET_CERT_FAKE;
  key_data.size = o_strlen(ANDROID_SAFETYNET_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, NULL, &cert_der_enc_len), 1);
  cert_der_enc = o_malloc(cert_der_enc_len+1);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, cert_der_enc, &cert_der_enc_len), 1);

  ck_assert_int_eq(jwt_new(&jwt_response), 0);
  ck_assert_int_eq(jwt_set_alg(jwt_response, JWT_ALG_ES256, (unsigned char *)ANDROID_SAFETYNET_KEY_FAKE, o_strlen(ANDROID_SAFETYNET_KEY_FAKE)), 0);
  j_grant = json_pack("{sss[s]}",
                      "alg",
                      "RS256",
                      "x5c",
                        cert_der_enc);
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_headers_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  memcpy(nonce, auth_data, auth_data_len);
  nonce_len = NONCE_SIZE-auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce+auth_data_len, &nonce_len), GNUTLS_E_SUCCESS);
  nonce_len += auth_data_len;
  key_data.data = nonce;
  key_data.size = nonce_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce_hash, &nonce_hash_len), GNUTLS_E_SUCCESS);
  
  ck_assert_int_eq(o_base64_encode(nonce_hash, nonce_hash_len, nonce_hash_enc, &nonce_hash_enc_len), 1);
  j_grant = json_pack("{sssisssssosos[s]}",
                      "nonce", nonce_hash_enc,
                      "timestampMs", time(NULL)*1000,
                      "apkPackageName", "com.google.android.gms",
                      "apkDigestSha256", "cGxlYXNlZG9udGRlY29kZW1laW1ub3RhcmVhbGhhc2gK",
                      "ctsProfileMatch", json_true(),
                      "basicIntegrity", json_true(),
                      "apkCertificateDigestSha256",
                        "cGxlYXNlZG9udGRlY29kZW1lZWl0aGVyaXRzZmFrZSEK");
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_grants_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  ck_assert_ptr_ne((str_response = jwt_encode_str(jwt_response)), NULL);
  
  cose_pair.key = cbor_build_string("response");
  cose_pair.value = cbor_build_bytestring((unsigned char *)str_response, o_strlen(str_response));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("error");
  cose_pair.value = cbor_build_string("android-safetynet");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  j_error = json_string("authData invalid");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_error_safetynet_jws_invalid_signature)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential, * j_error;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], * att_obj_ser, * att_obj_ser_enc, nonce[NONCE_SIZE], nonce_hash[32], nonce_hash_enc[64], * cert_der_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, att_obj_ser_len, att_obj_ser_enc_len, nonce_len, nonce_hash_len = 32, nonce_hash_enc_len, cert_der_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json, * str_grant, * str_response;
  gnutls_datum_t key_data, key_x, key_y;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  jwt_t * jwt_response;
  json_t  * j_grant;
    
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  cose_pair.key = cbor_build_string("ver");
  cose_pair.value = cbor_build_string("14366018");
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)ANDROID_SAFETYNET_CERT_FAKE;
  key_data.size = o_strlen(ANDROID_SAFETYNET_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, NULL, &cert_der_enc_len), 1);
  cert_der_enc = o_malloc(cert_der_enc_len+1);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, cert_der_enc, &cert_der_enc_len), 1);

  ck_assert_int_eq(jwt_new(&jwt_response), 0);
  ck_assert_int_eq(jwt_set_alg(jwt_response, JWT_ALG_ES256, (unsigned char *)ANDROID_SAFETYNET_KEY_FAKE, o_strlen(ANDROID_SAFETYNET_KEY_FAKE)), 0);
  j_grant = json_pack("{sss[s]}",
                      "alg",
                      "RS256",
                      "x5c",
                        cert_der_enc);
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_headers_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  memcpy(nonce, auth_data, auth_data_len);
  nonce_len = NONCE_SIZE-auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce+auth_data_len, &nonce_len), GNUTLS_E_SUCCESS);
  nonce_len += auth_data_len;
  key_data.data = nonce;
  key_data.size = nonce_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce_hash, &nonce_hash_len), GNUTLS_E_SUCCESS);
  
  ck_assert_int_eq(o_base64_encode(nonce_hash, nonce_hash_len, nonce_hash_enc, &nonce_hash_enc_len), 1);
  j_grant = json_pack("{sssisssssosos[s]}",
                      "nonce", nonce_hash_enc,
                      "timestampMs", time(NULL)*1000,
                      "apkPackageName", "com.google.android.gms",
                      "apkDigestSha256", "cGxlYXNlZG9udGRlY29kZW1laW1ub3RhcmVhbGhhc2gK",
                      "ctsProfileMatch", json_true(),
                      "basicIntegrity", json_true(),
                      "apkCertificateDigestSha256",
                        "cGxlYXNlZG9udGRlY29kZW1lZWl0aGVyaXRzZmFrZSEK");
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_grants_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  ck_assert_ptr_ne((str_response = jwt_encode_str(jwt_response)), NULL);
  str_response[o_strlen(str_response)-3]++;
  
  cose_pair.key = cbor_build_string("response");
  cose_pair.value = cbor_build_bytestring((unsigned char *)str_response, o_strlen(str_response));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("android-safetynet");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  j_error = json_string("response invalid");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 400, j_error, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  json_decref(j_error);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_register_safetynet_success)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_result, * j_client_data, * j_credential;
  struct _u_response resp, resp_register;
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], * att_obj_ser, * att_obj_ser_enc, nonce[NONCE_SIZE], nonce_hash[32], nonce_hash_enc[64], * cert_der_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, att_obj_ser_len, att_obj_ser_enc_len, nonce_len, nonce_hash_len = 32, nonce_hash_enc_len, cert_der_enc_len;
  const char * session, * challenge, * user_id, * username, * rpid;
  char * client_data_json, * str_grant, * str_response;
  gnutls_datum_t key_data, key_x, key_y;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_x509_privkey_t key = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_ecc_curve_t curve;
  cbor_item_t * cbor_cose, * att_stmt, * att_obj;
  struct cbor_pair cose_pair;
  jwt_t * jwt_response;
  json_t  * j_grant;
    
  ulfius_init_response(&resp);
  ulfius_init_response(&resp_register);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne((j_result = ulfius_get_json_body_response(&resp, NULL)), NULL);
  ck_assert_ptr_ne((session = json_string_value(json_object_get(j_result, "session"))), NULL);
  ck_assert_ptr_ne((challenge = json_string_value(json_object_get(j_result, "challenge"))), NULL);
  ck_assert_ptr_ne((rpid = json_string_value(json_object_get(j_result, "rpId"))), NULL);
  ck_assert_ptr_ne((user_id = json_string_value(json_object_get(json_object_get(j_result, "user"), "id"))), NULL);
  ck_assert_ptr_ne((username = json_string_value(json_object_get(json_object_get(j_result, "user"), "name"))), NULL);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge_dec, &challenge_dec_len), 1);
  
  // Generate clientDataJSON
  ck_assert_int_eq(o_base64_2_base64url((unsigned char *)challenge, o_strlen(challenge), challenge_b64url, &challenge_b64url_len), 1);
  j_client_data = json_pack("{ss%s{}ssssss}",
                            "challenge",
                            challenge_b64url,
                            challenge_b64url_len,
                            "clientExtensions",
                            "hashAlgorithm",
                            "SHA-256",
                            "origin",
                            WEBAUTHN_RP_ORIGIN,
                            "type",
                            "webauthn.create");
  
  client_data_json = json_dumps(j_client_data, JSON_COMPACT);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), NULL, &client_data_json_enc_len), 1);
  client_data_json_enc = o_malloc(client_data_json_enc_len+1);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, AUTH_DATA_SIZE);
  // Set rpId hash
  key_data.data = (unsigned char *)WEBAUTHN_RP_ID;
  key_data.size = o_strlen(WEBAUTHN_RP_ID);
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, auth_data, &auth_data_len), GNUTLS_E_SUCCESS);
  // Set flags
  *(auth_data+auth_data_len) = FLAG_USER_PRESENT | FLAG_AT;
  auth_data_len += 5;
  // Set aaguid
  memcpy((auth_data+auth_data_len), aaguid, AAGUID_LEN);
  auth_data_len += AAGUID_LEN;
  // Set Credential ID and Credential public key
  ck_assert_int_eq(gnutls_pubkey_init(&pubkey), 0);
  ck_assert_int_eq(gnutls_x509_privkey_init(&key), 0);
  ck_assert_int_eq(gnutls_privkey_init(&privkey), 0);
  key_data.data = (unsigned char *)CREDENTIAL_PUBLIC_KEY;
  key_data.size = o_strlen(CREDENTIAL_PUBLIC_KEY);
  ck_assert_int_eq(gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM), 0);
  key_data.data = (unsigned char *)FIDO_KEY_FAKE;
  key_data.size = o_strlen(FIDO_KEY_FAKE);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), WEBAUTHN_CREDENTIAL_ID_LEN>>8, 1);
  memset((auth_data+auth_data_len+1), WEBAUTHN_CREDENTIAL_ID_LEN, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  auth_data_len += WEBAUTHN_CREDENTIAL_ID_LEN;
  
  ck_assert_int_eq(gnutls_pubkey_export_ecc_raw(pubkey, &curve, &key_x, &key_y), 0);
  cbor_cose = cbor_new_definite_map(4);
  ck_assert_ptr_ne(cbor_cose, NULL);
  
  cose_pair.key = cbor_build_uint8(1);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_x.data, key_x.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(2);
  cbor_mark_negint(cose_pair.key);
  cose_pair.value = cbor_build_bytestring(key_y.data, key_y.size);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(1);
  cose_pair.value = cbor_build_uint8(2);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_uint8(3);
  cose_pair.value = cbor_build_uint8(6);
  cbor_mark_negint(cose_pair.value);
  ck_assert_int_eq(cbor_map_add(cbor_cose, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cbor_cose_dump_len = cbor_serialize(cbor_cose, cbor_cose_dump, cbor_cose_dump_max_len);
  ck_assert_int_gt(cbor_cose_dump_len, 0);
  memcpy((auth_data+auth_data_len), cbor_cose_dump, cbor_cose_dump_len);
  auth_data_len += cbor_cose_dump_len;
  // authData is properly built
  
  // Let's build attStmt
  att_stmt = cbor_new_definite_map(2);
  
  cose_pair.key = cbor_build_string("ver");
  cose_pair.value = cbor_build_string("14366018");
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  ck_assert_int_eq(gnutls_x509_crt_init(&cert), 0);
  key_data.data = (unsigned char *)ANDROID_SAFETYNET_CERT_FAKE;
  key_data.size = o_strlen(ANDROID_SAFETYNET_CERT_FAKE);
  ck_assert_int_ge(gnutls_x509_crt_import(cert, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len), 0);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, NULL, &cert_der_enc_len), 1);
  cert_der_enc = o_malloc(cert_der_enc_len+1);
  ck_assert_int_eq(o_base64_encode(cert_der, cert_der_len, cert_der_enc, &cert_der_enc_len), 1);

  ck_assert_int_eq(jwt_new(&jwt_response), 0);
  ck_assert_int_eq(jwt_set_alg(jwt_response, JWT_ALG_ES256, (unsigned char *)ANDROID_SAFETYNET_KEY_FAKE, o_strlen(ANDROID_SAFETYNET_KEY_FAKE)), 0);
  j_grant = json_pack("{sss[s]}",
                      "alg",
                      "RS256",
                      "x5c",
                        cert_der_enc);
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_headers_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  
  key_data.data = (unsigned char *)client_data_json;
  key_data.size = o_strlen(client_data_json);
  memcpy(nonce, auth_data, auth_data_len);
  nonce_len = NONCE_SIZE-auth_data_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce+auth_data_len, &nonce_len), GNUTLS_E_SUCCESS);
  nonce_len += auth_data_len;
  key_data.data = nonce;
  key_data.size = nonce_len;
  ck_assert_int_eq(gnutls_fingerprint(GNUTLS_MAC_SHA256, &key_data, nonce_hash, &nonce_hash_len), GNUTLS_E_SUCCESS);
  
  ck_assert_int_eq(o_base64_encode(nonce_hash, nonce_hash_len, nonce_hash_enc, &nonce_hash_enc_len), 1);
  j_grant = json_pack("{sssisssssosos[s]}",
                      "nonce", nonce_hash_enc,
                      "timestampMs", time(NULL)*1000,
                      "apkPackageName", "com.google.android.gms",
                      "apkDigestSha256", "cGxlYXNlZG9udGRlY29kZW1laW1ub3RhcmVhbGhhc2gK",
                      "ctsProfileMatch", json_true(),
                      "basicIntegrity", json_true(),
                      "apkCertificateDigestSha256",
                        "cGxlYXNlZG9udGRlY29kZW1lZWl0aGVyaXRzZmFrZSEK");
  str_grant = json_dumps(j_grant, JSON_COMPACT);
  ck_assert_int_eq(jwt_add_grants_json(jwt_response, str_grant), 0);
  o_free(str_grant);
  json_decref(j_grant);
  ck_assert_ptr_ne((str_response = jwt_encode_str(jwt_response)), NULL);
  
  cose_pair.key = cbor_build_string("response");
  cose_pair.value = cbor_build_bytestring((unsigned char *)str_response, o_strlen(str_response));
  ck_assert_int_eq(cbor_map_add(att_stmt, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  // attStmt is properly built
  
  // Let's built the attestation object
  att_obj = cbor_new_definite_map(3);
  cose_pair.key = cbor_build_string("fmt");
  cose_pair.value = cbor_build_string("android-safetynet");
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("authData");
  cose_pair.value = cbor_build_bytestring(auth_data, auth_data_len);
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  cbor_decref(&cose_pair.value);
  
  cose_pair.key = cbor_build_string("attStmt");
  cose_pair.value = att_stmt;
  ck_assert_int_eq(cbor_map_add(att_obj, cose_pair), true);
  cbor_decref(&cose_pair.key);
  
  ck_assert_int_gt(cbor_serialize_alloc(att_obj, &att_obj_ser, &att_obj_ser_len), 0);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, NULL, &att_obj_ser_enc_len), 1);
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len+1);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{ss% ss%}}}}",
                           "username", USERNAME,
                           "scheme_type", MODULE_MODULE,
                           "scheme_name", MODULE_NAME,
                           "value",
                            "register", "register-credential",
                            "session", session,
                            "type", "public-key",
                            "credential",
                              "id", credential_id_enc_url, credential_id_enc_url_len,
                              "rawId", credential_id_enc, credential_id_enc_len,
                              "type", "public-key",
                              "response",
                                "attestationObject", att_obj_ser_enc, att_obj_ser_enc_len,
                                "clientDataJSON", client_data_json_enc, client_data_json_enc_len);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 200, NULL, NULL, NULL), 1);

  /*ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  printf("body %.*s\n", (int)resp_register.binary_body_length, (char *)resp_register.binary_body);
  ck_assert_int_eq(resp_register.status, 200);*/
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_disable_credential_error)
{
  json_t * j_params;
  
  j_params = json_pack("{sssssss{ssss}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "disable-credential",
                        "credential_id", "error");
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 404, NULL, NULL, NULL), 1);
  json_decref(j_params);

  j_params = json_pack("{sssssss{sssi}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "disable-credential",
                        "credential_id", 42);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);

  j_params = json_pack("{sssssss{ss}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "disable-credential");
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_disable_credential_success)
{
  json_t * j_params;
  unsigned char credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2];
  size_t credential_id_enc_len;
  
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  j_params = json_pack("{sssssss{ssss%}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "disable-credential",
                        "credential_id", credential_id_enc, credential_id_enc_len);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_enable_credential_error)
{
  json_t * j_params;
  
  j_params = json_pack("{sssssss{ssss}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "enable-credential",
                        "credential_id", "error");
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 404, NULL, NULL, NULL), 1);
  json_decref(j_params);

  j_params = json_pack("{sssssss{sssi}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "enable-credential",
                        "credential_id", 42);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);

  j_params = json_pack("{sssssss{ss}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "enable-credential");
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_enable_credential_success)
{
  json_t * j_params;
  unsigned char credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2];
  size_t credential_id_enc_len;
  
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  j_params = json_pack("{sssssss{ssss%}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "enable-credential",
                        "credential_id", credential_id_enc, credential_id_enc_len);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_edit_credential_error)
{
  json_t * j_params;
  unsigned char credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2];
  size_t credential_id_enc_len;
  
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  j_params = json_pack("{sssssss{ssssss}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "edit-credential",
                        "credential_id", "error",
                        "name", WEBAUTHN_CREDENTIAL_NEW_NAME);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 404, NULL, NULL, NULL), 1);
  json_decref(j_params);

  j_params = json_pack("{sssssss{sssiss}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "edit-credential",
                        "credential_id", 42,
                        "name", WEBAUTHN_CREDENTIAL_NEW_NAME);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);

  j_params = json_pack("{sssssss{sssssi}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "edit-credential",
                        "credential_id", credential_id_enc,
                        "name", 42);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_edit_credential_success)
{
  json_t * j_params;
  unsigned char credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2];
  size_t credential_id_enc_len;
  
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  j_params = json_pack("{sssssss{ssssss}}",
                      "username", USERNAME, 
                      "scheme_type", MODULE_MODULE, 
                      "scheme_name", MODULE_NAME, 
                      "value", 
                        "register", "edit-credential",
                        "credential_id", credential_id_enc,
                        "name", WEBAUTHN_CREDENTIAL_NEW_NAME);
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
}
END_TEST

START_TEST(test_glwd_scheme_webauthn_irl_module_remove)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/scheme/" MODULE_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd scheme webauthn");
  tc_core = tcase_create("test_glwd_scheme_webauthn_irl");
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_module_add);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_new_credential);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_bad_formed_response);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_client_data_json_challenge);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_client_data_json_hash_alg);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_client_data_json_rp_origin);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_client_data_json_type);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_rpid);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_flag_at);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_flag_user_present);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_credential_id);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_credential_id_content);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_cose_key_invalid_map);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_cose_key_invalid_alg);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_auth_data_cose_key_invalid_dump);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_data_cose_key_key_x_sign);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_data_cose_key_key_x_type);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_invalid_data_cose_key_key_alg);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_att_stmt_map_size);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_att_stmt_cert_key);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_att_stmt_x5c_size);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_prefix);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_rpid);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_client_data_hash);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_client_id);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_key_prefix);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_key_x);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_key_y);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_size);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_base_content);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_sig_key);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_att_obj_size);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_auth_data_key);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_u2f_invalid_att_stmt_key);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_u2f_success);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_disable_credential_error);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_disable_credential_success);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_enable_credential_error);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_enable_credential_success);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_edit_credential_error);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_edit_credential_success);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_test_assertion_trigger_error_session_invalid);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_test_assertion_error_session_invalid);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_test_assertion_invalid_challenge);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_test_assertion_invalid_origin);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_test_assertion_invalid_client_data_type);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_test_assertion_invalid_client_data_encoded);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_test_assertion_invalid_rp_id_hash);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_test_assertion_invalid_flag_user_present);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_test_assertion_invalid_client_data_hash);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_test_assertion_invalid_signature);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_test_assertion_success);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_auth_success);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_remove_credential_success);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_safetynet_ver_key);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_safetynet_ver_type);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_safetynet_cert);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_safetynet_cert_missing);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_safetynet_nonce_invalid);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_safetynet_jws_invalid);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_safetynet_fmt_invalid_key);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_error_safetynet_jws_invalid_signature);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_safetynet_success);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_test_assertion_success);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_auth_success);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_remove_credential_success);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_module_remove);
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
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(user_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    do_test = 1;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
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
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(admin_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    do_test = 1;
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
  
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&admin_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

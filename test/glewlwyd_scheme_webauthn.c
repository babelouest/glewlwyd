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
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <cbor.h>

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

#define FLAG_USER_PRESENT 0x01
#define FLAG_USER_VERIFY 0x04
#define FLAG_AT 0x40
#define AAGUID {0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57}
#define AAGUID_LEN 16
#define AUTH_DATA_SIZE 1024

#define FIDO_CERT_FAKE "-----BEGIN CERTIFICATE-----\
MIICoDCCAkagAwIBAgIUSyUhE6AOXAHPSkG14XJfyKXzJwcwCgYIKoZIzj0EAwIw\
gaYxCzAJBgNVBAYTAkNBMQ8wDQYDVQQIDAZRdWViZWMxDzANBgNVBAcMBlF1ZWJl\
YzETMBEGA1UECgwKYmFiZWxvdWVzdDERMA8GA1UECwwIZ2xld2x3eWQxKTAnBgNV\
BAMMIEZJRE8yIGNlcnRpZmljYXRlIGZvciB1bml0IHRlc3RzMSIwIAYJKoZIhvcN\
AQkBFhNtYWlsQGJhYmVsb3Vlc3Qub3JnMB4XDTE5MDYxMTE2NDQzNloXDTI5MDYw\
ODE2NDQzNlowgaYxCzAJBgNVBAYTAkNBMQ8wDQYDVQQIDAZRdWViZWMxDzANBgNV\
BAcMBlF1ZWJlYzETMBEGA1UECgwKYmFiZWxvdWVzdDERMA8GA1UECwwIZ2xld2x3\
eWQxKTAnBgNVBAMMIEZJRE8yIGNlcnRpZmljYXRlIGZvciB1bml0IHRlc3RzMSIw\
IAYJKoZIhvcNAQkBFhNtYWlsQGJhYmVsb3Vlc3Qub3JnMFYwEAYHKoZIzj0CAQYF\
K4EEAAoDQgAEoN1yk1zF7nFJP4fePGI3Ui+XgWU80VVD4bJiHW120DQhOlvYss46\
P9J/2TTD1rTvlfffzUXVaW50BLIFAFPJWKNTMFEwHQYDVR0OBBYEFC78C4imKhvo\
yl4Hf8nnZLkGCtXmMB8GA1UdIwQYMBaAFC78C4imKhvoyl4Hf8nnZLkGCtXmMA8G\
A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgEw6TbjJZcg6qwFvMB+3O\
K30vxgZTigsCQPchLOoaEUICIQDd/04rQhRmKZpg2WUJFh51FqfsGffTnq8QIxYZ\
SkWG6A==\
-----END CERTIFICATE-----"
#define FIDO_KEY_FAKE "-----BEGIN EC PRIVATE KEY-----\
MHQCAQEEIMV9huYpsNxz1SBEyK8WzniLU7O5pl0oCw6rwkYHToE6oAcGBSuBBAAK\
oUQDQgAEoN1yk1zF7nFJP4fePGI3Ui+XgWU80VVD4bJiHW120DQhOlvYss46P9J/\
2TTD1rTvlfffzUXVaW50BLIFAFPJWA==\
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

START_TEST(test_glwd_scheme_webauthn_irl_new_credential)
{
  json_t * j_params = json_pack("{sssssss{ss}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME, 
                                "value", 
                                  "register", "new-credential"),
         * j_response = json_pack("{s[{sssi}{sssi}{sssi}]ss}",
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
  unsigned char challenge[WEBAUTHN_CHALLENGE_LEN];
  size_t challenge_len;
  
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_params, NULL, 200, j_response, NULL, NULL), 1);
  
  ulfius_init_response(&resp);
  
  user_req.http_verb = o_strdup("POST");
  user_req.http_url = o_strdup(SERVER_URI "profile/scheme/register/");
  ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_params), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_result = ulfius_get_json_body_response(&resp, NULL);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_result2 = ulfius_get_json_body_response(&resp, NULL);
  
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result, "challenge")), json_string_length(json_object_get(j_result, "challenge")), challenge, &challenge_len), 1);
  ck_assert_int_eq(challenge_len, WEBAUTHN_CHALLENGE_LEN);
  ck_assert_int_eq(o_base64_decode((unsigned char *)json_string_value(json_object_get(j_result2, "challenge")), json_string_length(json_object_get(j_result2, "challenge")), challenge, &challenge_len), 1);
  ck_assert_int_eq(challenge_len, WEBAUTHN_CHALLENGE_LEN);
  ck_assert_str_ne(json_string_value(json_object_get(j_result, "session")), "");
  ck_assert_str_ne(json_string_value(json_object_get(j_result, "session")), json_string_value(json_object_get(j_result2, "session")));
  ck_assert_str_ne(json_string_value(json_object_get(j_result, "challenge")), json_string_value(json_object_get(j_result2, "challenge")));
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_result2);
  json_decref(j_response);
  ulfius_clean_response(&resp);
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
  unsigned char challenge_dec[WEBAUTHN_CHALLENGE_LEN], challenge_b64url[WEBAUTHN_CHALLENGE_LEN*2], * client_data_json_enc, credential_id[WEBAUTHN_CREDENTIAL_ID_LEN], credential_id_enc[WEBAUTHN_CREDENTIAL_ID_LEN*2], credential_id_enc_url[WEBAUTHN_CREDENTIAL_ID_LEN*2], auth_data[AUTH_DATA_SIZE], aaguid[AAGUID_LEN] = AAGUID, pubkey_id[128], cbor_cose_dump[512], cert_der[1024], verification_data[256], client_data_hash[32], * att_obj_ser, * att_obj_ser_enc;
  size_t challenge_dec_len, challenge_b64url_len, client_data_json_enc_len, credential_id_enc_len, credential_id_enc_url_len, auth_data_len = 1024, pubkey_id_len = 128, cbor_cose_dump_max_len = 512, cbor_cose_dump_len, cert_der_len = 1024, client_data_hash_len = 32, att_obj_ser_len, att_obj_ser_enc_len;
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
  client_data_json_enc = o_malloc(client_data_json_enc_len);
  ck_assert_ptr_ne(client_data_json_enc, NULL);
  ck_assert_int_eq(o_base64_encode((unsigned char *)client_data_json, o_strlen(client_data_json), client_data_json_enc, &client_data_json_enc_len), 1);
  
  // Generate credential_id
  ck_assert_int_eq(gnutls_rnd(GNUTLS_RND_KEY, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN), 0);
  ck_assert_int_eq(o_base64_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc, &credential_id_enc_len), 1);
  ck_assert_int_eq(o_base64url_encode(credential_id, WEBAUTHN_CREDENTIAL_ID_LEN, credential_id_enc_url, &credential_id_enc_url_len), 1);
  
  // Let's build auth_data
  memset(auth_data, 0, 1024);
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
  key_data.data = (unsigned char *)CREDENTIAL_PRIVATE_KEY;
  key_data.size = o_strlen(CREDENTIAL_PRIVATE_KEY);
  ck_assert_int_eq(gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM), 0);
  ck_assert_int_eq(gnutls_privkey_import_x509(privkey, key, 0), 0);
  ck_assert_int_eq(gnutls_pubkey_get_key_id(pubkey, 0, pubkey_id, &pubkey_id_len), 0);
  memset((auth_data+auth_data_len), pubkey_id_len>>8, 1);
  memset((auth_data+auth_data_len+1), pubkey_id_len, 1);
  auth_data_len += 2;
  memcpy((auth_data+auth_data_len), pubkey_id, pubkey_id_len);
  auth_data_len += pubkey_id_len;
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
  memcpy(verification_data+1, auth_data, 32);
  
  memcpy(verification_data+33, client_data_hash, client_data_hash_len);
  memcpy(verification_data+65, credential_id, WEBAUTHN_CREDENTIAL_ID_LEN);
  memset(verification_data+65+WEBAUTHN_CREDENTIAL_ID_LEN, 0x04, 1);
  memcpy(verification_data+65+WEBAUTHN_CREDENTIAL_ID_LEN+1, key_x.data, key_x.size);
  memcpy(verification_data+65+WEBAUTHN_CREDENTIAL_ID_LEN+1+key_x.size, key_y.data, key_y.size);
  
  key_data.data = verification_data;
  key_data.size = 65+WEBAUTHN_CREDENTIAL_ID_LEN+1+key_x.size+key_y.size;
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
  att_obj_ser_enc = o_malloc(att_obj_ser_enc_len);
  ck_assert_int_eq(o_base64_encode(att_obj_ser, att_obj_ser_len, att_obj_ser_enc, &att_obj_ser_enc_len), 1);
  
  j_credential = json_pack("{ss ss ss s{ss ss ss s{ss% ss% ss s{}}}}",
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
                              "response");
  ck_assert_int_eq(json_object_set_new(json_object_get(json_object_get(json_object_get(j_credential, "value"), "credential"), "response"), "attestationObject", json_stringn((const char *)att_obj_ser_enc, att_obj_ser_enc_len)), 0);
  ck_assert_int_eq(json_object_set_new(json_object_get(json_object_get(json_object_get(j_credential, "value"), "credential"), "response"), "clientDataJSON", json_stringn((const char *)client_data_json_enc, client_data_json_enc_len)), 0);
  //printf("j_credential %s\n", json_dumps(j_credential, JSON_ENCODE_ANY));
  //ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_credential, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(ulfius_set_empty_body_request(&user_req), U_OK);
  user_req.binary_body = json_dumps(j_credential, JSON_COMPACT);
  user_req.binary_body_length = o_strlen(user_req.binary_body);
  //ck_assert_int_eq(ulfius_set_json_body_request(&user_req, j_credential), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp_register), U_OK);
  ck_assert_int_eq(resp.status, 200);
  
  json_decref(j_params);
  json_decref(j_result);
  json_decref(j_credential);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp_register);
  o_free(client_data_json);
  o_free(client_data_json_enc);
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
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_new_credential);
  tcase_add_test(tc_core, test_glwd_scheme_webauthn_irl_register_u2f_success);
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

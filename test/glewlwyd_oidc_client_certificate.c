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
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <gnutls/pkcs12.h>
#include <check.h>

#include <orcania.h>
#include <yder.h>
#include <ulfius.h>
#include <rhonabwy.h>

#include "unit-tests.h"

#define SERVER_URI "https://localhost:4593/api/"
#define USERNAME "user1"
#define PASSWORD "password"
#define SCOPE_LIST "openid"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define PLUGIN_MODULE "oidc"
#define PLUGIN_NAME "oidc_client_cert"
#define PLUGIN_DISPLAY_NAME "oidc with client mtls authentication"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_ACCESS_TOKEN_DURATION 3600

#define CLIENT_ID "client_cert"
#define CLIENT_NAME "client with certificate"
#define CLIENT_SCOPE "scope2"
#define CLIENT_REDIRECT_URI "https://client.glewlwyd.tld"
#define CLIENT_SUBJECT_DN "CN=client-tls,O=babelouest"
#define CLIENT_SAN_DNS "client.glewlwyd.tld"
#define CLIENT_SAN_URI "https://client.glewlwyd.tld"
#define CLIENT_SAN_IPV4 "1.2.3.4"
#define CLIENT_SAN_IPV6 "2001:db8:85a3:8d3:1319:8a2e:370:7348"
#define CLIENT_SAN_IPV6_LOCALHOST "::1"
#define CLIENT_SAN_EMAIL "client-tls@client.glewlwyd.tld"

#define ROOT_CA_CERT_1_PATH "cert/root1.crt"
#define ROOT_CA_KEY_1_PATH "cert/root1.key"
#define ROOT_CA_CERT_3_PATH "cert/root2.crt"
#define ROOT_CA_KEY_3_PATH "cert/root2.key"

#define CLIENT_CERT_1_PATH "cert/client1.crt"
#define CLIENT_CERT_1_DER_PATH "cert/client1.crt.der"
#define CLIENT_KEY_1_PATH "cert/client1.key"
#define CLIENT_KEY_1_PASSWORD ""

#define CLIENT_CERT_2_PATH "cert/client2.crt"
#define CLIENT_CERT_2_DER_PATH "cert/client2.crt.der"
#define CLIENT_KEY_2_PATH "cert/client2.key"
#define CLIENT_KEY_2_PASSWORD ""

#define CLIENT_CERT_3_PATH "cert/client3.crt"
#define CLIENT_CERT_3_DER_PATH "cert/client3.crt.der"
#define CLIENT_KEY_3_PATH "cert/client3.key"
#define CLIENT_KEY_3_PASSWORD ""

char client_cert_1_id[128];
char client_cert_2_id[128];
char client_cert_3_id[128];

static char * get_file_content(const char * file_path) {
  char * buffer = NULL;
  size_t length, res;
  FILE * f;

  f = fopen (file_path, "rb");
  if (f) {
    fseek (f, 0, SEEK_END);
    length = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = o_malloc((length+1)*sizeof(char));
    if (buffer) {
      res = fread (buffer, 1, length, f);
      if (res != length) {
        fprintf(stderr, "fread warning, reading %zu while expecting %zu", res, length);
      }
      // Add null character at the end of buffer, just in case
      buffer[length] = '\0';
    }
    fclose (f);
  } else {
    fprintf(stderr, "error opening file %s\n", file_path);
  }
  
  return buffer;
}

static int get_certificate_id(const char * file_path, unsigned char * certificate_id) {
  char * cert_content = get_file_content(file_path);
  unsigned char cert_digest[128];
  size_t cert_digest_len = 128, certificate_id_len;
  gnutls_x509_crt_t cert = NULL;
  gnutls_datum_t cert_dat, dat;
  int ret = 0;
  
  if (!gnutls_x509_crt_init(&cert)) {
    cert_dat.data = (unsigned char *)cert_content;
    cert_dat.size = o_strlen(cert_content);
    if (gnutls_x509_crt_import(cert, &cert_dat, GNUTLS_X509_FMT_PEM) >= 0) {
      if (gnutls_x509_crt_export2(cert, GNUTLS_X509_FMT_DER, &dat) >= 0) {
        if (gnutls_fingerprint(GNUTLS_DIG_SHA256, &dat, cert_digest, &cert_digest_len) == GNUTLS_E_SUCCESS) {
          if (o_base64_encode(cert_digest, cert_digest_len, certificate_id, &certificate_id_len)) {
            certificate_id[certificate_id_len] = '\0';
            ret = 1;
          }
        }
        gnutls_free(dat.data);
      }
    }
  }
  gnutls_x509_crt_deinit(cert);
  o_free(cert_content);
  return ret;
}

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_oidc_client_certificate_add_module_both_no_alias_ok)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisososososososososssssosososo}}",
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
                                  "auth-type-device-enabled", json_true(),
                                  "client-cert-source", "both",
                                  "client-cert-header-name", "x509",
                                  "client-cert-self-signed-allowed", json_true(),
                                  "client-cert-use-endpoint-aliases", json_false(),
                                  "introspection-revocation-allowed", json_true(),
                                  "introspection-revocation-allow-target-client", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_module_header_no_alias_ok)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisososososososososssssosososo}}",
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
                                  "auth-type-device-enabled", json_true(),
                                  "client-cert-source", "header",
                                  "client-cert-header-name", "x509",
                                  "client-cert-self-signed-allowed", json_true(),
                                  "client-cert-use-endpoint-aliases", json_false(),
                                  "introspection-revocation-allowed", json_true(),
                                  "introspection-revocation-allow-target-client", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_module_tls_no_alias_ok)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisososososososososssssosososo}}",
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
                                  "auth-type-device-enabled", json_true(),
                                  "client-cert-source", "TLS",
                                  "client-cert-header-name", "x509",
                                  "client-cert-self-signed-allowed", json_true(),
                                  "client-cert-use-endpoint-aliases", json_false(),
                                  "introspection-revocation-allowed", json_true(),
                                  "introspection-revocation-allow-target-client", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_module_both_with_alias_ok)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisososososososososssssosososo}}",
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
                                  "auth-type-device-enabled", json_true(),
                                  "client-cert-source", "both",
                                  "client-cert-header-name", "x509",
                                  "client-cert-self-signed-allowed", json_true(),
                                  "client-cert-use-endpoint-aliases", json_true(),
                                  "introspection-revocation-allowed", json_true(),
                                  "introspection-revocation-allow-target-client", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_certificate_dn)
{
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssss[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "tls_client_auth",
                                "tls_client_auth_subject_dn", CLIENT_SUBJECT_DN,
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_invalid_certificate_dn)
{
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssss[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "tls_client_auth",
                                "tls_client_auth_subject_dn", CLIENT_SUBJECT_DN ",DN=error",
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_san_dns)
{
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssss[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "tls_client_auth",
                                "tls_client_auth_san_dns", CLIENT_SAN_DNS,
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_san_uri)
{
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssss[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "tls_client_auth",
                                "tls_client_auth_san_uri", CLIENT_SAN_URI,
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_san_ipv4)
{
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssss[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "tls_client_auth",
                                "tls_client_auth_san_ip", CLIENT_SAN_IPV4,
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_san_ipv6)
{
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssss[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "tls_client_auth",
                                "tls_client_auth_san_ip", CLIENT_SAN_IPV6,
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_san_ipv6_localhost)
{
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssss[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "tls_client_auth",
                                "tls_client_auth_san_ip", CLIENT_SAN_IPV6_LOCALHOST,
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_san_email)
{
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssss[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "tls_client_auth",
                                "tls_client_auth_san_email", CLIENT_SAN_EMAIL,
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_self_signed_certificate)
{
  char * cert_content = get_file_content(CLIENT_CERT_3_PATH);
  jwk_t * jwk;
  jwks_t * jwks;
  r_jwk_init(&jwk);
  r_jwks_init(&jwks);
  r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, (const unsigned char *)cert_content, o_strlen(cert_content));
  r_jwks_append_jwk(jwks, jwk);
  
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssos[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "self_signed_tls_client_auth",
                                "jwks", r_jwks_export_to_json_t(jwks),
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  o_free(cert_content);
  r_jwk_free(jwk);
  r_jwks_free(jwks);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_invalid_san_dns)
{
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssss[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "tls_client_auth",
                                "tls_client_auth_san_dns", "error.error",
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_invalid_san_uri)
{
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssss[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "tls_client_auth",
                                "tls_client_auth_san_uri", "https://error.error",
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_invalid_san_ipv4)
{
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssss[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "tls_client_auth",
                                "tls_client_auth_san_ip", "2.6.8.10",
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_invalid_san_ipv6)
{
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssss[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "tls_client_auth",
                                "tls_client_auth_san_ip", "2001:db6:85a3:8d1:1319:8a24:370:73e8",
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_add_client_with_invalid_san_email)
{
  json_t * j_parameters = json_pack("{sssss[s]sos[sssss]sssss[s]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "scope", CLIENT_SCOPE,
                                "confidential", json_true(),
                                "authorization_type", "code", "client_credentials", "refresh_token", "password", "device_authorization",
                                "token_endpoint_auth_methods_supported", "tls_client_auth",
                                "tls_client_auth_san_email", "error@error.error",
                                "redirect_uri", CLIENT_REDIRECT_URI,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_client_certificate_delete_module)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_client_certificate_delete_client)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_client_certificate_client_cred_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_claims;
  jwt_t * jwt;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                U_OPT_POST_BODY_PARAMETER, "scope", CLIENT_SCOPE,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_1_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_1_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_resp, "access_token")), 0);
  r_jwt_init(&jwt);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_claims = r_jwt_get_full_claims_json_t(jwt));
  ck_assert_int_gt(json_string_length(json_object_get(json_object_get(j_claims, "cnf"), "x5t#S256")), 0);
  json_decref(j_claims);
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_oidc_client_certificate_client_cred_ca_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                U_OPT_POST_BODY_PARAMETER, "scope", CLIENT_SCOPE,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_2_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_2_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ck_assert_ptr_eq(NULL, ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_client_certificate_client_cred_self_signed_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                U_OPT_POST_BODY_PARAMETER, "scope", CLIENT_SCOPE,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_3_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_3_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ck_assert_ptr_eq(NULL, ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_client_certificate_client_cred_client_id_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", "error",
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                U_OPT_POST_BODY_PARAMETER, "scope", CLIENT_SCOPE,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_1_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_1_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_client_certificate_client_cred_cert_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                U_OPT_POST_BODY_PARAMETER, "scope", CLIENT_SCOPE,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_1_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_1_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_client_certificate_code_valid)
{
  json_t * j_body, * j_resp, * j_claims;
  struct _u_request req;
  struct _u_response resp;
  char * code, * cookie, * refresh_token, * access_token;
  jwt_t * jwt;

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/auth/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_JSON_BODY, j_body,
                                                U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  ck_assert_int_eq(u_map_put(req.map_header, "Cookie", cookie), U_OK);
  o_free(cookie);
  ulfius_clean_response(&resp);

  // Set grant
  ulfius_init_response(&resp);
  j_body = json_pack("{ss}", "scope", "openid");
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "PUT",
                                                U_OPT_HTTP_URL, SERVER_URI "/auth/grant/" CLIENT_ID,
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_JSON_BODY, j_body,
                                                U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_response(&resp);

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "GET",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT_ID "&redirect_uri=" CLIENT_REDIRECT_URI "&state=xyzabcd&nonce=nonce1234&scope=openid",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "code=")+o_strlen("code="));
  if (o_strstr(code, "&") != NULL) {
    *o_strstr(code, "&") = '\0';
  }
  ulfius_clean_response(&resp);

  // Clean grant
  ulfius_init_response(&resp);
  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "PUT",
                                                U_OPT_HTTP_URL, SERVER_URI "/auth/grant/" CLIENT_ID,
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_JSON_BODY, j_body,
                                                U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  // Get tokens
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                U_OPT_POST_BODY_PARAMETER, "code", code,
                                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_1_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_1_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_body = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_ptr_ne(json_object_get(j_body, "refresh_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_body, "access_token"), NULL);
  refresh_token = o_strdup(json_string_value(json_object_get(j_body, "refresh_token")));
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  // Refresh token
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                U_OPT_POST_BODY_PARAMETER, "refresh_token", refresh_token,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_1_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_1_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_resp, "access_token")), 0);
  r_jwt_init(&jwt);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  access_token = o_strdup(json_string_value(json_object_get(j_resp, "access_token")));
  ck_assert_ptr_ne(NULL, j_claims = r_jwt_get_full_claims_json_t(jwt));
  ck_assert_int_gt(json_string_length(json_object_get(json_object_get(j_claims, "cnf"), "x5t#S256")), 0);
  json_decref(j_claims);
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);

  // Introspect token
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/introspect",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "token", access_token,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_1_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_1_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(json_object_get(j_resp, "cnf"), "x5t#S256")), 0);
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  // Revoke token
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/revoke",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "token", access_token,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_1_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_1_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  o_free(access_token);
  o_free(code);
  o_free(refresh_token);
}
END_TEST

START_TEST(test_oidc_client_certificate_code_ca_invalid)
{
  json_t * j_body;
  struct _u_request req;
  struct _u_response resp;
  char * code, * cookie;

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/auth/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_JSON_BODY, j_body,
                                                U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  ck_assert_int_eq(u_map_put(req.map_header, "Cookie", cookie), U_OK);
  o_free(cookie);
  ulfius_clean_response(&resp);

  // Set grant
  ulfius_init_response(&resp);
  j_body = json_pack("{ss}", "scope", "openid");
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "PUT",
                                                U_OPT_HTTP_URL, SERVER_URI "/auth/grant/" CLIENT_ID,
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_JSON_BODY, j_body,
                                                U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_response(&resp);

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "GET",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT_ID "&redirect_uri=" CLIENT_REDIRECT_URI "&state=xyzabcd&nonce=nonce1234&scope=openid",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "code=")+o_strlen("code="));
  if (o_strstr(code, "&") != NULL) {
    *o_strstr(code, "&") = '\0';
  }
  ulfius_clean_response(&resp);

  // Clean grant
  ulfius_init_response(&resp);
  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "PUT",
                                                U_OPT_HTTP_URL, SERVER_URI "/auth/grant/" CLIENT_ID,
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_JSON_BODY, j_body,
                                                U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  // Get tokens
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                U_OPT_POST_BODY_PARAMETER, "code", code,
                                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_2_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_2_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  o_free(code);
}
END_TEST

START_TEST(test_oidc_client_certificate_code_self_signed_invalid)
{
  json_t * j_body;
  struct _u_request req;
  struct _u_response resp;
  char * code, * cookie;

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/auth/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_JSON_BODY, j_body,
                                                U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  cookie = msprintf("%s=%s", resp.map_cookie[0].key, resp.map_cookie[0].value);
  ck_assert_int_eq(u_map_put(req.map_header, "Cookie", cookie), U_OK);
  o_free(cookie);
  ulfius_clean_response(&resp);

  // Set grant
  ulfius_init_response(&resp);
  j_body = json_pack("{ss}", "scope", "openid");
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "PUT",
                                                U_OPT_HTTP_URL, SERVER_URI "/auth/grant/" CLIENT_ID,
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_JSON_BODY, j_body,
                                                U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_response(&resp);

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "GET",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=code&g_continue&client_id=" CLIENT_ID "&redirect_uri=" CLIENT_REDIRECT_URI "&state=xyzabcd&nonce=nonce1234&scope=openid",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "code=")+o_strlen("code="));
  if (o_strstr(code, "&") != NULL) {
    *o_strstr(code, "&") = '\0';
  }
  ulfius_clean_response(&resp);

  // Clean grant
  ulfius_init_response(&resp);
  j_body = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "PUT",
                                                U_OPT_HTTP_URL, SERVER_URI "/auth/grant/" CLIENT_ID,
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_JSON_BODY, j_body,
                                                U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);
  
  // Get tokens
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                U_OPT_POST_BODY_PARAMETER, "code", code,
                                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_3_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_3_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 403);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  o_free(code);
}
END_TEST

START_TEST(test_oidc_client_certificate_resource_owner_pwd_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_claims;
  jwt_t * jwt;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "password",
                                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                U_OPT_POST_BODY_PARAMETER, "username", USERNAME,
                                                U_OPT_POST_BODY_PARAMETER, "password", PASSWORD,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_1_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_1_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_resp, "access_token")), 0);
  r_jwt_init(&jwt);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_claims = r_jwt_get_full_claims_json_t(jwt));
  ck_assert_int_gt(json_string_length(json_object_get(json_object_get(j_claims, "cnf"), "x5t#S256")), 0);
  json_decref(j_claims);
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_oidc_client_certificate_resource_owner_pwd_ca_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "password",
                                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                U_OPT_POST_BODY_PARAMETER, "username", USERNAME,
                                                U_OPT_POST_BODY_PARAMETER, "password", PASSWORD,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_2_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_2_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ck_assert_ptr_eq(NULL, ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_client_certificate_resource_owner_pwd_self_signed_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "password",
                                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                U_OPT_POST_BODY_PARAMETER, "username", USERNAME,
                                                U_OPT_POST_BODY_PARAMETER, "password", PASSWORD,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_3_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_3_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ck_assert_ptr_eq(NULL, ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_client_certificate_device_authorization_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_grant, * j_claims;
  const char * redirect_uri, * code, * device_code;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/device_authorization/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "device_authorization",
                                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_1_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_1_PATH,
                                                U_OPT_NONE), U_OK);  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_ptr_ne(code = json_string_value(json_object_get(j_resp, "user_code")), NULL);
  ck_assert_ptr_ne(device_code = json_string_value(json_object_get(j_resp, "device_code")), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), SERVER_URI PLUGIN_NAME "/device");
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
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:ietf:params:oauth:grant-type:device_code",
                                                U_OPT_POST_BODY_PARAMETER, "device_code", device_code,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_1_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_1_PATH,
                                                U_OPT_NONE), U_OK);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "refresh_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "id_token"), NULL);
  r_jwt_init(&jwt);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_claims = r_jwt_get_full_claims_json_t(jwt));
  ck_assert_int_gt(json_string_length(json_object_get(json_object_get(j_claims, "cnf"), "x5t#S256")), 0);
  json_decref(j_claims);
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);
  
}
END_TEST

START_TEST(test_oidc_client_certificate_device_authorization_ca_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/device_authorization/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "device_authorization",
                                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_2_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_2_PATH,
                                                U_OPT_NONE), U_OK);  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(403, resp.status);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_client_certificate_device_authorization_self_signed_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/device_authorization/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "device_authorization",
                                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_3_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_3_PATH,
                                                U_OPT_NONE), U_OK);  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(403, resp.status);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_client_certificate_client_cred_with_alias_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_claims;
  jwt_t * jwt;
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                U_OPT_POST_BODY_PARAMETER, "scope", CLIENT_SCOPE,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_1_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_1_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/mtls/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                U_OPT_POST_BODY_PARAMETER, "scope", CLIENT_SCOPE,
                                                U_OPT_CLIENT_CERT_FILE, CLIENT_CERT_1_PATH,
                                                U_OPT_CLIENT_KEY_FILE, CLIENT_KEY_1_PATH,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_resp, "access_token")), 0);
  r_jwt_init(&jwt);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_claims = r_jwt_get_full_claims_json_t(jwt));
  ck_assert_int_gt(json_string_length(json_object_get(json_object_get(j_claims, "cnf"), "x5t#S256")), 0);
  json_decref(j_claims);
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_oidc_client_certificate_client_cred_header_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_claims;
  jwt_t * jwt;
  char * cert_content = get_file_content(CLIENT_CERT_1_PATH),
       * cert_content_escaped = str_replace(cert_content, "\n", "");
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                U_OPT_POST_BODY_PARAMETER, "scope", CLIENT_SCOPE,
                                                U_OPT_HEADER_PARAMETER, "x509", cert_content_escaped,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_resp, "access_token")), 0);
  r_jwt_init(&jwt);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_claims = r_jwt_get_full_claims_json_t(jwt));
  ck_assert_int_gt(json_string_length(json_object_get(json_object_get(j_claims, "cnf"), "x5t#S256")), 0);
  json_decref(j_claims);
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);
  o_free(cert_content);
  o_free(cert_content_escaped);
}
END_TEST

START_TEST(test_oidc_client_certificate_client_cred_header_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  char * cert_content = get_file_content(CLIENT_CERT_1_PATH),
       * cert_content_escaped = str_replace(cert_content, "\n", "");
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                U_OPT_POST_BODY_PARAMETER, "scope", CLIENT_SCOPE,
                                                U_OPT_HEADER_PARAMETER, "x509", cert_content_escaped,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(cert_content);
  o_free(cert_content_escaped);
}
END_TEST

START_TEST(test_oidc_client_certificate_client_cred_self_signed_header_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_claims;
  jwt_t * jwt;
  char * cert_content = get_file_content(CLIENT_CERT_3_PATH),
       * cert_content_escaped = str_replace(cert_content, "\n", "");
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                U_OPT_POST_BODY_PARAMETER, "scope", CLIENT_SCOPE,
                                                U_OPT_HEADER_PARAMETER, "x509", cert_content_escaped,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_string_length(json_object_get(j_resp, "access_token")), 0);
  r_jwt_init(&jwt);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_ptr_ne(NULL, j_claims = r_jwt_get_full_claims_json_t(jwt));
  ck_assert_int_gt(json_string_length(json_object_get(json_object_get(j_claims, "cnf"), "x5t#S256")), 0);
  json_decref(j_claims);
  json_decref(j_resp);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);
  o_free(cert_content);
  o_free(cert_content_escaped);
}
END_TEST

START_TEST(test_oidc_client_certificate_client_cred_self_signed_header_invalid_cert)
{
  struct _u_request req;
  struct _u_response resp;
  char * cert_content = get_file_content(CLIENT_CERT_2_PATH),
       * cert_content_escaped = str_replace(cert_content, "\n", "");
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_set_request_properties(&req,
                                                U_OPT_HTTP_VERB, "POST",
                                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token/",
                                                U_OPT_CHECK_SERVER_CERTIFICATE, 0,
                                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                U_OPT_POST_BODY_PARAMETER, "scope", CLIENT_SCOPE,
                                                U_OPT_HEADER_PARAMETER, "x509", cert_content_escaped,
                                                U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(403, resp.status);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  o_free(cert_content);
  o_free(cert_content_escaped);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc client certificate");
  tc_core = tcase_create("test_glwd_oidc_client_certificate");
  tcase_add_test(tc_core, test_oidc_client_certificate_add_module_both_no_alias_ok);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_certificate_dn);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_header_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_ca_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_self_signed_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_client_id_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_code_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_code_ca_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_code_self_signed_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_resource_owner_pwd_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_resource_owner_pwd_ca_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_resource_owner_pwd_self_signed_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_device_authorization_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_device_authorization_ca_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_device_authorization_self_signed_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_invalid_certificate_dn);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_cert_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_san_dns);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_invalid_san_dns);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_cert_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_san_uri);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_invalid_san_uri);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_cert_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_san_ipv4);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_invalid_san_ipv4);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_cert_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_san_ipv6);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_invalid_san_ipv6);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_cert_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_san_ipv6_localhost);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_san_email);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_invalid_san_email);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_cert_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_self_signed_certificate);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_self_signed_header_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_self_signed_header_invalid_cert);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_module);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_module_header_no_alias_ok);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_certificate_dn);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_cert_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_header_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_module);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_module_tls_no_alias_ok);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_certificate_dn);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_header_invalid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_module);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_module_both_with_alias_ok);
  tcase_add_test(tc_core, test_oidc_client_certificate_add_client_with_certificate_dn);
  tcase_add_test(tc_core, test_oidc_client_certificate_client_cred_with_alias_valid);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_client);
  tcase_add_test(tc_core, test_oidc_client_certificate_delete_module);
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
  ulfius_init_request(&admin_req);
  admin_req.check_server_certificate = 0;
  ulfius_init_request(&user_req);
  user_req.check_server_certificate = 0;
  
  ulfius_init_request(&auth_req);
  auth_req.check_server_certificate = 0;
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
      y_log_message(Y_LOG_LEVEL_DEBUG, "User %s authenticated", ADMIN_USERNAME);
      do_test = 1;
    }
  } else {
    do_test = 0;
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication %s (%d/%d/%d)", ADMIN_USERNAME, res, auth_resp.status, auth_resp.nb_cookies);
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);

  ulfius_init_request(&auth_req);
  auth_req.check_server_certificate = 0;
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
      y_log_message(Y_LOG_LEVEL_DEBUG, "User %s authenticated", USERNAME);
      do_test = 1;
    }
  } else {
    do_test = 0;
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication %s (%d/%d/%d)", USERNAME, res, auth_resp.status, auth_resp.nb_cookies);
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);
  
  get_certificate_id(CLIENT_CERT_1_PATH, (unsigned char *)client_cert_1_id);
  get_certificate_id(CLIENT_CERT_2_PATH, (unsigned char *)client_cert_2_id);
  get_certificate_id(CLIENT_CERT_3_PATH, (unsigned char *)client_cert_3_id);

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Tests not executed");
  }
  
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

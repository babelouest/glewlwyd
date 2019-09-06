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
#include <liboath/oath.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "https://localhost:4593/api/"
#define USERNAME "user1"
#define PASSWORD "password"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define MODULE_MODULE "certificate"
#define MODULE_NAME "test_certificate"
#define MODULE_NAME_2 "test_certificate_2"
#define MODULE_NAME_3 "test_certificate_3"
#define MODULE_DISPLAY_NAME "Client certificate scheme for test"
#define MODULE_EXPIRATION 600
#define MODULE_MAX_USE 0

#define ROOT_CA_1_PATH "cert/root1.crt"
#define ROOT_CA_3_PATH "cert/root2.crt"

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
  o_free(cert_content);
  return ret;
}

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_glwd_scheme_certificate_module_add_scheme_backend)
{
  json_t * j_parameters = json_pack("{sssssssisis{so}}", 
                                    "module", MODULE_MODULE, 
                                    "name", MODULE_NAME, 
                                    "display_name", MODULE_DISPLAY_NAME, 
                                    "expiration", MODULE_EXPIRATION, 
                                    "max_use", MODULE_MAX_USE, 
                                    "parameters",
                                      "use-scheme-storage",
                                      json_true());
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_register_scheme_backend_use_cert)
{
  json_t * j_parameters = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "use-certificate");
  user_req.client_cert_file = o_strdup(CLIENT_CERT_1_PATH);
  user_req.client_key_file = o_strdup(CLIENT_KEY_1_PATH);
  user_req.client_key_password = o_strdup(CLIENT_KEY_1_PASSWORD);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  o_free(user_req.client_cert_file);
  o_free(user_req.client_key_file);
  o_free(user_req.client_key_password);
  user_req.client_cert_file = NULL;
  user_req.client_key_file = NULL;
  user_req.client_key_password = NULL;
}
END_TEST

START_TEST(test_glwd_scheme_certificate_register_scheme_backend_invalid_certificate)
{
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "upload-certificate", "x509", "error");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  char * cert_content = get_file_content(CLIENT_CERT_1_DER_PATH);
  j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "upload-certificate", "x509", cert_content);
  o_free(cert_content);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_register_scheme_backend)
{
  char * cert_content = get_file_content(CLIENT_CERT_1_PATH);
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "upload-certificate", "x509", cert_content);
  o_free(cert_content);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_get_register_scheme_backend)
{
  json_t * j_parameters = json_pack("{sssssss{}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value"),
  * j_result = json_string(client_cert_1_id);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_parameters);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_test_register_scheme_backend)
{
  json_t * j_parameters = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "test-certificate"),
  * j_result = json_string(client_cert_1_id);
  user_req.client_cert_file = o_strdup(CLIENT_CERT_1_PATH);
  user_req.client_key_file = o_strdup(CLIENT_KEY_1_PATH);
  user_req.client_key_password = o_strdup(CLIENT_KEY_1_PASSWORD);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, j_result, NULL, NULL), 1);
  o_free(user_req.client_cert_file);
  o_free(user_req.client_key_file);
  o_free(user_req.client_key_password);
  user_req.client_cert_file = NULL;
  user_req.client_key_file = NULL;
  user_req.client_key_password = NULL;
  json_decref(j_parameters);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_error_no_certificate_scheme_backend)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_error_unregistered_certificate_scheme_backend)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_2_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_2_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_2_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_error_invalid_ca_scheme_backend)
{
  char * cert_content = get_file_content(CLIENT_CERT_3_PATH);
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "upload-certificate", "x509", cert_content);
  o_free(cert_content);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);

  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_3_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_3_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_3_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
  
  j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "delete-certificate", "certificate_id", client_cert_3_id);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_success_scheme_backend)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_1_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_1_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_1_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_cert_disabled_enabled_scheme_backend)
{
  json_t * j_parameters = json_pack("{sssssss{ssssso}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "toggle-certificate", "certificate_id", client_cert_1_id, "enabled", json_false());
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);

  j_parameters = json_pack("{sssssss{}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, json_false(), NULL, NULL), 1);
  json_decref(j_parameters);

  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_1_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_1_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_1_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  
  j_parameters = json_pack("{sssssss{ssssso}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "toggle-certificate", "certificate_id", client_cert_1_id, "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{sssssss{}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, json_true(), NULL, NULL), 1);
  json_decref(j_parameters);

  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_deregister_scheme_backend)
{
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "delete-certificate", "certificate_id", client_cert_1_id);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_register_scheme_backend_multiple_cert)
{
  char * cert_content = get_file_content(CLIENT_CERT_1_PATH);
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "upload-certificate", "x509", cert_content);
  o_free(cert_content);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  cert_content = get_file_content(CLIENT_CERT_2_PATH);
  j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "upload-certificate", "x509", cert_content);
  o_free(cert_content);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_get_register_scheme_backend_multiple_cert)
{
  char * cert_content = get_file_content(CLIENT_CERT_1_PATH);
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "upload-certificate", "x509", cert_content),
  * j_result_1 = json_string(client_cert_1_id), * j_result_2 = json_string(client_cert_2_id);
  o_free(cert_content);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, j_result_1, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, j_result_2, NULL, NULL), 1);
  json_decref(j_parameters);
  json_decref(j_result_1);
  json_decref(j_result_2);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_test_register_scheme_backend_multiple_cert)
{
  json_t * j_parameters = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "test-certificate"),
  * j_result = json_string(client_cert_1_id);
  user_req.client_cert_file = o_strdup(CLIENT_CERT_1_PATH);
  user_req.client_key_file = o_strdup(CLIENT_KEY_1_PATH);
  user_req.client_key_password = o_strdup(CLIENT_KEY_1_PASSWORD);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, j_result, NULL, NULL), 1);
  o_free(user_req.client_cert_file);
  o_free(user_req.client_key_file);
  o_free(user_req.client_key_password);
  user_req.client_cert_file = NULL;
  user_req.client_key_file = NULL;
  user_req.client_key_password = NULL;
  json_decref(j_parameters);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_error_no_certificate_scheme_backend_multiple_cert)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_error_invalid_ca_scheme_backend_multiple_cert)
{
  char * cert_content = get_file_content(CLIENT_CERT_3_PATH);
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "upload-certificate", "x509", cert_content);
  o_free(cert_content);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);

  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_3_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_3_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_3_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
  
  j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "delete-certificate", "certificate_id", client_cert_3_id);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_success_scheme_backend_multiple_cert)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_1_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_1_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_1_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_deregister_scheme_backend_multiple_cert)
{
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "delete-certificate", "certificate_id", client_cert_1_id);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);

  j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "register", "delete-certificate", "certificate_id", client_cert_2_id);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_module_remove_scheme_backend)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/scheme/" MODULE_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_module_add_user_properties_pem)
{
  json_t * j_parameters = json_pack("{sssssssisis{sossss}}", 
                                    "module", MODULE_MODULE, 
                                    "name", MODULE_NAME_2, 
                                    "display_name", MODULE_DISPLAY_NAME, 
                                    "expiration", MODULE_EXPIRATION, 
                                    "max_use", MODULE_MAX_USE, 
                                    "parameters",
                                      "use-scheme-storage",
                                      json_false(),
                                      "user-certificate-property",
                                      "cert",
                                      "user-certificate-format",
                                      "PEM");
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  char * cert_1_content = get_file_content(CLIENT_CERT_1_PATH);
  j_parameters = json_pack("{ss}", "cert", cert_1_content);
  o_free(cert_1_content);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USERNAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_get_register_user_properties_pem)
{
  char * cert_content = get_file_content(CLIENT_CERT_1_PATH);
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME_2, "value", "register", "upload-certificate", "x509", cert_content),
  * j_result = json_string(client_cert_1_id);
  o_free(cert_content);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_parameters);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_test_register_user_properties_pem)
{
  json_t * j_parameters = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME_2, "value", "register", "test-certificate"),
  * j_result = json_string(client_cert_1_id);
  user_req.client_cert_file = o_strdup(CLIENT_CERT_1_PATH);
  user_req.client_key_file = o_strdup(CLIENT_KEY_1_PATH);
  user_req.client_key_password = o_strdup(CLIENT_KEY_1_PASSWORD);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, j_result, NULL, NULL), 1);
  o_free(user_req.client_cert_file);
  o_free(user_req.client_key_file);
  o_free(user_req.client_key_password);
  user_req.client_cert_file = NULL;
  user_req.client_key_file = NULL;
  user_req.client_key_password = NULL;
  json_decref(j_parameters);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_error_no_certificate_user_properties_pem)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME_2,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_error_unregistered_certificate_user_properties_pem)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME_2,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_2_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_2_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_2_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_success_user_properties_pem)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME_2,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_1_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_1_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_1_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_module_remove_user_properties_pem)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/scheme/" MODULE_NAME_2, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  
  json_t * j_parameters = json_pack("{so}", "cert", json_null());
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USERNAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_module_add_user_properties_pem_multiple_cert)
{
  json_t * j_parameters = json_pack("{sssssssisis{sossss}}", 
                                    "module", MODULE_MODULE, 
                                    "name", MODULE_NAME_2, 
                                    "display_name", MODULE_DISPLAY_NAME, 
                                    "expiration", MODULE_EXPIRATION, 
                                    "max_use", MODULE_MAX_USE, 
                                    "parameters",
                                      "use-scheme-storage",
                                      json_false(),
                                      "user-certificate-property",
                                      "cert",
                                      "user-certificate-format",
                                      "PEM");
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  char * cert_1_content = get_file_content(CLIENT_CERT_1_PATH), * cert_2_content = get_file_content(CLIENT_CERT_3_PATH);
  j_parameters = json_pack("{s[ss]}", "cert", cert_1_content, cert_2_content);
  o_free(cert_1_content);
  o_free(cert_2_content);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USERNAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_get_register_user_properties_pem_multiple_cert)
{
  char * cert_content = get_file_content(CLIENT_CERT_1_PATH);
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME_2, "value", "register", "upload-certificate", "x509", cert_content),
  * j_result = json_string(client_cert_1_id), * j_result_3 = json_string(client_cert_3_id);
  o_free(cert_content);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, j_result, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, j_result_3, NULL, NULL), 1);
  json_decref(j_parameters);
  json_decref(j_result);
  json_decref(j_result_3);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_test_register_user_properties_pem_multiple_cert)
{
  json_t * j_parameters = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME_2, "value", "register", "test-certificate"),
  * j_result = json_string(client_cert_1_id);
  user_req.client_cert_file = o_strdup(CLIENT_CERT_1_PATH);
  user_req.client_key_file = o_strdup(CLIENT_KEY_1_PATH);
  user_req.client_key_password = o_strdup(CLIENT_KEY_1_PASSWORD);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, j_result, NULL, NULL), 1);
  o_free(user_req.client_cert_file);
  o_free(user_req.client_key_file);
  o_free(user_req.client_key_password);
  user_req.client_cert_file = NULL;
  user_req.client_key_file = NULL;
  user_req.client_key_password = NULL;
  json_decref(j_parameters);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_error_no_certificate_user_properties_pem_multiple_cert)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME_2,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_error_unregistered_certificate_user_properties_pem_multiple_cert)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME_2,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_2_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_2_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_2_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_error_invalid_ca_user_properties_pem_multiple_cert)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_3_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_3_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_3_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_success_user_properties_pem_multiple_cert)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME_2,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_1_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_1_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_1_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_module_remove_user_properties_pem_multiple_cert)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/scheme/" MODULE_NAME_2, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  
  json_t * j_parameters = json_pack("{so}", "cert", json_null());
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USERNAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_module_add_user_properties_der)
{
  json_t * j_parameters = json_pack("{sssssssisis{sossss}}", 
                                    "module", MODULE_MODULE, 
                                    "name", MODULE_NAME_2, 
                                    "display_name", MODULE_DISPLAY_NAME, 
                                    "expiration", MODULE_EXPIRATION, 
                                    "max_use", MODULE_MAX_USE, 
                                    "parameters",
                                      "use-scheme-storage",
                                      json_false(),
                                      "user-certificate-property",
                                      "cert",
                                      "user-certificate-format",
                                      "DER");
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  char * cert_1_content = get_file_content(CLIENT_CERT_1_DER_PATH);
  j_parameters = json_pack("{ss}", "cert", cert_1_content);
  o_free(cert_1_content);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USERNAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_get_register_user_properties_der)
{
  json_t * j_parameters = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME_2, "value", "register", "upload-certificate"),
  * j_result = json_string(client_cert_1_id);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, j_result, NULL, NULL), 1);
  json_decref(j_parameters);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_error_no_certificate_user_properties_der)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME_2,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_error_unregistered_certificate_user_properties_der)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME_2,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_2_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_2_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_2_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_success_user_properties_der)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME_2,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_1_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_1_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_1_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_module_remove_user_properties_der)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/scheme/" MODULE_NAME_2, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  
  json_t * j_parameters = json_pack("{so}", "cert", json_null());
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USERNAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_module_add_scheme_backend_ca_chain)
{
  char * content = get_file_content(ROOT_CA_1_PATH);
  json_t * j_parameters = json_pack("{sssssssisis{sos[{ssss}]}}", 
                                    "module", MODULE_MODULE, 
                                    "name", MODULE_NAME_3, 
                                    "display_name", MODULE_DISPLAY_NAME, 
                                    "expiration", MODULE_EXPIRATION, 
                                    "max_use", MODULE_MAX_USE, 
                                    "parameters",
                                      "use-scheme-storage",
                                      json_true(),
                                      "ca-chain",
                                        "file-name",
                                        ROOT_CA_1_PATH,
                                        "cert-file",
                                        content);
  o_free(content);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_register_scheme_backend_ca_chain)
{
  char * cert_content = get_file_content(CLIENT_CERT_1_PATH);
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME_3, "value", "register", "upload-certificate", "x509", cert_content);
  o_free(cert_content);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_success_scheme_backend_ca_chain)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME_3,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_1_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_1_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_1_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_deregister_scheme_backend_ca_chain)
{
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME_3, "value", "register", "delete-certificate", "certificate_id", client_cert_1_id);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_module_remove_scheme_backend_ca_chain)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/scheme/" MODULE_NAME_3, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_module_add_scheme_backend_invalid_ca_chain)
{
  char * content = get_file_content(ROOT_CA_3_PATH);
  json_t * j_parameters = json_pack("{sssssssisis{sos[{ssss}]}}", 
                                    "module", MODULE_MODULE, 
                                    "name", MODULE_NAME_3, 
                                    "display_name", MODULE_DISPLAY_NAME, 
                                    "expiration", MODULE_EXPIRATION, 
                                    "max_use", MODULE_MAX_USE, 
                                    "parameters",
                                      "use-scheme-storage",
                                      json_true(),
                                      "ca-chain",
                                        "file-name",
                                        ROOT_CA_1_PATH,
                                        "cert-file",
                                        content);
  o_free(content);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_register_scheme_backend_invalid_ca_chain)
{
  char * cert_content = get_file_content(CLIENT_CERT_1_PATH);
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME_3, "value", "register", "upload-certificate", "x509", cert_content);
  o_free(cert_content);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_authenticate_error_scheme_backend_invalid_ca_chain)
{
  struct _u_request req;
  json_t * j_params = json_pack("{sssssss{}}", 
                                "username", USERNAME, 
                                "scheme_type", MODULE_MODULE, 
                                "scheme_name", MODULE_NAME_3,
                                "value");
  ulfius_init_request(&req);
  req.check_server_certificate = 0;
  req.client_cert_file = o_strdup(CLIENT_CERT_1_PATH);
  req.client_key_file = o_strdup(CLIENT_KEY_1_PATH);
  req.client_key_password = o_strdup(CLIENT_KEY_1_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_deregister_scheme_backend_invalid_ca_chain)
{
  json_t * j_parameters = json_pack("{sssssss{ssss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME_3, "value", "register", "delete-certificate", "certificate_id", client_cert_1_id);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "profile/scheme/register/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_certificate_module_remove_scheme_backend_invalid_ca_chain)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/scheme/" MODULE_NAME_3, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd scheme certificate");
  tc_core = tcase_create("test_glwd_scheme_certificate");
  tcase_add_test(tc_core, test_glwd_scheme_certificate_module_add_scheme_backend);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_register_scheme_backend_use_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_get_register_scheme_backend);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_deregister_scheme_backend);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_register_scheme_backend_invalid_certificate);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_register_scheme_backend);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_get_register_scheme_backend);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_test_register_scheme_backend);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_error_no_certificate_scheme_backend);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_error_unregistered_certificate_scheme_backend);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_error_invalid_ca_scheme_backend);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_success_scheme_backend);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_cert_disabled_enabled_scheme_backend);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_deregister_scheme_backend);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_register_scheme_backend_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_get_register_scheme_backend_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_test_register_scheme_backend_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_error_no_certificate_scheme_backend_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_error_invalid_ca_scheme_backend_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_success_scheme_backend_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_deregister_scheme_backend_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_module_remove_scheme_backend);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_module_add_user_properties_pem);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_get_register_user_properties_pem);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_test_register_user_properties_pem);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_error_no_certificate_user_properties_pem);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_error_unregistered_certificate_user_properties_pem);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_success_user_properties_pem);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_module_remove_user_properties_pem);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_module_add_user_properties_pem_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_get_register_user_properties_pem_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_test_register_user_properties_pem_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_error_no_certificate_user_properties_pem_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_error_unregistered_certificate_user_properties_pem_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_error_invalid_ca_user_properties_pem_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_success_user_properties_pem_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_module_remove_user_properties_pem_multiple_cert);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_module_add_user_properties_der);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_get_register_user_properties_der);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_error_no_certificate_user_properties_der);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_error_unregistered_certificate_user_properties_der);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_success_user_properties_der);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_module_remove_user_properties_der);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_module_add_scheme_backend_ca_chain);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_register_scheme_backend_ca_chain);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_success_scheme_backend_ca_chain);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_deregister_scheme_backend_ca_chain);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_module_remove_scheme_backend_ca_chain);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_module_add_scheme_backend_invalid_ca_chain);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_register_scheme_backend_invalid_ca_chain);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_authenticate_error_scheme_backend_invalid_ca_chain);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_deregister_scheme_backend_invalid_ca_chain);
  tcase_add_test(tc_core, test_glwd_scheme_certificate_module_remove_scheme_backend_invalid_ca_chain);
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
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication (%d/%d)", res, auth_resp.status);
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
  if (do_test && res == U_OK && auth_resp.status == 200) {
    for (i=0; i<auth_resp.nb_cookies; i++) {
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(user_req.map_header, "Cookie", cookie);
      o_free(cookie);
      y_log_message(Y_LOG_LEVEL_DEBUG, "User %s authenticated", USERNAME);
      do_test = 1;
    }
  } else {
    do_test = 0;
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
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

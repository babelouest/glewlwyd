/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * TLS client certificate authentication scheme module
 * 
 * Copyright 2019 Nicolas Mora <mail@babelouest.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation;
 * version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <gnutls/pkcs12.h>
#include <string.h>
#include <jansson.h>
#include <yder.h>
#include <orcania.h>
#include "../glewlwyd-common.h"

#define GLEWLWYD_SCHEME_CERTIFICATE_TABLE_USER_CERTIFICATE "gs_user_certificate"
#define GLEWLWYD_SCHEME_CERTIFICATE_TABLE_USER_PKCS12 "gs_user_pkcs12"

#define G_CERT_SOURCE_TLS    0x01
#define G_CERT_SOURCE_HEADER 0x10

#define G_PKCS12_FRIENDLY_NAME "Glewlwyd generated PKCS#12"
#define G_PKCS12_PASSWORD_LENGTH 16

int user_auth_scheme_module_validate(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls);

static int add_user_certificate_scheme_storage(struct config_module * config, json_t * j_parameters, const char * x509_data, const char * username, const char * user_agent);

/**
 * 
 * How-To generate a cert chain with cient certificates
 * 
 * OpenSSL
 * =======
 * 
 * Root cert/key
 * openssl genrsa -out root.key 4096
 * openssl req -x509 -new -nodes -key root.key -sha256 -days 1024 -out root.crt
 * 
 * Client cert/key/pfx
 * openssl genrsa -out client.key 4096
 * openssl req -new -key client.key -out client.csr
 * openssl x509 -req -in client.csr -CA root.crt -CAkey root.key -CAcreateserial -out client.crt -days 500 -sha256
 * openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt
 * 
 * GnuTLS
 * ======
 * 
 * Root cert/key
 * certtool --generate-privkey --outfile root.key --bits=4096
 * certtool --generate-request --load-privkey root.key --outfile root.csr
 * certtool --generate-self-signed --load-privkey root.key --outfile root.crt
 * 
 * Client cert/key/pfx
 * certtool --generate-privkey --outfile client.key --bits=4096
 * certtool --generate-request --load-privkey client.key --outfile client.csr
 * certtool --generate-certificate --load-request client.csr --load-ca-certificate root.crt --load-ca-privkey root.key --outfile client.crt
 * certtool --load-certificate client.crt --load-privkey client.key --to-p12 --outder --outfile client.pfx
 * 
 */

struct _cert_chain_element {
  gnutls_x509_crt_t            cert;
  char                       * dn;
  struct _cert_chain_element * issuer_cert;
  char                       * issuer_dn;
};

struct _cert_param {
  json_t                      * j_parameters;
  size_t                        cert_array_len;
  struct _cert_chain_element ** cert_array;
  ushort                        cert_source;
  pthread_mutex_t               cert_request_lock;
};

static json_int_t get_last_serial(struct config_module * config) {
  json_t * j_query, * j_result;
  int res;
  json_int_t ret = 0;

  j_query = json_pack("{sss[s]sssi}",
                      "table",
                      GLEWLWYD_SCHEME_CERTIFICATE_TABLE_USER_PKCS12,
                      "columns",
                        "gsup_id",
                      "order_by",
                      "gsup_id DESC",
                      "limit",
                      1);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      ret = json_integer_value(json_object_get(json_array_get(j_result, 0), "gsup_id"));
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_stored_generated_certificate - Error executing j_query");
  }
  return ret;
}

static int generate_pkcs12(gnutls_x509_privkey_t privkey_x509, gnutls_x509_crt_t crt, gnutls_pkcs12_t pkcs12, const char * password) {
  int res, bag_index, ret = G_ERROR;
  gnutls_pkcs12_bag_t bag, key_bag;
  unsigned char key_id_dat[1024];
  size_t key_id_dat_size = 1024;
  gnutls_datum_t key_id = {NULL, 0}, cert_dat = {NULL, 0}, key_dat = {NULL, 0};

  do {
    if ((res = gnutls_x509_privkey_get_key_id(privkey_x509, 0, key_id_dat, &key_id_dat_size)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_privkey_get_key_id: %d", res);
      break;
    }
    
    key_id.data = key_id_dat;
    key_id.size = key_id_dat_size;

    if ((res = gnutls_pkcs12_bag_init(&bag)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_pkcs12_bag_init: %d", res);
      break;
    }
      
    if ((res = gnutls_pkcs12_bag_init(&key_bag)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_pkcs12_bag_init: %d", res);
      break;
    }
    
    if ((res = gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_DER, &cert_dat)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_crt_export2: %d", res);
      break;
    }
    
    if ((res = gnutls_x509_privkey_export2_pkcs8(privkey_x509, GNUTLS_X509_FMT_DER, password, GNUTLS_PKCS_USE_PBES2_AES_128, &key_dat)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_privkey_export2_pkcs8: %d", res);
      break;
    }

    if ((res = gnutls_pkcs12_bag_set_data(bag, GNUTLS_BAG_CERTIFICATE, &cert_dat)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_pkcs12_bag_set_data: %d", res);
      break;
    }

    bag_index = res;

    if ((res = gnutls_pkcs12_bag_set_friendly_name(bag, bag_index, G_PKCS12_FRIENDLY_NAME)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_pkcs12_bag_set_friendly_name: %d", res);
      break;
    }

    if ((res = gnutls_pkcs12_bag_set_key_id(bag, bag_index, &key_id)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_pkcs12_bag_set_key_id: %d", res);
      break;
    }

    if ((res = gnutls_pkcs12_bag_encrypt(bag, password, GNUTLS_PKCS_USE_PKCS12_RC2_40)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_pkcs12_bag_encrypt: %d", res);
      break;
    }

    if ((res = gnutls_pkcs12_bag_set_data(key_bag, GNUTLS_BAG_PKCS8_ENCRYPTED_KEY, &key_dat)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_pkcs12_bag_set_data: %d", res);
      break;
    }

    bag_index = res;

    if ((res = gnutls_pkcs12_bag_set_friendly_name(key_bag, bag_index, G_PKCS12_FRIENDLY_NAME)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_pkcs12_bag_set_friendly_name: %d", res);
      break;
    }

    if ((res = gnutls_pkcs12_bag_set_key_id(key_bag, bag_index, &key_id)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_pkcs12_bag_set_key_id: %d", res);
      break;
    }

    if ((res = gnutls_pkcs12_set_bag(pkcs12, bag)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_pkcs12_set_bag: %d", res);
      break;
    }
    
    if ((res = gnutls_pkcs12_set_bag(pkcs12, key_bag)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_pkcs12_set_bag: %d", res);
      break;
    }

    if ((res = gnutls_pkcs12_generate_mac(pkcs12, password)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_pkcs12_generate_mac: %d", res);
      break;
    }

    ret = G_OK;
  } while (0);

  gnutls_pkcs12_bag_deinit(bag);
  gnutls_pkcs12_bag_deinit(key_bag);
  gnutls_free(cert_dat.data);
  gnutls_free(key_dat.data);

  return ret;
}

static char * get_dn_for_user(struct config_module * config, json_t * j_parameters, const char * username) {
  char * dn = NULL, * tmp, * pattern;
  const char * key = NULL;
  json_t * j_user = config->glewlwyd_module_callback_get_user(config, username), * j_property = NULL;
  
  if (check_result_value(j_user, G_OK)) {
    dn = o_strdup(json_string_value(json_object_get(json_object_get(j_parameters, "request-certificate"), "dn-format")));
    json_object_foreach(json_object_get(j_user, "user"), key, j_property) {
      if (o_strchr(dn, '{') == NULL) {
        // If there's no more pattern to replace in DN, exit foreach
        break;
      }
      if (json_is_string(j_property)) {
        pattern = msprintf("{%s}", key);
        tmp = str_replace(dn, pattern, json_string_value(j_property));
        o_free(dn);
        o_free(pattern);
        dn = tmp;
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_dn_for_user - Error glewlwyd_module_callback_get_user");
  }
  json_decref(j_user);
  return dn;
}

static int generate_key_cert(struct config_module * config, json_t * j_parameters, const char * username, gnutls_x509_privkey_t privkey_x509, gnutls_privkey_t privkey, gnutls_x509_crt_t crt, time_t activation, time_t expiration) {
  gnutls_x509_privkey_t key_issuer = NULL;
  gnutls_x509_crt_t crt_issuer = NULL;
  gnutls_datum_t dat;
  const char * err = NULL;
  int res, ret = G_ERROR;
  json_int_t serial = get_last_serial(config);
  char * dn = get_dn_for_user(config, j_parameters, username);

  do {
    if (dn == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error dn");
      break;
    }
    
    if ((res = gnutls_x509_privkey_init(&key_issuer)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_privkey_init: %d", res);
      break;
    }
    
    if ((res = gnutls_x509_crt_init(&crt_issuer)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_crt_init: %d", res);
      break;
    }
    
    dat.data = (unsigned char *)json_string_value(json_object_get(json_object_get(json_object_get(j_parameters, "request-certificate"), "issuer-key"), "cert-file"));
    dat.size = json_string_length(json_object_get(json_object_get(json_object_get(j_parameters, "request-certificate"), "issuer-key"), "cert-file"));
    if ((res = gnutls_x509_privkey_import(key_issuer, &dat, GNUTLS_X509_FMT_PEM)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_privkey_import: %d", res);
      break;
    }

    dat.data = (unsigned char *)json_string_value(json_object_get(json_object_get(json_object_get(j_parameters, "request-certificate"), "issuer-cert"), "cert-file"));
    dat.size = json_string_length(json_object_get(json_object_get(json_object_get(j_parameters, "request-certificate"), "issuer-cert"), "cert-file"));
    if ((res = gnutls_x509_crt_import(crt_issuer, &dat, GNUTLS_X509_FMT_PEM)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_crt_import: %d", res);
      break;
    }
    
    if ((res = gnutls_x509_crt_set_version(crt, 1)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_crt_set_version: %d", res);
      break;
    }

    if ((res = gnutls_x509_privkey_generate(privkey_x509, GNUTLS_PK_RSA, gnutls_sec_param_to_pk_bits(GNUTLS_PK_RSA, GNUTLS_SEC_PARAM_MEDIUM), GNUTLS_PRIVKEY_SIGN_FLAG_TLS1_RSA)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_privkey_generate: %d", res);
      break;
    }
    
    if ((res = gnutls_privkey_import_x509(privkey, privkey_x509, GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_privkey_import_x509: %d", res);
      break;
    }
    
    if ((res = gnutls_x509_crt_set_key(crt, privkey_x509)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_crt_set_key: %d", res);
      break;
    }
    
    if ((res = gnutls_x509_crt_set_expiration_time(crt, (time_t)expiration)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_crt_set_expiration_time: %d", res);
      break;
    }
    
    if ((res = gnutls_x509_crt_set_activation_time(crt, (time_t)activation)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_crt_set_activation_time: %d", res);
      break;
    }
    
    if ((res = gnutls_x509_crt_set_serial(crt, &serial, sizeof(serial))) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_crt_set_serial: %d", res);
      break;
    }
    
    
    if ((res = gnutls_x509_crt_set_dn(crt, dn, &err)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_crt_set_dn: %d", res);
      break;
    }
    
    if ((res = gnutls_x509_crt_sign2(crt, crt_issuer, key_issuer, GNUTLS_DIG_SHA256, 0)) < 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_crt_sign2: %d", res);
      break;
    }
    
    ret = G_OK;
  } while (0);
  
  if (key_issuer) {
    gnutls_x509_privkey_deinit(key_issuer);
  }
  if (crt_issuer) {
    gnutls_x509_crt_deinit(crt_issuer);
  }
  o_free(dn);
  
  return ret;
}

static int store_generated_certificate(struct config_module * config, json_t * j_parameters, const char * username, const char * p12_content, const char * password, time_t activation, time_t expiration, const char * host, const char * user_agent) {
  json_t * j_query;
  char * expiration_clause = NULL, * activation_clause = NULL;
  int res, ret;
  
  if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
    expiration_clause = msprintf("FROM_UNIXTIME(%ld)", expiration);
    activation_clause = msprintf("FROM_UNIXTIME(%ld)", activation);
  } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
    expiration_clause = msprintf("TO_TIMESTAMP(%ld)", expiration);
    activation_clause = msprintf("TO_TIMESTAMP(%ld)", activation);
  } else { // HOEL_DB_TYPE_SQLITE
    expiration_clause = msprintf("%ld", expiration);
    activation_clause = msprintf("%ld", activation);
  }
  j_query = json_pack("{sss{sOsssosos{ss}s{ss}ssss}}",
                      "table",
                      GLEWLWYD_SCHEME_CERTIFICATE_TABLE_USER_PKCS12,
                      "values",
                        "gsup_mod_name",
                        json_object_get(j_parameters, "mod_name"),
                        "gsup_username",
                        username,
                        "gsup_pkcs12_content",
                        p12_content!=NULL?json_string(p12_content):json_null(),
                        "gsup_pkcs12_password",
                        password!=NULL?json_string(password):json_null(),
                        "gsup_activation",
                          "raw",
                          activation_clause,
                        "gsup_expiration",
                          "raw",
                          expiration_clause,
                        "gsup_host",
                        host,
                        "gsup_user_agent",
                        user_agent!=NULL?user_agent:"");
  o_free(expiration_clause);
  o_free(activation_clause);
  res = h_insert(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "store_generated_certificate - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static json_t * generate_new_certificate(struct config_module * config, json_t * j_parameters, const char * username, const char * user_agent, time_t activation, time_t expiration) {
  int res, ret = G_OK;
  gnutls_privkey_t privkey = NULL;
  gnutls_x509_privkey_t privkey_x509 = NULL;
  gnutls_x509_crt_t crt = NULL;
  gnutls_pkcs12_t pkcs12 = NULL;
  gnutls_datum_t export_p12 = {NULL, 0}, export_cert = {NULL, 0};
  char password[G_PKCS12_PASSWORD_LENGTH+1] = {};
  json_t * j_return;
  unsigned char * pkcs12_encoded = NULL;
  size_t pkcs12_encoded_len = 0;
  
  rand_string(password, G_PKCS12_PASSWORD_LENGTH);
  
  if ((res = gnutls_x509_privkey_init(&privkey_x509)) < 0) {
    y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_privkey_init: %d", res);
    ret = G_ERROR;
  }

  if ((res = gnutls_privkey_init(&privkey)) < 0) {
    y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_privkey_init: %d", res);
    ret = G_ERROR;
  }

  if (ret == G_OK && (res = gnutls_x509_crt_init(&crt)) < 0) {
    y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_x509_crt_init: %d", res);
    ret = G_ERROR;
  }
  
  if (ret == G_OK && (res = gnutls_pkcs12_init(&pkcs12)) < 0) {
    y_log_message(Y_LOG_LEVEL_ERROR, "error gnutls_pkcs12_init: %d", res);
    ret = G_ERROR;
  }
  
  if (ret == G_OK && (ret = generate_key_cert(config, j_parameters, username, privkey_x509, privkey, crt, activation, expiration)) != G_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "error generate_key_cert");
    ret = G_ERROR;
  }
  
  if (ret == G_OK && (ret = generate_pkcs12(privkey_x509, crt, pkcs12, password)) != G_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "error generate_pkcs12");
    ret = G_ERROR;
  }
  
  if (ret == G_OK) {
    if ((res = gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_PEM, &export_cert)) >= 0) {
      if (add_user_certificate_scheme_storage(config, j_parameters, (const char *)export_cert.data, username, user_agent) == G_OK) {
        if ((res = gnutls_pkcs12_export2(pkcs12, GNUTLS_X509_FMT_DER, &export_p12)) >= 0) {
          if (o_base64_encode(export_p12.data, export_p12.size, NULL, &pkcs12_encoded_len)) {
            if ((pkcs12_encoded = o_malloc(pkcs12_encoded_len+1)) != NULL) {
              if (o_base64_encode(export_p12.data, export_p12.size, pkcs12_encoded, &pkcs12_encoded_len)) {
                pkcs12_encoded[pkcs12_encoded_len] = '\0';
                j_return = json_pack("{sis{ssss}}", "result", G_OK, "certificate", "p12", pkcs12_encoded, "password", password);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_certificate - Error o_base64_encode (1)");
                j_return = json_pack("{si}", "result", G_ERROR);
              }
              o_free(pkcs12_encoded);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_certificate - Error o_malloc");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_certificate - Error o_base64_encode (1)");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          gnutls_free(export_p12.data);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_certificate - Error gnutls_pkcs12_export: %s", gnutls_strerror(res));
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_certificate - Error add_user_certificate_scheme_storage");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      gnutls_free(export_cert.data);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_certificate - Error gnutls_x509_crt_export2: %s", gnutls_strerror(res));
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  
  if (privkey != NULL) {
    gnutls_privkey_deinit(privkey);
  }
  
  if (crt != NULL) {
    gnutls_x509_crt_deinit(crt);
  }
  
  if (pkcs12 != NULL) {
    gnutls_pkcs12_deinit(pkcs12);
  }
  
  return j_return;
}

static json_t * get_stored_generated_certificate(struct config_module * config, json_t * j_parameters, const char * username) {
  json_t * j_query, * j_result, * j_return;
  int res;
  char * expiration_clause;
  time_t now;
  
  time(&now);
  if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
    expiration_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
  } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
    expiration_clause = msprintf("> TO_TIMESTAMP(%u)", now);
  } else { // HOEL_DB_TYPE_SQLITE
    expiration_clause = msprintf("> %u", (now));
  }
  j_query = json_pack("{sss[ssss]s{sOsss{ssss}s{ssss}s{ssss}}sssi}",
                      "table",
                      GLEWLWYD_SCHEME_CERTIFICATE_TABLE_USER_PKCS12,
                      "columns",
                        "gsup_pkcs12_content AS p12",
                        "gsup_pkcs12_password AS password",
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gsup_activation) AS activation", "strftime('%s', gsup_activation) AS activation", "EXTRACT(EPOCH FROM gsup_activation)::integer AS activation"),
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gsup_expiration) AS expiration", "strftime('%s', gsup_expiration) AS expiration", "EXTRACT(EPOCH FROM gsup_expiration)::integer AS expiration"),
                      "where",
                        "gsup_mod_name",
                        json_object_get(j_parameters, "mod_name"),
                        "gsup_username",
                        username,
                        "gsup_expiration",
                          "operator",
                          "raw",
                          "value",
                          expiration_clause,
                        "gsup_pkcs12_content",
                          "operator",
                          "raw",
                          "value",
                          "IS NOT NULL",
                        "gsup_pkcs12_password",
                          "operator",
                          "raw",
                          "value",
                          "IS NOT NULL",
                      "order_by",
                      "gsup_expiration DESC",
                      "limit",
                      1);
  o_free(expiration_clause);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      j_return = json_pack("{sisO}", "result", G_OK, "certificate", json_array_get(j_result, 0));
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_stored_generated_certificate - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static json_t * get_generated_certificate(struct config_module * config, json_t * j_parameters, const char * username, const char * ip_source, const char * user_agent) {
  json_t * j_return = NULL, * j_certificate, * j_new_cetificate;
  time_t activation, expiration;
  
  if (json_object_get(json_object_get(j_parameters, "request-certificate"), "allow-multiple") == json_true()) {
    time(&activation);
    expiration = activation + json_integer_value(json_object_get(json_object_get(j_parameters, "request-certificate"), "expiration"));
    j_certificate = generate_new_certificate(config, j_parameters, username, user_agent, activation, expiration);
    if (check_result_value(j_certificate, G_OK)) {
      if (store_generated_certificate(config, j_parameters, username, NULL, NULL, activation, expiration, ip_source, user_agent) == G_OK) {
        j_return = json_incref(j_certificate);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_generated_certificate - Error store_generated_certificate");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_generated_certificate - Error generate_new_certificate (1)");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_certificate);
  } else {
    j_certificate = get_stored_generated_certificate(config, j_parameters, username);
    if (check_result_value(j_certificate, G_OK)) {
      j_return = json_pack("{sis{sOsO}}", "result", G_OK, "certificate", "p12", json_object_get(json_object_get(j_certificate, "certificate"), "p12"), "password", json_object_get(json_object_get(j_certificate, "certificate"), "password"));
    } else if (check_result_value(j_certificate, G_ERROR_NOT_FOUND)) {
      time(&activation);
      expiration = activation + json_integer_value(json_object_get(json_object_get(j_parameters, "request-certificate"), "expiration"));
      j_new_cetificate = generate_new_certificate(config, j_parameters, username, user_agent, activation, expiration);
      if (check_result_value(j_new_cetificate, G_OK)) {
        if (store_generated_certificate(config, j_parameters, username, json_string_value(json_object_get(json_object_get(j_new_cetificate, "certificate"), "p12")), json_string_value(json_object_get(json_object_get(j_new_cetificate, "certificate"), "password")), activation, expiration, ip_source, user_agent) == G_OK) {
          j_return = json_incref(j_new_cetificate);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_generated_certificate - Error store_generated_certificate");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_generated_certificate - Error generate_new_certificate (2)");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_new_cetificate);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_generated_certificate - Error get_stored_generated_certificate");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_certificate);
  }
  return j_return;
}

static int get_certificate_id(gnutls_x509_crt_t cert, unsigned char * cert_id, size_t * cert_id_len) {
  int ret;
  unsigned char cert_digest[64];
  size_t cert_digest_len = 64;
  gnutls_datum_t dat;
  dat.data = NULL;
  
  
  if (gnutls_x509_crt_export2(cert, GNUTLS_X509_FMT_DER, &dat) >= 0) {
    if (gnutls_fingerprint(GNUTLS_DIG_SHA256, &dat, cert_digest, &cert_digest_len) == GNUTLS_E_SUCCESS) {
      if (o_base64_encode(cert_digest, cert_digest_len, cert_id, cert_id_len)) {
        cert_id[*cert_id_len] = '\0';
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_certificate_id - Error o_base64_encode");
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_certificate_id - Error gnutls_fingerprint");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_certificate_id - Error gnutls_x509_crt_export2");
    ret = G_ERROR;
  }
  gnutls_free(dat.data);
  return ret;
}

static json_t * parse_certificate(const char * x509_data, int der_format) {
  json_t * j_return;
  gnutls_x509_crt_t cert = NULL;
  gnutls_datum_t cert_dat;
  char * dn = NULL, * issuer_dn = NULL;
  size_t key_id_enc_len = 256, dn_len = 0, issuer_dn_len = 0;
  time_t expires_at = 0, issued_at = 0;
  int ret;
  unsigned char * der_dec = NULL, key_id_enc[257] = {0};
  size_t der_dec_len = 0;
  
  if (o_strlen(x509_data)) {
    if (!gnutls_x509_crt_init(&cert)) {
      if (der_format) {
        cert_dat.data = NULL;
        cert_dat.size = 0;
        if (o_base64_decode((const unsigned char *)x509_data, o_strlen(x509_data), NULL, &der_dec_len)) {
          if ((der_dec = o_malloc(der_dec_len+1)) != NULL) {
            if (o_base64_decode((const unsigned char *)x509_data, o_strlen(x509_data), der_dec, &der_dec_len)) {
              cert_dat.data = der_dec;
              cert_dat.size = der_dec_len;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "parse_certificate - Error o_base64_decode (2)");
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "parse_certificate - Error allocating resources for der_dec");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "parse_certificate - Error o_base64_decode (1)");
        }
      } else {
        cert_dat.data = (unsigned char *)x509_data;
        cert_dat.size = o_strlen(x509_data);
      }
      if (gnutls_x509_crt_import(cert, &cert_dat, der_format?GNUTLS_X509_FMT_DER:GNUTLS_X509_FMT_PEM) >= 0) {
        ret = gnutls_x509_crt_get_issuer_dn(cert, NULL, &issuer_dn_len);
        if (gnutls_x509_crt_get_dn(cert, NULL, &dn_len) == GNUTLS_E_SHORT_MEMORY_BUFFER && (ret == GNUTLS_E_SHORT_MEMORY_BUFFER || ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)) {
          if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER) {
            if ((issuer_dn = o_malloc(issuer_dn_len +1)) != NULL) {
              if (gnutls_x509_crt_get_issuer_dn(cert, issuer_dn, &issuer_dn_len) < 0) {
                y_log_message(Y_LOG_LEVEL_ERROR, "parse_certificate - Error gnutls_x509_crt_get_issuer_dn");
                o_free(issuer_dn);
                issuer_dn = NULL;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "parse_certificate - Error o_malloc issuer_dn");
            }
          }
          if ((dn = o_malloc(dn_len +1)) != NULL) {
            if (gnutls_x509_crt_get_dn(cert, dn, &dn_len) >= 0) {
              dn[dn_len] = '\0';
              if (get_certificate_id(cert, key_id_enc, &key_id_enc_len) == G_OK && (expires_at = gnutls_x509_crt_get_expiration_time(cert)) != (time_t)-1 && (issued_at = gnutls_x509_crt_get_activation_time(cert)) != (time_t)-1) {
                j_return = json_pack("{sis{sssisisssssissss}}",
                                     "result",
                                     G_OK,
                                     "certificate",
                                       "certificate_id",
                                       key_id_enc,
                                       "activation",
                                       issued_at,
                                       "expiration",
                                       expires_at,
                                       "certificate_dn",
                                       dn,
                                       "certificate_issuer_dn",
                                       issuer_dn!=NULL?issuer_dn:"",
                                       "last_used",
                                       0,
                                       "last_user_agent",
                                       "",
                                       "x509",
                                       x509_data);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "parse_certificate - Error gnutls_x509_crt_get_key_id or gnutls_x509_crt_get_expiration_time or gnutls_x509_crt_get_activation_time");
                j_return = json_pack("{si}", "result", G_ERROR);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "parse_certificate - Error gnutls_x509_crt_get_dn (2)");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "parse_certificate - Error o_malloc dn");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          o_free(dn);
          o_free(issuer_dn);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "parse_certificate - Error gnutls_x509_crt_get_dn (1)");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "parse_certificate - Error gnutls_x509_crt_import");
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      }
      gnutls_x509_crt_deinit(cert);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "parse_certificate - Error gnutls_x509_crt_init");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(der_dec);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

static int update_user_certificate_scheme_storage(struct config_module * config, json_t * j_parameters, const char * username, const char * cert_id, int enabled) {
  json_t * j_query;
  int res, ret;
  
  j_query = json_pack("{sss{si}s{sOssss}}",
                      "table",
                      GLEWLWYD_SCHEME_CERTIFICATE_TABLE_USER_CERTIFICATE,
                      "set",
                        "gsuc_enabled",
                        enabled,
                      "where",
                        "gsuc_mod_name",
                        json_object_get(j_parameters, "mod_name"),
                        "gsuc_username",
                        username,
                        "gsuc_x509_certificate_id",
                        cert_id);
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "toggle_enabled_user_certificate_scheme_storage - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static int delete_user_certificate_scheme_storage(struct config_module * config, json_t * j_parameters, const char * username, const char * cert_id) {
  json_t * j_query;
  int res, ret;
  
  j_query = json_pack("{sss{sOssss}}",
                      "table",
                      GLEWLWYD_SCHEME_CERTIFICATE_TABLE_USER_CERTIFICATE,
                      "where",
                        "gsuc_mod_name",
                        json_object_get(j_parameters, "mod_name"),
                        "gsuc_username",
                        username,
                        "gsuc_x509_certificate_id",
                        cert_id);
  res = h_delete(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "delete_user_certificate_scheme_storage - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static json_t * get_user_certificate_from_id_user_property(struct config_module * config, json_t * j_parameters, const char * username, const char * cert_id) {
  json_t * j_user, * j_user_certificate, * j_parsed_certificate, * j_return = NULL, * j_element = NULL;
  size_t index = 0;
  
  j_user = config->glewlwyd_module_callback_get_user(config, username);
  if (check_result_value(j_user, G_OK)) {
    j_user_certificate = json_object_get(json_object_get(j_user, "user"), json_string_value(json_object_get(j_parameters, "user-certificate-property")));
    if (json_is_string(j_user_certificate)) {
      j_parsed_certificate = parse_certificate(json_string_value(j_user_certificate), (0 == o_strcmp("DER", json_string_value(json_object_get(j_parameters, "user-certificate-format")))));
      if (check_result_value(j_parsed_certificate, G_OK)) {
        if (0 == o_strcmp(cert_id, json_string_value(json_object_get(json_object_get(j_parsed_certificate, "certificate"), "certificate_id")))) {
          j_return = json_pack("{sisO}", "result", G_OK, "certificate", json_object_get(j_parsed_certificate, "certificate"));
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_certificate_from_id_user_property certificate - Error parse_certificate (1)");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_parsed_certificate);
    } else if (json_is_array(j_user_certificate)) {
      json_array_foreach(j_user_certificate, index, j_element) {
        j_parsed_certificate = parse_certificate(json_string_value(j_element), (0 == o_strcmp("DER", json_string_value(json_object_get(j_parameters, "user-certificate-format")))));
        if (check_result_value(j_parsed_certificate, G_OK)) {
          if (0 == o_strcmp(cert_id, json_string_value(json_object_get(json_object_get(j_parsed_certificate, "certificate"), "certificate_id")))) {
            j_return = json_pack("{sisO}", "result", G_OK, "certificate", json_object_get(j_parsed_certificate, "certificate"));
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_user_certificate_from_id_user_property certificate - Error parse_certificate (2)");
        }
        json_decref(j_parsed_certificate);
      }
      if (j_return == NULL) {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
    } else {
      j_return = json_pack("{sis[]}", "result", G_OK, "certificate");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_certificate_from_id_user_property certificate - Error glewlwyd_module_callback_get_user");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_user);
  return j_return;
}

static json_t * get_user_certificate_list_user_property(struct config_module * config, json_t * j_parameters, const char * username) {
  json_t * j_user, * j_user_certificate, * j_parsed_certificate, * j_return, * j_element = NULL;
  size_t index = 0;
  
  j_user = config->glewlwyd_module_callback_get_user(config, username);
  if (check_result_value(j_user, G_OK)) {
    j_user_certificate = json_object_get(json_object_get(j_user, "user"), json_string_value(json_object_get(j_parameters, "user-certificate-property")));
    if (json_is_string(j_user_certificate)) {
      j_parsed_certificate = parse_certificate(json_string_value(j_user_certificate), (0 == o_strcmp("DER", json_string_value(json_object_get(j_parameters, "user-certificate-format")))));
      if (check_result_value(j_parsed_certificate, G_OK)) {
        json_object_del(json_object_get(j_parsed_certificate, "certificate"), "x509");
        j_return = json_pack("{sis[O]}", "result", G_OK, "certificate", json_object_get(j_parsed_certificate, "certificate"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_can_use certificate - Error parse_certificate (1)");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_parsed_certificate);
    } else if (json_is_array(j_user_certificate)) {
      if ((j_return = json_pack("{sis[]}", "result", G_OK, "certificate")) != NULL) {
        json_array_foreach(j_user_certificate, index, j_element) {
          j_parsed_certificate = parse_certificate(json_string_value(j_element), (0 == o_strcmp("DER", json_string_value(json_object_get(j_parameters, "user-certificate-format")))));
          if (check_result_value(j_parsed_certificate, G_OK)) {
            json_object_del(json_object_get(j_parsed_certificate, "certificate"), "x509");
            json_array_append(json_object_get(j_return, "certificate"), json_object_get(j_parsed_certificate, "certificate"));
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_can_use certificate - Error parse_certificate (2)");
          }
          json_decref(j_parsed_certificate);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_can_use certificate - Error allocating resources for j_return");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else {
      j_return = json_pack("{sis[]}", "result", G_OK, "certificate");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_can_use certificate - Error glewlwyd_module_callback_get_user");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_user);
  return j_return;
}

static json_t * get_user_certificate_from_id_scheme_storage(struct config_module * config, json_t * j_parameters, const char * username, const char * cert_id) {
  json_t * j_query, * j_result, * j_return;
  int res;

  j_query = json_pack("{sss[ssssssss]s{sOssss}}",
                      "table",
                      GLEWLWYD_SCHEME_CERTIFICATE_TABLE_USER_CERTIFICATE,
                      "columns",
                        "gsuc_x509_certificate_dn AS certificate_dn",
                        "gsuc_x509_certificate_issuer_dn AS certificate_issuer_dn",
                        "gsuc_x509_certificate_id AS certificate_id",
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gsuc_activation) AS activation", "strftime('%s', gsuc_activation) AS activation", "EXTRACT(EPOCH FROM gsuc_activation)::integer AS activation"),
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gsuc_expiration) AS expiration", "strftime('%s', gsuc_expiration) AS expiration", "EXTRACT(EPOCH FROM gsuc_expiration)::integer AS expiration"),
                        "gsuc_enabled",
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gsuc_last_used) AS last_used", "strftime('%s', gsuc_last_used) AS last_used", "EXTRACT(EPOCH FROM gsuc_last_used)::integer AS last_used"),
                        "gsuc_last_user_agent AS last_user_agent",
                      "where",
                        "gsuc_mod_name",
                        json_object_get(j_parameters, "mod_name"),
                        "gsuc_username",
                        username,
                        "gsuc_x509_certificate_id",
                        cert_id);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gsuc_enabled"))) {
        json_object_set(json_array_get(j_result, 0), "enabled", json_true());
      } else {
        json_object_set(json_array_get(j_result, 0), "enabled", json_false());
      }
      json_object_del(json_array_get(j_result, 0), "gsuc_enabled");
      j_return = json_pack("{sisO}", "result", G_OK, "certificate", json_array_get(j_result, 0));
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "get_user_certificate_from_id_scheme_storage - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static json_t * get_user_certificate_list_scheme_storage(struct config_module * config, json_t * j_parameters, const char * username, int enabled) {
  json_t * j_query, * j_result, * j_return, * j_element = NULL;
  int res;
  size_t index = 0;
  
  j_query = json_pack("{sss[ssssssss]s{sOss}ss}",
                      "table",
                      GLEWLWYD_SCHEME_CERTIFICATE_TABLE_USER_CERTIFICATE,
                      "columns",
                        "gsuc_x509_certificate_dn AS certificate_dn",
                        "gsuc_x509_certificate_issuer_dn AS certificate_issuer_dn",
                        "gsuc_x509_certificate_id AS certificate_id",
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gsuc_activation) AS activation", "strftime('%s', gsuc_activation) AS activation", "EXTRACT(EPOCH FROM gsuc_activation)::integer AS activation"),
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gsuc_expiration) AS expiration", "strftime('%s', gsuc_expiration) AS expiration", "EXTRACT(EPOCH FROM gsuc_expiration)::integer AS expiration"),
                        "gsuc_enabled",
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gsuc_last_used) AS last_used", "strftime('%s', gsuc_last_used) AS last_used", "EXTRACT(EPOCH FROM gsuc_last_used)::integer AS last_used"),
                        "gsuc_last_user_agent AS last_user_agent",
                      "where",
                        "gsuc_mod_name",
                        json_object_get(j_parameters, "mod_name"),
                        "gsuc_username",
                        username,
                      "order_by",
                      "gsuc_id");
  if (enabled) {
    json_object_set_new(json_object_get(j_query, "where"), "gsuc_enabled", json_integer(1));
  }
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      if (json_integer_value(json_object_get(j_element, "gsuc_enabled"))) {
        json_object_set(j_element, "enabled", json_true());
      } else {
        json_object_set(j_element, "enabled", json_false());
      }
      json_object_del(j_element, "gsuc_enabled");
    }
    j_return = json_pack("{sisO}", "result", G_OK, "certificate", j_result);
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_certificate_list - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static struct _cert_chain_element * get_cert_chain_element_from_dn(struct _cert_param * cert_params, const char * dn) {
  size_t i;
  struct _cert_chain_element * cert_chain_element = NULL;
  
  for (i=0; i<cert_params->cert_array_len; i++) {
    if (0 == o_strcmp(dn, cert_params->cert_array[i]->dn)) {
      cert_chain_element = cert_params->cert_array[i];
      break;
    }
  }
  
  return cert_chain_element;
}

static int add_user_certificate_scheme_storage(struct config_module * config, json_t * j_parameters, const char * x509_data, const char * username, const char * user_agent) {
  json_t * j_query, * j_parsed_certificate, * j_result;
  char * expiration_clause, * activation_clause;
  int res, ret;
  
  if (o_strlen(x509_data)) {
    j_parsed_certificate = parse_certificate(x509_data, 0);
    if (check_result_value(j_parsed_certificate, G_OK)) {
      j_result = get_user_certificate_from_id_scheme_storage(config, j_parameters, username, json_string_value(json_object_get(json_object_get(j_parsed_certificate, "certificate"), "certificate_id")));
      if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
        if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
          expiration_clause = msprintf("FROM_UNIXTIME(%"JSON_INTEGER_FORMAT")", json_integer_value(json_object_get(json_object_get(j_parsed_certificate, "certificate"), "expiration")));
          activation_clause = msprintf("FROM_UNIXTIME(%"JSON_INTEGER_FORMAT")", json_integer_value(json_object_get(json_object_get(j_parsed_certificate, "certificate"), "activation")));
        } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
          expiration_clause = msprintf("TO_TIMESTAMP(%"JSON_INTEGER_FORMAT")", json_integer_value(json_object_get(json_object_get(j_parsed_certificate, "certificate"), "expiration")));
          activation_clause = msprintf("TO_TIMESTAMP(%"JSON_INTEGER_FORMAT")", json_integer_value(json_object_get(json_object_get(j_parsed_certificate, "certificate"), "activation")));
        } else { // HOEL_DB_TYPE_SQLITE
          expiration_clause = msprintf("%"JSON_INTEGER_FORMAT"", json_integer_value(json_object_get(json_object_get(j_parsed_certificate, "certificate"), "expiration")));
          activation_clause = msprintf("%"JSON_INTEGER_FORMAT"", json_integer_value(json_object_get(json_object_get(j_parsed_certificate, "certificate"), "activation")));
        }
        j_query = json_pack("{ss s{sO ss sO sO sO sO s{ss} s{ss} so}}",
                            "table",
                            GLEWLWYD_SCHEME_CERTIFICATE_TABLE_USER_CERTIFICATE,
                            "values",
                              "gsuc_mod_name",
                              json_object_get(j_parameters, "mod_name"),
                              "gsuc_username",
                              username,
                              "gsuc_x509_certificate_id",
                              json_object_get(json_object_get(j_parsed_certificate, "certificate"), "certificate_id"),
                              "gsuc_x509_certificate_content",
                              json_object_get(json_object_get(j_parsed_certificate, "certificate"), "x509"),
                              "gsuc_x509_certificate_dn",
                              json_object_get(json_object_get(j_parsed_certificate, "certificate"), "certificate_dn"),
                              "gsuc_x509_certificate_issuer_dn",
                              json_object_get(json_object_get(j_parsed_certificate, "certificate"), "certificate_issuer_dn"),
                              "gsuc_expiration",
                                "raw",
                                expiration_clause,
                              "gsuc_activation",
                                "raw",
                                activation_clause,
                              "gsuc_last_used",
                              json_null());
        o_free(expiration_clause);
        o_free(activation_clause);
        if (o_strlen(user_agent)) {
          json_object_set_new(json_object_get(j_query, "values"), "gsuc_last_user_agent", json_string(user_agent));
        }
        res = h_insert(config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "add_user_certificate_scheme_storage - Error executing j_query");
          ret = G_ERROR_DB;
        }
      } else if (check_result_value(j_result, G_OK)) {
        ret = G_ERROR_PARAM;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_user_certificate_scheme_storage - Error get_user_certificate_from_id_scheme_storage");
        ret = G_ERROR;
      }
      json_decref(j_result);
    } else if (check_result_value(j_parsed_certificate, G_ERROR_PARAM)) {
      ret = G_ERROR_PARAM;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_user_certificate_scheme_storage - Error parse_certificate");
      ret = G_ERROR;
    }
    json_decref(j_parsed_certificate);
  } else {
    ret = G_ERROR_PARAM;
  }

  return ret;
}

static void scm_gnutls_certificate_status_to_c_string (gnutls_certificate_status_t c_obj) {
  static const struct { 
    gnutls_certificate_status_t value; 
    const char* name; 
  } table[] =
    {
       { GNUTLS_CERT_INVALID, "invalid" },
       { GNUTLS_CERT_REVOKED, "revoked" },
       { GNUTLS_CERT_SIGNER_NOT_FOUND, "signer-not-found" },
       { GNUTLS_CERT_SIGNER_NOT_CA, "signer-not-ca" },
       { GNUTLS_CERT_INSECURE_ALGORITHM, "insecure-algorithm" },
    };
  unsigned i;
  for (i = 0; i < 5; i++)
    {
      if (table[i].value & c_obj)
        {
          y_log_message(Y_LOG_LEVEL_DEBUG, "%s", table[i].name);
        }
    }
}

static int is_certificate_valid_from_ca_chain(struct _cert_param * cert_params, gnutls_x509_crt_t cert) {
  int ret = G_OK, res;
  unsigned int result = 0;
  gnutls_x509_crt_t * cert_chain = NULL, root_x509 = NULL;
  gnutls_x509_trust_list_t tlist = NULL;
  size_t cert_chain_len = 0, issuer_dn_len = 0;
  char * issuer_dn = NULL;
  struct _cert_chain_element * cert_chain_element;
  
  if ((res = gnutls_x509_crt_get_issuer_dn(cert, NULL, &issuer_dn_len)) == GNUTLS_E_SHORT_MEMORY_BUFFER) {
    if ((issuer_dn = o_malloc(issuer_dn_len+1)) != NULL && gnutls_x509_crt_get_issuer_dn(cert, issuer_dn, &issuer_dn_len) >= 0) {
      // Calculate ca chain length
      cert_chain_len = 1;
      cert_chain_element = get_cert_chain_element_from_dn(cert_params, issuer_dn);
      while (cert_chain_element != NULL) {
        if (cert_chain_element->issuer_cert == NULL) {
          root_x509 = cert_chain_element->cert;
        }
        cert_chain_len++;
        cert_chain_element = cert_chain_element->issuer_cert;
      }
      if (root_x509 != NULL) {
        if ((cert_chain = o_malloc(cert_chain_len*sizeof(gnutls_x509_crt_t))) != NULL) {
          cert_chain[0] = cert;
          cert_chain_len = 1;
          cert_chain_element = get_cert_chain_element_from_dn(cert_params, issuer_dn);
          while (cert_chain_element != NULL) {
            cert_chain[cert_chain_len] = cert_chain_element->cert;
            cert_chain_len++;
            cert_chain_element = cert_chain_element->issuer_cert;
          }
          if (!gnutls_x509_trust_list_init(&tlist, 0)) {
            if (gnutls_x509_trust_list_add_cas(tlist, &root_x509, 1, 0) >= 0) {
              if (gnutls_x509_trust_list_verify_crt(tlist, cert_chain, cert_chain_len, 0, &result, NULL) >= 0) {
                if (!result) {
                  ret = G_OK;
                } else {
                  y_log_message(Y_LOG_LEVEL_DEBUG, "is_certificate_valid_from_ca_chain - certificate chain invalid");
                  scm_gnutls_certificate_status_to_c_string(result);
                  ret = G_ERROR_UNAUTHORIZED;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "is_certificate_valid_from_ca_chain - Error gnutls_x509_trust_list_verify_crt");
                ret = G_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "is_certificate_valid_from_ca_chain - Error gnutls_x509_trust_list_add_cas");
              ret = G_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "is_certificate_valid_from_ca_chain - Error gnutls_x509_trust_list_init");
            ret = G_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "is_certificate_valid_from_ca_chain - Error allocating resources for cert_chain");
          ret = G_ERROR;
        }
        o_free(cert_chain);
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "is_certificate_valid_from_ca_chain - no root certificate found");
        ret = G_ERROR_UNAUTHORIZED;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_certificate_valid_from_ca_chain - Error gnutls_x509_crt_get_issuer_dn (2)");
      ret = G_ERROR;
    }
  } else if (res == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
    ret = G_ERROR_UNAUTHORIZED;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_certificate_valid_from_ca_chain - Error gnutls_x509_crt_get_issuer_dn (1)");
    ret = G_ERROR;
  }
  o_free(issuer_dn);
  gnutls_x509_trust_list_deinit(tlist, 0);
  
  return ret;
}

static int is_user_certificate_valid_user_property(struct config_module * config, json_t * j_parameters, const char * username, gnutls_x509_crt_t cert) {
  json_t * j_user_list = get_user_certificate_list_user_property(config, j_parameters, username), * j_element = NULL;
  int ret;
  unsigned char key_id_enc[256] = {0};
  size_t index = 0, key_id_enc_len = 0;
  
  if (check_result_value(j_user_list, G_OK)) {
    if (get_certificate_id(cert, key_id_enc, &key_id_enc_len) == G_OK) {
      ret = G_ERROR_UNAUTHORIZED;
      json_array_foreach(json_object_get(j_user_list, "certificate"), index, j_element) {
        if (0 == o_strcmp((const char *)key_id_enc, json_string_value(json_object_get(j_element, "certificate_id")))) {
          ret = G_OK;
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_user_certificate_valid_user_property - Error gnutls_x509_crt_get_key_id");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_user_certificate_valid_user_property - Error get_user_certificate_list_user_property");
    ret = G_ERROR;
  }
  json_decref(j_user_list);
  
  return ret;
}

static int is_user_certificate_valid_scheme_storage(struct config_module * config, json_t * j_parameters, const char * username, gnutls_x509_crt_t cert) {
  int ret, res;
  json_t * j_query, * j_result;
  unsigned char key_id_enc[256] = {0};
  size_t key_id_enc_len = 0;
  
  if (get_certificate_id(cert, key_id_enc, &key_id_enc_len) == G_OK) {
    key_id_enc[key_id_enc_len] = '\0';
    j_query = json_pack("{sss[s]s{sOsssssi}}",
                        "table",
                        GLEWLWYD_SCHEME_CERTIFICATE_TABLE_USER_CERTIFICATE,
                        "columns",
                          "gsuc_id",
                        "where",
                          "gsuc_mod_name",
                          json_object_get(j_parameters, "mod_name"),
                          "gsuc_username",
                          username,
                          "gsuc_x509_certificate_id",
                          key_id_enc,
                          "gsuc_enabled",
                          1);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        ret = G_OK;
      } else {
        ret = G_ERROR_UNAUTHORIZED;
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_user_certificate_valid_scheme_storage - Error executing j_query");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_user_certificate_valid_scheme_storage - Error get_certificate_id");
    ret = G_ERROR;
  }
  
  return ret;
}

static int is_user_certificate_valid(struct config_module * config, json_t * j_parameters, const char * username, gnutls_x509_crt_t cert) {
  if (json_object_get(j_parameters, "use-scheme-storage") == json_true()) {
    return is_user_certificate_valid_scheme_storage(config, j_parameters, username, cert);
  } else {
    return is_user_certificate_valid_user_property(config, j_parameters, username, cert);
  }
}

static void update_cert_chain_issuer(struct _cert_chain_element ** ca_chain, size_t cert_array_len, struct _cert_chain_element * cur_ca) {
  size_t i;
  
  for (i=0; i<cert_array_len; i++) {
    if (0 == o_strcmp(ca_chain[i]->dn, cur_ca->issuer_dn)) {
      cur_ca->issuer_cert = ca_chain[i];
    }
    if (0 == o_strcmp(ca_chain[i]->issuer_dn, cur_ca->dn)) {
      ca_chain[i]->issuer_cert = cur_ca;
    }
  }
}

static int parse_ca_chain(json_t * j_ca_chain, struct _cert_chain_element *** ca_chain, size_t * cert_array_len) {
  json_t * j_element = NULL;
  size_t index = 0, len = 0;
  int ret = G_OK, cur_status, res;
  gnutls_x509_crt_t cert;
  struct _cert_chain_element * cur_ca;
  gnutls_datum_t cert_dat;
  
  *ca_chain = NULL;
  *cert_array_len = 0;
  UNUSED(j_ca_chain);
  
  if (j_ca_chain != NULL) {
    json_array_foreach(j_ca_chain, index, j_element) {
      cert = NULL;
      cur_status = G_OK;
      if (!gnutls_x509_crt_init(&cert)) {
        cert_dat.data = (unsigned char *)json_string_value(json_object_get(j_element, "cert-file"));
        cert_dat.size = json_string_length(json_object_get(j_element, "cert-file"));
        if ((res = gnutls_x509_crt_import(cert, &cert_dat, GNUTLS_X509_FMT_PEM)) < 0) {
          y_log_message(Y_LOG_LEVEL_ERROR, "parse_ca_chain - Error gnutls_x509_crt_import: %d", res);
          cur_status = G_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "parse_ca_chain - Error gnutls_x509_crt_init");
        cur_status = G_ERROR;
      }
      if (cur_status == G_OK) {
        cur_ca = o_malloc(sizeof(struct _cert_chain_element));
        cur_ca->cert = cert;
        cur_ca->dn = NULL;
        cur_ca->issuer_dn = NULL;
        cur_ca->issuer_cert = NULL;
        len = 0;
        if (gnutls_x509_crt_get_dn(cert, NULL, &len) == GNUTLS_E_SHORT_MEMORY_BUFFER) {
          if ((cur_ca->dn = o_malloc(len+1)) == NULL || gnutls_x509_crt_get_dn(cert, cur_ca->dn, &len) < 0) {
            y_log_message(Y_LOG_LEVEL_ERROR, "parse_ca_chain - Error gnutls_x509_crt_get_dn (2) on cert at index %zu", index);
            cur_status = G_ERROR;
          } else {
            cur_ca->dn[len] = '\0';
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "parse_ca_chain - Error gnutls_x509_crt_get_dn (1) on cert at index %zu", index);
          cur_status = G_ERROR;
        }
        if (cur_status == G_OK) {
          len = 0;
          if ((res = gnutls_x509_crt_get_issuer_dn(cert, NULL, &len)) == GNUTLS_E_SHORT_MEMORY_BUFFER) {
            if ((cur_ca->issuer_dn = o_malloc(len+1)) == NULL || gnutls_x509_crt_get_issuer_dn(cert, cur_ca->issuer_dn, &len) < 0) {
              y_log_message(Y_LOG_LEVEL_ERROR, "parse_ca_chain - Error gnutls_x509_crt_get_issuer_dn (2) on cert at index %zu", index);
              cur_status = G_ERROR;
            } else {
              cur_ca->issuer_dn[len] = '\0';
            }
          } else if (res != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
            y_log_message(Y_LOG_LEVEL_ERROR, "parse_ca_chain - Error gnutls_x509_crt_get_issuer_dn (1) on cert at index %zu", index);
            cur_status = G_ERROR;
          }
        }
        if (cur_status == G_OK) {
          update_cert_chain_issuer(*ca_chain, *cert_array_len, cur_ca);
          *ca_chain = o_realloc(*ca_chain, ((*cert_array_len)+1)*sizeof(struct _cert_chain_element *));
          if (*ca_chain != NULL) {
            (*ca_chain)[*cert_array_len] = cur_ca;
            (*cert_array_len)++;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "parse_ca_chain - Error alocatig resources for ca_chain at index %zu", index);
            gnutls_x509_crt_deinit(cert);
            o_free(cur_ca->issuer_dn);
            o_free(cur_ca->dn);
            o_free(cur_ca);
          }
        } else {
          gnutls_x509_crt_deinit(cert);
          o_free(cur_ca->issuer_dn);
          o_free(cur_ca->dn);
          o_free(cur_ca);
        }
      } else {
        gnutls_x509_crt_deinit(cert);
      }
      if (cur_status != G_OK) {
        ret = cur_status;
        break;
      }
    }
  }
  return ret;
}

static json_t * is_certificate_parameters_valid(json_t * j_parameters) {
  json_t * j_array = json_array(), * j_return, * j_element = NULL;
  size_t index = 0;
  
  if (j_array != NULL) {
    if (json_is_object(j_parameters)) {
      if (json_object_get(j_parameters, "cert-source") != NULL && 0 != o_strcmp("TLS", json_string_value(json_object_get(j_parameters, "cert-source"))) && 0 != o_strcmp("header", json_string_value(json_object_get(j_parameters, "cert-source"))) && 0 != o_strcmp("both", json_string_value(json_object_get(j_parameters, "cert-source")))) {
        json_array_append_new(j_array, json_string("cert-source is optional and must be one of the following values: 'TLS', 'header' or 'both'"));
      }
      if ((0 == o_strcmp("header", json_string_value(json_object_get(j_parameters, "cert-source"))) || 0 == o_strcmp("both", json_string_value(json_object_get(j_parameters, "cert-source")))) && !json_string_length(json_object_get(j_parameters, "header-name"))) {
        json_array_append_new(j_array, json_string("header-name is mandatory when cert-source is 'header' or 'both' and must be a non empty string"));
      }
      if (json_object_get(j_parameters, "use-scheme-storage") != NULL && !json_is_boolean(json_object_get(j_parameters, "use-scheme-storage"))) {
        json_array_append_new(j_array, json_string("use-scheme-storage is optional and must be a boolean"));
      }
      if (json_object_get(j_parameters, "use-scheme-storage") != json_true() && !json_string_length(json_object_get(j_parameters, "user-certificate-property"))) {
        json_array_append_new(j_array, json_string("user-certificate-property is mandatory and must be a non empty string"));
      }
      if (json_object_get(j_parameters, "use-scheme-storage") != json_true() && json_object_get(j_parameters, "user-certificate-format") != NULL && 0 != o_strcmp("PEM", json_string_value(json_object_get(j_parameters, "user-certificate-format"))) && 0 != o_strcmp("DER", json_string_value(json_object_get(j_parameters, "user-certificate-format")))) {
        json_array_append_new(j_array, json_string("user-certificate-format is optional and must be one of the following values: 'PEM' or 'DER'"));
      }
      if (json_object_get(j_parameters, "ca-chain") != NULL && !json_is_array(json_object_get(j_parameters, "ca-chain"))) {
        json_array_append_new(j_array, json_string("ca-chain is optional and must be an array of JSON objects"));
      } else {
        json_array_foreach(json_object_get(j_parameters, "ca-chain"), index, j_element) {
          if (!json_is_object(j_element) || !json_string_length(json_object_get(j_element, "file-name")) || !json_string_length(json_object_get(j_element, "cert-file"))) {
            json_array_append_new(j_array, json_string("A ca-chain object must have the format {file-name: '', cert-file: ''} with non empty string values"));
          }
        }
      }
      if (json_object_get(j_parameters, "request-certificate") != NULL && !json_is_object(json_object_get(j_parameters, "request-certificate"))) {
        json_array_append_new(j_array, json_string("request-certificate is optional and must be a JSON object"));
      } else if (json_object_get(j_parameters, "request-certificate") != NULL) {
        if (!json_is_object(json_object_get(json_object_get(j_parameters, "request-certificate"), "issuer-cert")) || !json_string_length(json_object_get(json_object_get(json_object_get(j_parameters, "request-certificate"), "issuer-cert"), "file-name")) || !json_string_length(json_object_get(json_object_get(json_object_get(j_parameters, "request-certificate"), "issuer-cert"), "cert-file"))) {
          json_array_append_new(j_array, json_string("request-certificate.issuer-cert is mandatory and must be a JSON object with the format {file-name: '', cert-file: ''} with non empty string values"));
        }
        if (!json_is_object(json_object_get(json_object_get(j_parameters, "request-certificate"), "issuer-key")) || !json_string_length(json_object_get(json_object_get(json_object_get(j_parameters, "request-certificate"), "issuer-key"), "file-name")) || !json_string_length(json_object_get(json_object_get(json_object_get(j_parameters, "request-certificate"), "issuer-key"), "cert-file"))) {
          json_array_append_new(j_array, json_string("request-certificate.issuer-key is mandatory and must be a JSON object with the format {file-name: '', cert-file: ''} with non empty string values"));
        }
        if (json_integer_value(json_object_get(json_object_get(j_parameters, "request-certificate"), "expiration")) <= 0) {
          json_array_append_new(j_array, json_string("request-certificate.expiration is mandatory and must be a positive integer"));
        }
        if (!json_string_length(json_object_get(json_object_get(j_parameters, "request-certificate"), "dn-format"))) {
          json_array_append_new(j_array, json_string("request-certificate.dn-format is mandatory and must be a non empty string"));
        }
        if (json_object_get(json_object_get(j_parameters, "request-certificate"), "allow-multiple") != NULL && !json_is_boolean(json_object_get(json_object_get(j_parameters, "request-certificate"), "allow-multiple"))) {
          json_array_append_new(j_array, json_string("request-certificate.allow-multiple is optional and must be a boolean, default false"));
        }
      }
    } else {
      json_array_append_new(j_array, json_string("certificate parameters must be a JSON object"));
    }
    if (!json_array_size(j_array)) {
      j_return = json_pack("{si}", "result", G_OK);
    } else {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_array);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_certificate_parameters_valid - Error allocating resources for j_array");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  json_decref(j_array);
  return j_return;
}

/**
 * 
 * user_auth_scheme_module_load
 * 
 * Executed once when Glewlwyd service is started
 * Used to identify the module and to show its parameters on init
 * You can also use it to load resources that are required once for all
 * instance modules for example
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  name: string, mandatory, name of the module, must be unique among other scheme modules
 *                  display_name: string, optional, long name of the module
 *                  description: string, optional, description for the module
 *                  parameters: object, optional, parameters description for the module
 *                }
 * 
 *                Example:
 *                {
 *                  result: G_OK,
 *                  name: "mock",
 *                  display_name: "Mock scheme module",
 *                  description: "Mock scheme module for glewlwyd tests",
 *                  parameters: {
 *                    mock-value: {
 *                      type: "string",
 *                      mandatory: true
 *                    }
 *                  }
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * 
 */
json_t * user_auth_scheme_module_load(struct config_module * config) {
  UNUSED(config);
  return json_pack("{sisssssss{s{ssso}}}",
                   "result",
                   G_OK,
                   "name",
                   "certificate",
                   "display_name",
                   "Client certificate",
                   "description",
                   "Client certificate scheme module",
                   "parameters",
                     "cert-chain",
                       "type",
                       "list",
                       "mandatory",
                       json_true());
}

/**
 * 
 * user_auth_scheme_module_unload
 * 
 * Executed once when Glewlwyd service is stopped
 * You can also use it to release resources that are required once for all
 * instance modules for example
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * 
 */
int user_auth_scheme_module_unload(struct config_module * config) {
  UNUSED(config);
  return G_OK;
}

/**
 * 
 * user_auth_scheme_module_init
 * 
 * Initialize an instance of this module declared in Glewlwyd service.
 * If required, you must dynamically allocate a pointer to the configuration
 * for this instance and pass it to *cls
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter j_parameters: used to initialize an instance in JSON format
 *                          The module must validate itself its parameters
 * @parameter mod_name: module name in glewlwyd service
 * @parameter cls: will contain an allocated void * pointer that will be sent back
 *                 as void * in all module functions
 * 
 */
json_t * user_auth_scheme_module_init(struct config_module * config, json_t * j_parameters, const char * mod_name, void ** cls) {
  UNUSED(config);
  UNUSED(mod_name);
  pthread_mutexattr_t mutexattr;
  json_t * j_result = is_certificate_parameters_valid(j_parameters), * j_return;
  
  if (check_result_value(j_result, G_OK)) {
    json_object_set_new(j_parameters, "mod_name", json_string(mod_name));
    if ((*cls = o_malloc(sizeof(struct _cert_param))) != NULL) {
      pthread_mutexattr_init ( &mutexattr );
      pthread_mutexattr_settype( &mutexattr, PTHREAD_MUTEX_RECURSIVE );
      if (!pthread_mutex_init(&((struct _cert_param *)*cls)->cert_request_lock, &mutexattr)) {
        ((struct _cert_param *)*cls)->cert_source = 0;
        ((struct _cert_param *)*cls)->cert_array_len = 0;
        ((struct _cert_param *)*cls)->cert_array = NULL;
        if (json_object_get(j_parameters, "cert-source") == NULL || 0 == o_strcmp("TLS", json_string_value(json_object_get(j_parameters, "cert-source")))) {
          ((struct _cert_param *)*cls)->cert_source = G_CERT_SOURCE_TLS;
        } else if (0 == o_strcmp("header", json_string_value(json_object_get(j_parameters, "cert-source")))) {
          ((struct _cert_param *)*cls)->cert_source = G_CERT_SOURCE_HEADER;
        } else {
          ((struct _cert_param *)*cls)->cert_source = G_CERT_SOURCE_TLS|G_CERT_SOURCE_HEADER;
        }
        if (parse_ca_chain(json_object_get(j_parameters, "ca-chain"), &(((struct _cert_param *)*cls)->cert_array), &(((struct _cert_param *)*cls)->cert_array_len)) == G_OK) {
          ((struct _cert_param *)*cls)->j_parameters = json_incref(j_parameters);
          j_return = json_pack("{si}", "result", G_OK);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init certificate - Error parse_ca_chain");
          o_free(*cls);
          *cls = NULL;
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init certificate - Error pthread_mutex_init");
        o_free(*cls);
        *cls = NULL;
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init certificate - Error allocating resources for cls");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else if (check_result_value(j_result, G_ERROR_PARAM)) {
    j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", json_object_get(j_result, "error"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init certificate - Error is_certificate_parameters_valid");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_result);
  return j_return;
}

/**
 * 
 * user_auth_scheme_module_close
 * 
 * Close an instance of this module declared in Glewlwyd service.
 * You must free the memory previously allocated in
 * the user_auth_scheme_module_init function as void * cls
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_close(struct config_module * config, void * cls) {
  UNUSED(config);
  size_t i;
  
  pthread_mutex_destroy(&((struct _cert_param *)cls)->cert_request_lock);
  json_decref(((struct _cert_param *)cls)->j_parameters);
  for (i=0; i<((struct _cert_param *)cls)->cert_array_len; i++) {
    o_free(((struct _cert_param *)cls)->cert_array[i]->dn);
    o_free(((struct _cert_param *)cls)->cert_array[i]->issuer_dn);
    gnutls_x509_crt_deinit(((struct _cert_param *)cls)->cert_array[i]->cert);
    o_free(((struct _cert_param *)cls)->cert_array[i]);
  }
  o_free(((struct _cert_param *)cls)->cert_array);
  o_free(((struct _cert_param *)cls));
  return G_OK;
}

/**
 * 
 * user_auth_scheme_module_can_use
 * 
 * Validate if the user is allowed to use this scheme prior to the
 * authentication or registration
 * 
 * @return value: GLEWLWYD_IS_REGISTERED - User can use scheme and has registered
 *                GLEWLWYD_IS_AVAILABLE - User can use scheme but hasn't registered
 *                GLEWLWYD_IS_NOT_AVAILABLE - User can't use scheme
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: username to identify the user
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_can_use(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  json_t * j_user_certificate = NULL;
  int ret = GLEWLWYD_IS_NOT_AVAILABLE;
  
  if (json_object_get(((struct _cert_param *)cls)->j_parameters, "use-scheme-storage") != json_true()) {
    j_user_certificate = get_user_certificate_list_user_property(config, ((struct _cert_param *)cls)->j_parameters, username);
    ret = (check_result_value(j_user_certificate, G_OK) && json_array_size(json_object_get(j_user_certificate, "certificate")))?GLEWLWYD_IS_REGISTERED:GLEWLWYD_IS_AVAILABLE;
    json_decref(j_user_certificate);
  } else {
    j_user_certificate = get_user_certificate_list_scheme_storage(config, ((struct _cert_param *)cls)->j_parameters, username, 1);
    ret = (check_result_value(j_user_certificate, G_OK) && json_array_size(json_object_get(j_user_certificate, "certificate")))?GLEWLWYD_IS_REGISTERED:GLEWLWYD_IS_AVAILABLE;
    json_decref(j_user_certificate);
  }
  return ret;
}

/**
 * 
 * user_auth_scheme_module_register
 * 
 * Register the scheme for a user
 * Ex: add a certificate, add new TOTP values, etc.
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  response: JSON object, optional
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the HTTP API
 * @parameter username: username to identify the user
 * @parameter j_scheme_data: additional data used to register the scheme for the user
 *                           in JSON format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
json_t * user_auth_scheme_module_register(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls) {
  json_t * j_return, * j_result;
  int ret, clean_cert = 0;
  char * x509_data = NULL;
  const char * header_cert = NULL;
  unsigned char key_id_enc[257] = {0};
  size_t key_id_enc_len = 256;
  gnutls_x509_crt_t cert = NULL;
  gnutls_datum_t cert_dat;
  
  if (0 == o_strcmp("test-certificate", json_string_value(json_object_get(j_scheme_data, "register")))) {
    ret = user_auth_scheme_module_validate(config, http_request, username, NULL, cls);
    if (ret == G_OK) {
      if ((((struct _cert_param *)cls)->cert_source & G_CERT_SOURCE_TLS) && http_request->client_cert != NULL) {
        cert = http_request->client_cert;
      } else if ((((struct _cert_param *)cls)->cert_source & G_CERT_SOURCE_HEADER) && (header_cert = u_map_get(http_request->map_header, json_string_value(json_object_get(((struct _cert_param *)cls)->j_parameters, "header-name")))) != NULL) {
        if (!gnutls_x509_crt_init(&cert)) {
          clean_cert = 1;
          cert_dat.data = (unsigned char *)header_cert;
          cert_dat.size = o_strlen(header_cert);
          if (gnutls_x509_crt_import(cert, &cert_dat, GNUTLS_X509_FMT_PEM) < 0) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "user_auth_scheme_module_validate certificate - Error gnutls_x509_crt_import");
            ret = G_ERROR_UNAUTHORIZED;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "user_auth_scheme_module_validate certificate - Error gnutls_x509_crt_init");
          ret = G_ERROR_UNAUTHORIZED;
        }
        ret = G_ERROR_UNAUTHORIZED;
      }
      if (cert != NULL) {
        if (get_certificate_id(cert, key_id_enc, &key_id_enc_len) == G_OK) {
          key_id_enc[key_id_enc_len] = '\0';
          if (json_object_get(((struct _cert_param *)cls)->j_parameters, "use-scheme-storage") == json_true()) {
            j_result = get_user_certificate_from_id_scheme_storage(config, ((struct _cert_param *)cls)->j_parameters, username, (const char *)key_id_enc);
            if (check_result_value(j_result, G_OK)) {
              j_return = json_pack("{sisO}", "result", G_OK, "response", json_object_get(j_result, "certificate"));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register - Error get_user_certificate_from_id_scheme_storage");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
            json_decref(j_result);
          } else {
            j_result = get_user_certificate_from_id_user_property(config, ((struct _cert_param *)cls)->j_parameters, username, (const char *)key_id_enc);
            if (check_result_value(j_result, G_OK)) {
              j_return = json_pack("{sisO}", "result", G_OK, "response", json_object_get(j_result, "certificate"));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register - Error get_user_certificate_from_id_user_property");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
            json_decref(j_result);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register - Error get_certificate_id");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        if (clean_cert) {
          gnutls_x509_crt_deinit(cert);
        }
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    }
  } else if (json_object_get(((struct _cert_param *)cls)->j_parameters, "use-scheme-storage") == json_true()) {
    if (0 == o_strcmp("upload-certificate", json_string_value(json_object_get(j_scheme_data, "register")))) {
      if ((ret = add_user_certificate_scheme_storage(config, ((struct _cert_param *)cls)->j_parameters, json_string_value(json_object_get(j_scheme_data, "x509")), username, u_map_get_case(http_request->map_header, "user-agent"))) == G_OK) {
        j_return = json_pack("{si}", "result", G_OK);
      } else if (ret == G_ERROR_PARAM) {
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register certificate - Error add_user_certificate_scheme_storage (1)");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else if (0 == o_strcmp("use-certificate", json_string_value(json_object_get(j_scheme_data, "register")))) {
      if ((((struct _cert_param *)cls)->cert_source & G_CERT_SOURCE_TLS) && http_request->client_cert != NULL) {
        if ((x509_data = ulfius_export_client_certificate_pem(http_request)) != NULL) {
          if ((ret = add_user_certificate_scheme_storage(config, ((struct _cert_param *)cls)->j_parameters, x509_data, username, u_map_get_case(http_request->map_header, "user-agent"))) == G_OK) {
            j_return = json_pack("{si}", "result", G_OK);
          } else if (ret == G_ERROR_PARAM) {
            j_return = json_pack("{si}", "result", G_ERROR_PARAM);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register certificate - Error add_user_certificate_scheme_storage (2)  ");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          o_free(x509_data);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register certificate - Error ulfius_export_client_certificate_pem");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else if ((((struct _cert_param *)cls)->cert_source & G_CERT_SOURCE_HEADER) && (header_cert = u_map_get(http_request->map_header, json_string_value(json_object_get(((struct _cert_param *)cls)->j_parameters, "header-name")))) != NULL) {
        if ((ret = add_user_certificate_scheme_storage(config, ((struct _cert_param *)cls)->j_parameters, header_cert, username, u_map_get_case(http_request->map_header, "user-agent"))) == G_OK) {
          j_return = json_pack("{si}", "result", G_OK);
        } else if (ret == G_ERROR_PARAM) {
          j_return = json_pack("{si}", "result", G_ERROR_PARAM);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register certificate - Error add_user_certificate_scheme_storage (2)  ");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "user_auth_scheme_module_register certificate - No certificate");
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      }
    } else if (0 == o_strcmp("request-certificate", json_string_value(json_object_get(j_scheme_data, "register"))) && json_object_get(((struct _cert_param *)cls)->j_parameters, "request-certificate") != NULL) {
      j_result = get_generated_certificate(config, ((struct _cert_param *)cls)->j_parameters, username, get_ip_source(http_request), u_map_get_case(http_request->map_header, "user-agent"));
      if (check_result_value(j_result, G_OK)) {
        j_return = json_pack("{sis{sOsO}}", "result", G_OK, "response", "p12", json_object_get(json_object_get(j_result, "certificate"), "p12"), "password", json_object_get(json_object_get(j_result, "certificate"), "password"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register certificate - Error get_generated_certificate");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_result);
    } else if (0 == o_strcmp("toggle-certificate", json_string_value(json_object_get(j_scheme_data, "register")))) {
      if (json_string_length(json_object_get(j_scheme_data, "certificate_id"))) {
        j_result = get_user_certificate_from_id_scheme_storage(config, ((struct _cert_param *)cls)->j_parameters, username, json_string_value(json_object_get(j_scheme_data, "certificate_id")));
        if (check_result_value(j_result, G_OK)) {
          if (update_user_certificate_scheme_storage(config, ((struct _cert_param *)cls)->j_parameters, username, json_string_value(json_object_get(j_scheme_data, "certificate_id")), json_object_get(j_scheme_data, "enabled") == json_true()) == G_OK) {
            j_return = json_pack("{si}", "result", G_OK);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register certificate - Error update_user_certificate_scheme_storage");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
        } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
          j_return = json_pack("{si}", "result", G_ERROR_PARAM);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register certificate - Error get_user_certificate_from_id_scheme_storage");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_result);
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      }
    } else if (0 == o_strcmp("delete-certificate", json_string_value(json_object_get(j_scheme_data, "register")))) {
      if (json_string_length(json_object_get(j_scheme_data, "certificate_id"))) {
        j_result = get_user_certificate_from_id_scheme_storage(config, ((struct _cert_param *)cls)->j_parameters, username, json_string_value(json_object_get(j_scheme_data, "certificate_id")));
        if (check_result_value(j_result, G_OK)) {
          if (delete_user_certificate_scheme_storage(config, ((struct _cert_param *)cls)->j_parameters, username, json_string_value(json_object_get(j_scheme_data, "certificate_id"))) == G_OK) {
            j_return = json_pack("{si}", "result", G_OK);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register certificate - Error delete_user_certificate_scheme_storage");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
        } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
          j_return = json_pack("{si}", "result", G_ERROR_PARAM);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register certificate - Error get_user_certificate_from_id_scheme_storage");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_result);
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  
  return j_return;
}

/**
 * 
 * user_auth_scheme_module_register_get
 * 
 * Get the registration value(s) of the scheme for a user
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  response: JSON object, optional
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
json_t * user_auth_scheme_module_register_get(struct config_module * config, const struct _u_request * http_request, const char * username, void * cls) {
  UNUSED(http_request);
  json_t * j_return, * j_result;
  
  if (json_object_get(((struct _cert_param *)cls)->j_parameters, "use-scheme-storage") == json_true()) {
    j_result = get_user_certificate_list_scheme_storage(config, ((struct _cert_param *)cls)->j_parameters, username, 0);
    if (check_result_value(j_result, G_OK)) {
      j_return = json_pack("{sisO}", "result", G_OK, "response", json_object_get(j_result, "certificate"));
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register_get certificate - Error get_user_certificate_list_scheme_storage");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_result);
  } else {
    j_result = get_user_certificate_list_user_property(config, ((struct _cert_param *)cls)->j_parameters, username);
    if (check_result_value(j_result, G_OK)) {
      j_return = json_pack("{sisO}", "result", G_OK, "response", json_object_get(j_result, "certificate"));
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register_get certificate - Error get_user_certificate_list_user_property");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_result);
  }
  
  return j_return;
}

/**
 * 
 * user_auth_scheme_module_trigger
 * 
 * Trigger the scheme for a user
 * Ex: send the code to a device, generate a challenge, etc.
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  response: JSON object, optional
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter scheme_trigger: data sent to trigger the scheme for the user
 *                           in JSON format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
json_t * user_auth_scheme_module_trigger(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_trigger, void * cls) {
  UNUSED(config);
  UNUSED(http_request);
  UNUSED(username);
  UNUSED(j_scheme_trigger);
  UNUSED(cls);
  json_t * j_return = json_pack("{si}", "result", G_OK);
  
  return j_return;
}

/**
 * 
 * user_auth_scheme_module_validate
 * 
 * Validate the scheme for a user
 * Ex: check the code sent to a device, verify the challenge, etc.
 * 
 * @return value: G_OK on success
 *                G_ERROR_UNAUTHORIZED if validation fails
 *                G_ERROR_PARAM if error in parameters
 *                G_ERROR on another error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter j_scheme_data: data sent to validate the scheme for the user
 *                           in JSON format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_validate(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls) {
  UNUSED(j_scheme_data);
  int ret = G_OK, res, clean_cert = 0;
  const char * header_cert = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_datum_t cert_dat;

  // Get or parse certificate
  if ((((struct _cert_param *)cls)->cert_source & G_CERT_SOURCE_TLS) && http_request->client_cert != NULL) {
    cert = http_request->client_cert;
  } else if ((((struct _cert_param *)cls)->cert_source & G_CERT_SOURCE_HEADER) && (header_cert = u_map_get(http_request->map_header, json_string_value(json_object_get(((struct _cert_param *)cls)->j_parameters, "header-name")))) != NULL) {
    if (!gnutls_x509_crt_init(&cert)) {
      clean_cert = 1;
      cert_dat.data = (unsigned char *)header_cert;
      cert_dat.size = o_strlen(header_cert);
      if (gnutls_x509_crt_import(cert, &cert_dat, GNUTLS_X509_FMT_PEM) < 0) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "user_auth_scheme_module_validate certificate - Error gnutls_x509_crt_import");
        ret = G_ERROR_UNAUTHORIZED;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "user_auth_scheme_module_validate certificate - Error gnutls_x509_crt_init");
      ret = G_ERROR;
    }
  }
  
  // Validate certificate
  if (ret == G_OK && cert != NULL) {
    if ((res = is_user_certificate_valid(config, ((struct _cert_param *)cls)->j_parameters, username, cert)) == G_OK) {
      if (((struct _cert_param *)cls)->cert_array_len) {
        ret = is_certificate_valid_from_ca_chain((struct _cert_param *)cls, cert);
        if (ret != G_OK && ret != G_ERROR_UNAUTHORIZED) {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate certificate - Error is_certificate_valid_from_ca_chain");
          ret = G_ERROR;
        } else if (ret == G_ERROR_UNAUTHORIZED) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "user_auth_scheme_module_validate certificate - is_certificate_valid_from_ca_chain unauthorized");
        }
      }
    } else if (res == G_ERROR_UNAUTHORIZED) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "user_auth_scheme_module_validate certificate - is_user_certificate_valid unauthorized");
      ret = G_ERROR_UNAUTHORIZED;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate certificate - Error is_user_certificate_valid_scheme_storage");
      ret = G_ERROR;
    }
    if (clean_cert) {
      gnutls_x509_crt_deinit(cert);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "user_auth_scheme_module_validate certificate - No certificate");
    ret = G_ERROR_UNAUTHORIZED;
  }

  return ret;
}

/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * WebAuthn scheme module
 * 
 * Copyright 2019-2020 Nicolas Mora <mail@babelouest.org>
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

#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <jansson.h>
#include <cbor.h>
#include <ldap.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>
#include "glewlwyd-common.h"

const char * iso_3166_list[] = {"AF", "AX", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR", "AM", "AW", "AU", "AT", "AZ", "BH", "BS", "BD", "BB", "BY", "BE", "BZ", "BJ", "BM", "BT", "BO", "BQ", "BA", "BW", "BV", "BR", "IO", "BN", "BG", "BF", "BI", "KH", "CM", "CA", "CV", "KY", "CF", "TD", "CL", "CN", "CX", "CC", "CO", "KM", "CG", "CD", "CK", "CR", "CI", "HR", "CU", "CW", "CY", "CZ", "DK", "DJ", "DM", "DO", "EC", "EG", "SV", "GQ", "ER", "EE", "ET", "FK", "FO", "FJ", "FI", "FR", "GF", "PF", "TF", "GA", "GM", "GE", "DE", "GH", "GI", "GR", "GL", "GD", "GP", "GU", "GT", "GG", "GN", "GW", "GY", "HT", "HM", "VA", "HN", "HK", "HU", "IS", "IN", "ID", "IR", "IQ", "IE", "IM", "IL", "IT", "JM", "JP", "JE", "JO", "KZ", "KE", "KI", "KP", "KR", "KW", "KG", "LA", "LV", "LB", "LS", "LR", "LY", "LI", "LT", "LU", "MO", "MK", "MG", "MW", "MY", "MV", "ML", "MT", "MH", "MQ", "MR", "MU", "YT", "MX", "FM", "MD", "MC", "MN", "ME", "MS", "MA", "MZ", "MM", "NA", "NR", "NP", "NL", "NC", "NZ", "NI", "NE", "NG", "NU", "NF", "MP", "NO", "OM", "PK", "PW", "PS", "PA", "PG", "PY", "PE", "PH", "PN", "PL", "PT", "PR", "QA", "RE", "RO", "RU", "RW", "BL", "SH", "KN", "LC", "MF", "PM", "VC", "WS", "SM", "ST", "SA", "SN", "RS", "SC", "SL", "SG", "SX", "SK", "SI", "SB", "SO", "ZA", "GS", "SS", "ES", "LK", "SD", "SR", "SJ", "SZ", "SE", "CH", "SY", "TW", "TJ", "TZ", "TH", "TL", "TG", "TK", "TO", "TT", "TN", "TR", "TM", "TC", "TV", "UG", "UA", "AE", "GB", "US", "UM", "UY", "UZ", "VU", "VE", "VN", "VG", "VI", "WF", "EH", "YE", "ZM", "ZW", NULL};
#define G_PACKED_CERT_O_KEY    "O="
#define G_PACKED_CERT_OU_KEY   "OU="
#define G_PACKED_CERT_C_KEY    "C="
#define G_PACKED_CERT_CN_KEY   "CN="
#define G_PACKED_CERT_OU_VALUE "Authenticator Attestation"
#define G_PACKED_OID_AAGUID    "1.3.6.1.4.1.45724.1.1.4"

#define G_TABLE_WEBAUTHN_USER       "gs_webauthn_user"
#define G_TABLE_WEBAUTHN_CREDENTIAL "gs_webauthn_credential"
#define G_TABLE_WEBAUTHN_ASSERTION  "gs_webauthn_assertion"

#define SESSION_LENGTH 32
#define USER_ID_LENGTH 32

#define FLAG_USER_PRESENT 0x01
#define FLAG_USER_VERIFY  0x04
#define FLAG_AT           0x40
#define FLAG_ED           0x80

#define COUNTER_LEN   4
#define AAGUID_LEN    16
#define CRED_ID_L_LEN 2

#define FLAGS_OFFSET 32
#define COUNTER_OFFSET (FLAGS_OFFSET+1)
#define ATTESTED_CRED_DATA_OFFSET (COUNTER_OFFSET+COUNTER_LEN)
#define CRED_ID_L_OFFSET (ATTESTED_CRED_DATA_OFFSET+AAGUID_LEN)
#define CREDENTIAL_ID_OFFSET (ATTESTED_CRED_DATA_OFFSET+AAGUID_LEN+CRED_ID_L_LEN)

#define ECDSA256 -7
#define ECDSA384 -35
#define ECDSA512 -36

#define SAFETYNET_ISSUED_TO "CN=attest.android.com"

static json_t * get_cert_from_file_path(const char * path) {
  gnutls_x509_crt_t cert = NULL;
  gnutls_datum_t cert_dat = {NULL, 0}, export_dat = {NULL, 0};
  FILE * fl;
  size_t len, issued_for_len = 128;
  char * cert_content, issued_for[128] = {};
  json_t * j_return = NULL;
  
  fl = fopen(path, "r");
  if (fl != NULL) {
    fseek(fl, 0, SEEK_END);
    len = ftell(fl);
    cert_content = o_malloc(len);
    if (cert_content != NULL) {
      if (fseek(fl, 0, SEEK_SET) == -1) {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_cert_from_file_path - Error fseek");
        j_return = json_pack("{si}", "result", G_ERROR);
      } else if (fread(cert_content, 1, len, fl) != len) {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_cert_from_file_path - Error fread");
        j_return = json_pack("{si}", "result", G_ERROR);
      } else {
        cert_dat.data = (unsigned char *)cert_content;
        cert_dat.size = len;
        if (!gnutls_x509_crt_init(&cert)) {
          if (gnutls_x509_crt_import(cert, &cert_dat, GNUTLS_X509_FMT_DER) >= 0 || gnutls_x509_crt_import(cert, &cert_dat, GNUTLS_X509_FMT_PEM) >= 0) {
            if (!gnutls_x509_crt_get_dn(cert, issued_for, &issued_for_len)) {
              if (gnutls_x509_crt_export2(cert, GNUTLS_X509_FMT_PEM, &export_dat) >= 0) {
                j_return = json_pack("{sis{ss%ss%}}", "result", G_OK, "certificate", "dn", issued_for, issued_for_len, "x509", export_dat.data, export_dat.size);
                gnutls_free(export_dat.data);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_cert_from_file_path - Error gnutls_x509_crt_export2");
                j_return = json_pack("{si}", "result", G_ERROR);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_cert_from_file_path - Error gnutls_x509_crt_get_dn");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_cert_from_file_path - Error gnutls_x509_crt_import");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_cert_from_file_path - Error gnutls_x509_crt_init");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        gnutls_x509_crt_deinit(cert);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_cert_from_file_path - Error o_malloc cert_content");
      j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
    }
    o_free(cert_content);
    fclose(fl);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_cert_from_file_path - Error fopen %s", path);
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

static json_t * is_scheme_parameters_valid(json_t * j_params) {
  json_t * j_return, * j_error, * j_element = NULL, * j_cert;
  size_t index = 0;
  json_int_t pubkey;
  char * message;
  
  if (json_is_object(j_params)) {
    j_error = json_array();
    if (j_error != NULL) {
      if (!json_is_boolean(json_object_get(j_params, "session-mandatory"))) {
        json_array_append_new(j_error, json_string("session-mandatory is mandatory and must be a boolean"));
      }
      if (json_object_get(j_params, "seed") != NULL && !json_is_string(json_object_get(j_params, "seed"))) {
        json_array_append_new(j_error, json_string("seed is optional and must be a string"));
      }
      if (json_integer_value(json_object_get(j_params, "challenge-length")) <= 0) {
        json_array_append_new(j_error, json_string("challenge-length is mandatory and must be a positive integer"));
      }
      if (json_integer_value(json_object_get(j_params, "credential-expiration")) <= 0) {
        json_array_append_new(j_error, json_string("credential-expiration is mandatory and must be a positive integer"));
      }
      if (json_integer_value(json_object_get(j_params, "credential-assertion")) <= 0) {
        json_array_append_new(j_error, json_string("credential-assertion is mandatory and must be a positive integer"));
      }
      if (!json_string_length(json_object_get(j_params, "rp-origin"))) {
        json_array_append_new(j_error, json_string("rp-origin is mandatory and must be a non empty string"));
      }
      if (!json_array_size(json_object_get(j_params, "pubKey-cred-params"))) {
        json_array_append_new(j_error, json_string("pubKey-cred-params is mandatory and must be a non empty JSON array"));
      } else {
        json_array_foreach(json_object_get(j_params, "pubKey-cred-params"), index, j_element) {
          pubkey = json_integer_value(j_element);
          //if (pubkey != -7 && pubkey != -35 && pubkey != -36 && pubkey != -257 && pubkey != -258 && pubkey != -259) {
          if (pubkey != ECDSA256 && pubkey != ECDSA384 && pubkey != ECDSA512) {
            //json_array_append_new(j_error, json_string("pubKey-cred-params elements values available are -7, -35, -36 (ECDSA) or -257, -258, -259 (RSA)"));
            json_array_append_new(j_error, json_string("pubKey-cred-params elements values available are -7, -35, -36 (ECDSA)"));
          }
        }
      }
      if (json_object_get(j_params, "ctsProfileMatch") != NULL && (!json_is_integer(json_object_get(j_params, "ctsProfileMatch")) || json_integer_value(json_object_get(j_params, "ctsProfileMatch")) < -1 || json_integer_value(json_object_get(j_params, "ctsProfileMatch")) > 1)) {
        json_array_append_new(j_error, json_string("ctsProfileMatch is optional and must be an integer between -1 and 1"));
      }
      if (json_object_get(j_params, "basicIntegrity") != NULL && (!json_is_integer(json_object_get(j_params, "basicIntegrity")) || json_integer_value(json_object_get(j_params, "basicIntegrity")) < -1 || json_integer_value(json_object_get(j_params, "basicIntegrity")) > 1)) {
        json_array_append_new(j_error, json_string("basicIntegrity is optional and must be an integer between -1 and 1"));
      }
      if (json_object_get(j_params, "google-root-ca-r2") != NULL && !json_is_string(json_object_get(j_params, "google-root-ca-r2"))) {
        json_array_append_new(j_error, json_string("google-root-ca-r2 is optional and must be a string"));
      } else if (json_string_length(json_object_get(j_params, "google-root-ca-r2"))) {
        j_cert = get_cert_from_file_path(json_string_value(json_object_get(j_params, "google-root-ca-r2")));
        if (check_result_value(j_cert, G_OK)) {
          json_object_set(j_params, "google-root-ca-r2-content", json_object_get(j_cert, "certificate"));
        } else {
          message = msprintf("Error parsing google-root-ca-r2 certificate file %s", json_string_value(json_object_get(j_params, "google-root-ca-r2")));
          json_array_append_new(j_error, json_string(message));
          o_free(message);
        }
        json_decref(j_cert);
      }
      if (json_object_get(j_params, "root-ca-list") != NULL) {
        if (!json_is_array(json_object_get(j_params, "root-ca-list"))) {
          json_array_append_new(j_error, json_string("root-ca-list is optional and must be an array of strings"));
        } else {
          json_object_set_new(j_params, "root-ca-array", json_array());
          json_array_foreach(json_object_get(j_params, "root-ca-list"), index, j_element) {
            if (!json_string_length(j_element)) {
              json_array_append_new(j_error, json_string("root-ca-list is optional and must be an array of strings"));
            } else {
              j_cert = get_cert_from_file_path(json_string_value(j_element));
              if (check_result_value(j_cert, G_OK)) {
                json_array_append(json_object_get(j_params, "root-ca-array"), json_object_get(j_cert, "certificate"));
              } else {
                message = msprintf("Error parsing certificate file %s", json_string_value(j_element));
                json_array_append_new(j_error, json_string(message));
                o_free(message);
              }
              json_decref(j_cert);
            }
          }
        }
      }
      if (json_object_get(j_params, "force-fmt-none") != NULL && !json_is_boolean(json_object_get(j_params, "force-fmt-none"))) {
        json_array_append_new(j_error, json_string("allow-fmt-none is optional and must be a boolean"));
      }
      if (json_object_get(j_params, "fmt") != NULL && (!json_is_object(json_object_get(j_params, "fmt")) || (json_object_get(json_object_get(j_params, "fmt"), "packed") != json_true() && json_object_get(json_object_get(j_params, "fmt"), "tpm") != json_true() && json_object_get(json_object_get(j_params, "fmt"), "android-key") != json_true() && json_object_get(json_object_get(j_params, "fmt"), "android-safetynet") != json_true() && json_object_get(json_object_get(j_params, "fmt"), "fido-u2f") != json_true() && json_object_get(json_object_get(j_params, "fmt"), "none") != json_true()))) {
        json_array_append_new(j_error, json_string("fmt must be a JSON object filled with supported formats: 'packed' 'tpm', 'android-key', 'android-safetynet', 'fido-u2f', 'none'"));
      }
      if (json_array_size(j_error)) {
        j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
      } else {
        j_return = json_pack("{si}", "result", G_OK);
      }
      json_decref(j_error);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_scheme_parameters_valid - Error allocating resources for j_error");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "parameters must be a JSON object");
  }
  return j_return;
}

/**
 * Get the user_id associated with the username in the table G_TABLE_WEBAUTHN_USER
 * If user_id doesn't exist, create one, stores it, and return the new user_id
 */
static json_t * get_user_id_from_username(struct config_module * config, json_t * j_param, const char * username, int create) {
  json_t * j_query, * j_result, * j_return;
  int res;
  char * username_escaped, * username_clause;
  unsigned char new_user_id[USER_ID_LENGTH] = {0}, new_user_id_b64[USER_ID_LENGTH*2] = {0};
  size_t new_user_id_b64_len;
  
  username_escaped = h_escape_string_with_quotes(config->conn, username);
  username_clause = msprintf(" = UPPER(%s)", username_escaped);
  j_query = json_pack("{sss[s]s{s{ssss}sO}}",
                      "table",
                      G_TABLE_WEBAUTHN_USER,
                      "columns",
                        "gswu_user_id AS user_id",
                      "where",
                        "UPPER(gswu_username)",
                          "operator",
                          "raw",
                          "value",
                          username_clause,
                        "gswu_mod_name",
                        json_object_get(j_param, "mod_name"));
  o_free(username_clause);
  o_free(username_escaped);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      j_return = json_pack("{siss}", "result", G_OK, "user_id", json_string_value(json_object_get(json_array_get(j_result, 0), "user_id")));
    } else if (create) {
      // Generates a new user_id, and stores it in the database
      gnutls_rnd(GNUTLS_RND_KEY, new_user_id, USER_ID_LENGTH);
      if (o_base64_encode(new_user_id, USER_ID_LENGTH, new_user_id_b64, &new_user_id_b64_len)) {
        j_query = json_pack("{sss{sOssss}}",
                            "table",
                            G_TABLE_WEBAUTHN_USER,
                            "values",
                              "gswu_mod_name",
                              json_object_get(j_param, "mod_name"),
                              "gswu_username",
                              username,
                              "gswu_user_id",
                              new_user_id_b64);
        res = h_insert(config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          j_return = json_pack("{siss}", "result", G_OK, "user_id", new_user_id_b64);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_user_id_from_username - Error executing j_query insert");
          config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_id_from_username - Error o_base64_encode");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_id_from_username - Error executing j_query select");
    config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static json_t * get_credential_list(struct config_module * config, json_t * j_params, const char * username, int restrict_to_registered) {
  json_t * j_query, * j_result, * j_return, * j_element = NULL;
  int res;
  char * username_escaped, * mod_name_escaped, * username_clause;
  size_t index = 0;
  
  username_escaped = h_escape_string_with_quotes(config->conn, username);
  mod_name_escaped = h_escape_string_with_quotes(config->conn, json_string_value(json_object_get(j_params, "mod_name")));
  username_clause = msprintf(" = (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER(%s) AND gswu_mod_name = %s)", username_escaped, mod_name_escaped);
  j_query = json_pack("{sss[ssss]s{s{ssss}}}",
                      "table",
                      G_TABLE_WEBAUTHN_CREDENTIAL,
                      "columns",
                        "gswc_credential_id AS credential_id",
                        "gswc_name AS name",
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gswc_created_at) AS created_at", "strftime('%s', gswc_created_at) AS created_at", "EXTRACT(EPOCH FROM gswc_created_at)::integer AS created_at"),
                        "gswc_status",
                      "where",
                        "gswu_id",
                          "operator",
                          "raw",
                          "value",
                          username_clause);
  o_free(username_clause);
  o_free(username_escaped);
  o_free(mod_name_escaped);
  if (restrict_to_registered) {
    json_object_set_new(json_object_get(j_query, "where"), "gswc_status", json_integer(1));
  } else {
    json_object_set_new(json_object_get(j_query, "where"), "gswc_status", json_pack("{ssss}", "operator", "raw", "value", " IN (1,3)"));
  }
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      j_return = json_pack("{sis[]}", "result", G_OK, "credential");
      if (j_return != NULL) {
        json_array_foreach(j_result, index, j_element) {
          switch (json_integer_value(json_object_get(j_element, "gswc_status"))) {
            case 1:
              json_object_set_new(j_element, "status", json_string("registered"));
              break;
            case 3:
              json_object_set_new(j_element, "status", json_string("disabled"));
              break;
            default:
              break;
          }
          json_object_del(j_element, "gswc_status");
          json_array_append(json_object_get(j_return, "credential"), j_element);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_credential_list - Error json_pack");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_credential_list - Error executing j_query");
    config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static json_t * generate_new_credential(struct config_module * config, json_t * j_params, const char * username) {
  json_t * j_query, * j_return;
  char * username_escaped, * mod_name_escaped, * username_clause, * challenge_hash;
  int res;
  size_t challenge_b64_len, challenge_len = (size_t)json_integer_value(json_object_get(j_params, "challenge-length"));
  unsigned char challenge_b64[challenge_len*2], challenge[challenge_len+1];
  char session[SESSION_LENGTH+1] = {0}, * session_hash;
  
  gnutls_rnd(GNUTLS_RND_NONCE, challenge, challenge_len);
  if (o_base64_encode(challenge, challenge_len, challenge_b64, &challenge_b64_len)) {
    challenge_b64[challenge_b64_len] = '\0';
    if ((challenge_hash = generate_hash(config->hash_algorithm, (const char *)challenge_b64)) != NULL) {
      rand_string(session, SESSION_LENGTH);
      if ((session_hash = generate_hash(config->hash_algorithm, session)) != NULL) {
        username_escaped = h_escape_string_with_quotes(config->conn, username);
        mod_name_escaped = h_escape_string_with_quotes(config->conn, json_string_value(json_object_get(j_params, "mod_name")));
        username_clause = msprintf(" (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER(%s) AND gswu_mod_name = %s)", username_escaped, mod_name_escaped);
        // Disable all credential with status 0 (new) of the same user
        j_query = json_pack("{sss{si}s{s{ssss+}si}}",
                            "table",
                            G_TABLE_WEBAUTHN_CREDENTIAL,
                            "set",
                              "gswc_status",
                              2,
                            "where",
                              "gswu_id",
                                "operator",
                                "raw",
                                "value",
                                " =",
                                username_clause,
                              "gswc_status",
                              0);
        res = h_update(config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          // Insert new credential
          j_query = json_pack("{sss{s{ss}sssssi}}",
                              "table",
                              G_TABLE_WEBAUTHN_CREDENTIAL,
                              "values",
                                "gswu_id",
                                  "raw",
                                  username_clause,
                                "gswc_session_hash",
                                session_hash,
                                "gswc_challenge_hash",
                                challenge_hash,
                                "gswc_status",
                                0);
          res = h_insert(config->conn, j_query, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            j_return = json_pack("{sis{ssss}}", "result", G_OK, "credential", "session", session, "challenge", challenge_b64);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_credential - Error executing j_query insert");
            config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
            j_return = json_pack("{si}", "result", G_ERROR_DB);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_credential - Error executing j_query update");
          config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        o_free(username_clause);
        o_free(username_escaped);
        o_free(mod_name_escaped);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_credential - Error generate_hash session");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      o_free(session_hash);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_credential - Error generate_hash challenge");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(challenge_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_credential - Error o_base64_encode challenge");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

static json_t * generate_new_assertion(struct config_module * config, json_t * j_params, const char * username, int mock) {
  json_t * j_query, * j_return;
  char * username_escaped, * username_clause, * mod_name_escaped, * challenge_hash;
  int res;
  size_t challenge_b64_len, challenge_len = (size_t)json_integer_value(json_object_get(j_params, "challenge-length"));
  unsigned char challenge_b64[challenge_len*2], challenge[challenge_len+1];
  char session[SESSION_LENGTH+1] = {0}, * session_hash;
  
  gnutls_rnd(GNUTLS_RND_NONCE, challenge, challenge_len);
  if (o_base64_encode(challenge, challenge_len, challenge_b64, &challenge_b64_len)) {
    challenge_b64[challenge_b64_len] = '\0';
    if ((challenge_hash = generate_hash(config->hash_algorithm, (const char *)challenge_b64)) != NULL) {
      rand_string(session, SESSION_LENGTH);
      if ((session_hash = generate_hash(config->hash_algorithm, session)) != NULL) {
        if (mock < 2) {
          username_escaped = h_escape_string_with_quotes(config->conn, username);
          mod_name_escaped = h_escape_string_with_quotes(config->conn, json_string_value(json_object_get(j_params, "mod_name")));
          username_clause = msprintf(" (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER(%s) AND gswu_mod_name = %s)", username_escaped, mod_name_escaped);
          // Disable all assertions with status 0 (new) of the same user
          j_query = json_pack("{sss{si}s{s{ssss+}si}}",
                              "table",
                              G_TABLE_WEBAUTHN_ASSERTION,
                              "set",
                                "gswa_status",
                                3,
                              "where",
                                "gswu_id",
                                  "operator",
                                  "raw",
                                  "value",
                                  " =",
                                  username_clause,
                                "gswa_status",
                                0);
          res = h_update(config->conn, j_query, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            // Insert new assertion
            j_query = json_pack("{sss{s{ss}sssssisi}}",
                                "table",
                                G_TABLE_WEBAUTHN_ASSERTION,
                                "values",
                                  "gswu_id",
                                    "raw",
                                    username_clause,
                                  "gswa_session_hash",
                                  session_hash,
                                  "gswa_challenge_hash",
                                  challenge_hash,
                                  "gswa_status",
                                  0,
                                  "gswa_mock",
                                  mock);
            res = h_insert(config->conn, j_query, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              j_return = json_pack("{sis{ssss}}", "result", G_OK, "assertion", "session", session, "challenge", challenge_b64);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_assertion - Error executing j_query insert");
              config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
              j_return = json_pack("{si}", "result", G_ERROR_DB);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_assertion - Error executing j_query update");
            config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
            j_return = json_pack("{si}", "result", G_ERROR_DB);
          }
          o_free(username_clause);
          o_free(mod_name_escaped);
          o_free(username_escaped);
        } else {
          j_return = json_pack("{sis{ssss}}", "result", G_OK, "assertion", "session", session, "challenge", challenge_b64);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_assertion - Error generate_hash session");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      o_free(session_hash);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_assertion - Error generate_hash challenge");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(challenge_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_assertion - Error o_base64_encode challenge");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

static json_t * get_credential_from_session(struct config_module * config, json_t * j_params, const char * username, const char * session) {
  json_t * j_query, * j_result, * j_return;
  char * username_escaped, * mod_name_escaped, * username_clause, * expiration_clause;
  char * session_hash;
  int res;
  time_t now;
  
  if (o_strlen(session)) {
    session_hash = generate_hash(config->hash_algorithm, session);
    if (session_hash != NULL) {
      time(&now);
      username_escaped = h_escape_string_with_quotes(config->conn, username);
      mod_name_escaped = h_escape_string_with_quotes(config->conn, json_string_value(json_object_get(j_params, "mod_name")));
      username_clause = msprintf(" = (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER(%s) AND gswu_mod_name = %s)", username_escaped, mod_name_escaped);
      if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expiration_clause = msprintf("> FROM_UNIXTIME(%u)", (now - (unsigned int)json_integer_value(json_object_get(j_params, "credential-expiration"))));
      } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expiration_clause = msprintf("> TO_TIMESTAMP(%u)", (now - (unsigned int)json_integer_value(json_object_get(j_params, "credential-expiration"))));
      } else { // HOEL_DB_TYPE_SQLITE
        expiration_clause = msprintf("> %u", (now - (unsigned int)json_integer_value(json_object_get(j_params, "credential-expiration"))));
      }
      j_query = json_pack("{sss[ssssss]s{sss{ssss}sis{ssss}}}",
                          "table",
                          G_TABLE_WEBAUTHN_CREDENTIAL,
                          "columns",
                            "gswc_id",
                            "gswu_id",
                            "gswc_session_hash AS session_hash",
                            "gswc_challenge_hash AS challenge_hash",
                            "gswc_credential_id AS credential_id",
                            "gswc_public_key AS public_key",
                          "where",
                            "gswc_session_hash",
                            session_hash,
                            "gswu_id",
                              "operator",
                              "raw",
                              "value",
                              username_clause,
                            "gswc_status",
                            0,
                            "gswc_created_at",
                              "operator",
                              "raw",
                              "value",
                              expiration_clause);
      o_free(username_clause);
      o_free(username_escaped);
      o_free(mod_name_escaped);
      o_free(expiration_clause);
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          j_return = json_pack("{sisO}", "result", G_OK, "credential", json_array_get(j_result, 0));
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_credential_from_session - Error executing j_query");
        config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_credential_from_session - Error generate_hash");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(session_hash);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

static json_t * get_credential(struct config_module * config, json_t * j_params, const char * username, const char * credential_id) {
  json_t * j_query, * j_result, * j_return;
  char * username_escaped, * mod_name_escaped, * username_clause;
  int res;
  
  username_escaped = h_escape_string_with_quotes(config->conn, username);
  mod_name_escaped = h_escape_string_with_quotes(config->conn, json_string_value(json_object_get(j_params, "mod_name")));
  username_clause = msprintf(" = (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER(%s) AND gswu_mod_name = %s)", username_escaped, mod_name_escaped);
  j_query = json_pack("{sss[sss]s{sss{ssss}s{ssss}}}",
                      "table",
                      G_TABLE_WEBAUTHN_CREDENTIAL,
                      "columns",
                        "gswc_id",
                        "gswc_public_key AS public_key",
                        "gswc_counter AS counter",
                      "where",
                        "gswc_credential_id",
                        credential_id,
                        "gswu_id",
                          "operator",
                          "raw",
                          "value",
                          username_clause,
                        "gswc_status",
                          "operator",
                          "raw",
                          "value",
                          " IN (1,3)");
  o_free(username_clause);
  o_free(username_escaped);
  o_free(mod_name_escaped);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      j_return = json_pack("{sisO}", "result", G_OK, "credential", json_array_get(j_result, 0));
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_credential - Error executing j_query");
    config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static int update_credential(struct config_module * config, json_t * j_params, const char * username, const char * credential_id, int status) {
  json_t * j_query;
  char * username_escaped, * mod_name_escaped, * username_clause;
  int res, ret;
  
  username_escaped = h_escape_string_with_quotes(config->conn, username);
  mod_name_escaped = h_escape_string_with_quotes(config->conn, json_string_value(json_object_get(j_params, "mod_name")));
  username_clause = msprintf(" = (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER(%s) AND gswu_mod_name = %s)", username_escaped, mod_name_escaped);
  j_query = json_pack("{sss{si}s{sss{ssss}}}",
                      "table",
                      G_TABLE_WEBAUTHN_CREDENTIAL,
                      "set",
                        "gswc_status",
                        status,
                      "where",
                        "gswc_credential_id",
                        credential_id,
                        "gswu_id",
                          "operator",
                          "raw",
                          "value",
                          username_clause);
  o_free(username_clause);
  o_free(username_escaped);
  o_free(mod_name_escaped);
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_credential - Error executing j_query");
    config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    ret = G_ERROR_DB;
  }
  return ret;
}

static int update_credential_name(struct config_module * config, json_t * j_params, const char * username, const char * credential_id, const char * name) {
  json_t * j_query;
  char * username_escaped, * mod_name_escaped, * username_clause;
  int res, ret;
  
  username_escaped = h_escape_string_with_quotes(config->conn, username);
  mod_name_escaped = h_escape_string_with_quotes(config->conn, json_string_value(json_object_get(j_params, "mod_name")));
  username_clause = msprintf(" = (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER(%s) AND gswu_mod_name = %s)", username_escaped, mod_name_escaped);
  j_query = json_pack("{sss{ss}s{sss{ssss}}}",
                      "table",
                      G_TABLE_WEBAUTHN_CREDENTIAL,
                      "set",
                        "gswc_name",
                        name,
                      "where",
                        "gswc_credential_id",
                        credential_id,
                        "gswu_id",
                          "operator",
                          "raw",
                          "value",
                          username_clause);
  o_free(username_clause);
  o_free(username_escaped);
  o_free(mod_name_escaped);
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_credential - Error executing j_query");
    config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    ret = G_ERROR_DB;
  }
  return ret;
}

static json_t * get_assertion_from_session(struct config_module * config, json_t * j_params, const char * username, const char * session, int mock) {
  json_t * j_query, * j_result, * j_return;
  char * username_escaped, * mod_name_escaped, * username_clause, * expiration_clause;
  char * session_hash;
  int res;
  time_t now;
  
  if (o_strlen(session)) {
    session_hash = generate_hash(config->hash_algorithm, session);
    if (session_hash != NULL) {
      time(&now);
      username_escaped = h_escape_string_with_quotes(config->conn, username);
      mod_name_escaped = h_escape_string_with_quotes(config->conn, json_string_value(json_object_get(j_params, "mod_name")));
      username_clause = msprintf(" = (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER(%s) AND gswu_mod_name = %s)", username_escaped, mod_name_escaped);
      if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expiration_clause = msprintf("> FROM_UNIXTIME(%u)", (now - (unsigned int)json_integer_value(json_object_get(j_params, "credential-assertion"))));
      } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expiration_clause = msprintf("> TO_TIMESTAMP(%u)", (now - (unsigned int)json_integer_value(json_object_get(j_params, "credential-assertion"))));
      } else { // HOEL_DB_TYPE_SQLITE
        expiration_clause = msprintf("> %u", (now - (unsigned int)json_integer_value(json_object_get(j_params, "credential-assertion"))));
      }
      j_query = json_pack("{sss[ssss]s{sss{ssss}sis{ssss}si}}",
                          "table",
                          G_TABLE_WEBAUTHN_ASSERTION,
                          "columns",
                            "gswa_id",
                            "gswu_id",
                            "gswa_session_hash AS session_hash",
                            "gswa_challenge_hash AS challenge_hash",
                          "where",
                            "gswa_session_hash",
                            session_hash,
                            "gswu_id",
                              "operator",
                              "raw",
                              "value",
                              username_clause,
                            "gswa_status",
                            0,
                            "gswa_issued_at",
                              "operator",
                              "raw",
                              "value",
                              expiration_clause,
                            "gswa_mock",
                            mock);
      o_free(username_clause);
      o_free(username_escaped);
      o_free(mod_name_escaped);
      o_free(expiration_clause);
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          j_return = json_pack("{sisO}", "result", G_OK, "assertion", json_array_get(j_result, 0));
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_assertion_from_session - Error executing j_query");
        config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_assertion_from_session - Error generate_hash");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(session_hash);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

static int check_certificate(struct config_module * config, json_t * j_params, const char * credential_id, json_int_t gswu_id) {
  json_t * j_query, * j_result;
  int res, ret;
  char * credential_id_escaped, * mod_name_escaped, * where_clause;
  
  credential_id_escaped = h_escape_string_with_quotes(config->conn, credential_id);
  mod_name_escaped = h_escape_string_with_quotes(config->conn, json_string_value(json_object_get(j_params, "mod_name")));
  where_clause = msprintf(" IN (SELECT gswu_id FROM " G_TABLE_WEBAUTHN_CREDENTIAL " WHERE gswc_credential_id=%s AND gswc_status=1 AND gswu_id IN (SELECT gswu_id FROM " G_TABLE_WEBAUTHN_USER " WHERE gswu_mod_name=%s))", credential_id_escaped, mod_name_escaped);
  j_query = json_pack("{sss[s]s{s{ssss}si}}",
                      "table",
                      G_TABLE_WEBAUTHN_CREDENTIAL,
                      "columns",
                        "gswu_id",
                      "where",
                        "gswu_id",
                          "operator",
                          "raw",
                          "value",
                          where_clause,
                        "gswc_status",
                        1);
  o_free(where_clause);
  o_free(mod_name_escaped);
  o_free(credential_id_escaped);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gswu_id")) == gswu_id) {
        ret = G_OK;
      } else {
        ret = G_ERROR_UNAUTHORIZED;
      }
    } else {
      ret = G_ERROR_NOT_FOUND;
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "check_credential_id - Error executing j_query");
    config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    ret = G_ERROR_DB;
  }
  return ret;
}

static int validate_certificate_from_root(json_t * j_params, gnutls_x509_crt_t cert_leaf, cbor_item_t * x5c_array) {
  int ret = G_ERROR_NOT_FOUND, res;
  unsigned int result;
  gnutls_datum_t cert_dat = {NULL, 0}, issuer_dat = {NULL, 0};
  gnutls_x509_trust_list_t tlist = NULL;
  gnutls_x509_crt_t cert_x509[cbor_array_size(x5c_array)+1], root_x509 = NULL;
  json_t * j_cert = NULL;
  cbor_item_t * cbor_cert = NULL;
  size_t index = 0, i = 0, x5c_array_size = cbor_array_size(x5c_array);
  char * issuer;
  
  for (i=0; i<x5c_array_size+1; i++) {
    cert_x509[i] = NULL;
  }
  if ((res = gnutls_x509_crt_get_issuer_dn2(cert_leaf, &issuer_dat)) >= 0) {
    issuer = o_strndup((const char *)issuer_dat.data, issuer_dat.size);
    json_array_foreach(json_object_get(j_params, "root-ca-array"), index, j_cert) {
      if (0 == o_strcmp(issuer, json_string_value(json_object_get(j_cert, "dn")))) {
        cert_dat.data = (unsigned char *)json_string_value(json_object_get(j_cert, "x509"));
        cert_dat.size = json_string_length(json_object_get(j_cert, "x509"));
        if (!gnutls_x509_crt_init(&root_x509) && !gnutls_x509_crt_import(root_x509, &cert_dat, GNUTLS_X509_FMT_PEM)) {
          cert_x509[0] = cert_leaf;
          for (i=1; i<x5c_array_size; i++) {
            cbor_cert = cbor_array_get(x5c_array, i);
            cert_dat.data = cbor_bytestring_handle(cbor_cert);
            cert_dat.size = cbor_bytestring_length(cbor_cert);
            if (gnutls_x509_crt_init(&cert_x509[i]) < 0 || gnutls_x509_crt_import(cert_x509[i], &cert_dat, GNUTLS_X509_FMT_DER) < 0) {
              y_log_message(Y_LOG_LEVEL_ERROR, "validate_certificate_from_root - Error import chain cert at index %zu", i);
              ret = G_ERROR;
            }
            cbor_decref(&cbor_cert);
          }
          cert_x509[x5c_array_size] = root_x509;
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "validate_certificate_from_root - Error import root cert");
          ret = G_ERROR;
        }
      }
    }
    o_free(issuer);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "validate_certificate_from_root - Error gnutls_x509_crt_get_issuer_dn2: %d", res);
    ret = G_ERROR;
  }
  gnutls_free(issuer_dat.data);
  
  if (ret == G_OK) {
    if (!gnutls_x509_trust_list_init(&tlist, 0)) {
      if (gnutls_x509_trust_list_add_cas(tlist, &root_x509, 1, 0) >= 0) {
        if (gnutls_x509_trust_list_verify_crt(tlist, cert_x509, 2, 0, &result, NULL) >= 0) {
          if (result) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "validate_certificate_from_root - certificate chain invalid");
            ret = G_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "validate_certificate_from_root - Error gnutls_x509_trust_list_verify_crt");
          ret = G_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "validate_certificate_from_root - Error gnutls_x509_trust_list_add_cas");
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "validate_certificate_from_root - Error gnutls_x509_trust_list_init");
      ret = G_ERROR;
    }
  }
  gnutls_x509_crt_deinit(root_x509);
  for (i=1; i<x5c_array_size; i++) {
    gnutls_x509_crt_deinit(cert_x509[i]);
  }
  gnutls_x509_trust_list_deinit(tlist, 0);
  return ret;
}

static int validate_safetynet_ca_root(json_t * j_params, gnutls_x509_crt_t cert_leaf, json_t * j_header_x5c) {
  gnutls_x509_crt_t cert_x509[(json_array_size(j_header_x5c)+1)], root_x509 = NULL;
  gnutls_x509_trust_list_t tlist = NULL;
  int ret = G_OK;
  unsigned int result, i;
  json_t * j_cert;
  unsigned char * header_cert_decoded;
  size_t header_cert_decoded_len;
  gnutls_datum_t cert_dat;
  
  cert_x509[0] = cert_leaf;
  for (i=1; i<json_array_size(j_header_x5c); i++) {
    j_cert = json_array_get(j_header_x5c, i);
    
    if ((header_cert_decoded = o_malloc(json_string_length(j_cert))) != NULL) {
      if (o_base64_decode((const unsigned char *)json_string_value(j_cert), json_string_length(j_cert), header_cert_decoded, &header_cert_decoded_len)) {
        if (!gnutls_x509_crt_init(&cert_x509[i])) {
          cert_dat.data = header_cert_decoded;
          cert_dat.size = header_cert_decoded_len;
          if ((ret = gnutls_x509_crt_import(cert_x509[i], &cert_dat, GNUTLS_X509_FMT_DER)) < 0) {
            y_log_message(Y_LOG_LEVEL_ERROR, "validate_safetynet_ca_root - Error gnutls_x509_crt_import: %d", ret);
            ret = G_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "validate_safetynet_ca_root - Error gnutls_x509_crt_init");
          ret = G_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "validate_safetynet_ca_root - Error o_base64_decode x5c leaf");
        ret = G_ERROR;
      }
      o_free(header_cert_decoded);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "validate_safetynet_ca_root - Error allocating resources for header_cert_decoded");
      ret = G_ERROR_MEMORY;
    }
  }
  
  if (ret == G_OK) {
    cert_dat.data = (unsigned char *)json_string_value(json_object_get(json_object_get(j_params, "google-root-ca-r2-content"), "x509"));
    cert_dat.size = json_string_length(json_object_get(json_object_get(j_params, "google-root-ca-r2-content"), "x509"));
    if (!gnutls_x509_crt_init(&cert_x509[json_array_size(j_header_x5c)]) && 
        !gnutls_x509_crt_import(cert_x509[json_array_size(j_header_x5c)], &cert_dat, GNUTLS_X509_FMT_PEM)) {
      if (!gnutls_x509_crt_init(&root_x509) && 
          !gnutls_x509_crt_import(root_x509, &cert_dat, GNUTLS_X509_FMT_PEM)) {
        if (!gnutls_x509_trust_list_init(&tlist, 0)) {
          if (gnutls_x509_trust_list_add_cas(tlist, &root_x509, 1, 0) >= 0) {
            if (gnutls_x509_trust_list_verify_crt(tlist, cert_x509, (json_array_size(j_header_x5c)+1), 0, &result, NULL) >= 0) {
              if (!result) {
                ret = G_OK;
              } else {
                y_log_message(Y_LOG_LEVEL_DEBUG, "validate_safetynet_ca_root - certificate chain invalid");
                ret = G_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "validate_safetynet_ca_root - Error gnutls_x509_trust_list_verify_crt");
              ret = G_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "validate_safetynet_ca_root - Error gnutls_x509_trust_list_add_cas");
            ret = G_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "validate_safetynet_ca_root - Error gnutls_x509_trust_list_init");
          ret = G_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "validate_safetynet_ca_root - Error import root cert");
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "validate_safetynet_ca_root - Error import last cert");
      ret = G_ERROR;
    }
  }
  // Clean after me
  for (i=1; i<json_array_size(j_header_x5c); i++) {
    gnutls_x509_crt_deinit(cert_x509[i]);
  }
  gnutls_x509_crt_deinit(cert_x509[json_array_size(j_header_x5c)]);
  gnutls_x509_trust_list_deinit(tlist, 1);
  return ret;
}

static int validate_packed_leaf_certificate(gnutls_x509_crt_t cert, unsigned char * aaguid) {
  int ret = G_OK, i, c_valid = 0, o_valid = 0, ou_valid = 0, cn_valid = 0;
  unsigned int critial = 1, ca = 1;
  char cert_dn[128] = {0}, ** dn_exploded = NULL;
  unsigned char aaguid_oid[32];
  size_t cert_dn_len = 128, aaguid_oid_len = 32;
  
  do {
    if (gnutls_x509_crt_get_version(cert) != 3) {
      ret = G_ERROR_PARAM;
      y_log_message(Y_LOG_LEVEL_DEBUG, "validate_packed_leaf_certificate - Invalid certificate version");
      break;
    }
    
    if ((ret = gnutls_x509_crt_get_dn(cert, cert_dn, &cert_dn_len)) < 0) {
      ret = G_ERROR_PARAM;
      y_log_message(Y_LOG_LEVEL_DEBUG, "validate_packed_leaf_certificate - Error gnutls_x509_crt_get_dn");
      break;
    }
    
    if ((dn_exploded = ldap_explode_dn(cert_dn, 0)) == NULL) {
      ret = G_ERROR;
      y_log_message(Y_LOG_LEVEL_DEBUG, "validate_packed_leaf_certificate - Error ldap_explode_dn");
      break;
    }
    
    for (i=0; dn_exploded[i] != NULL; i++) {
      if (0 == o_strncasecmp(G_PACKED_CERT_C_KEY, dn_exploded[i], o_strlen(G_PACKED_CERT_C_KEY)) && string_array_has_value(iso_3166_list, dn_exploded[i]+o_strlen(G_PACKED_CERT_C_KEY))) {
        c_valid = 1;
      } else if (0 == o_strncasecmp(G_PACKED_CERT_O_KEY, dn_exploded[i], o_strlen(G_PACKED_CERT_O_KEY)) && o_strlen(dn_exploded[i]) > 2) {
        o_valid = 1;
      } else if (0 == o_strncasecmp(G_PACKED_CERT_CN_KEY, dn_exploded[i], o_strlen(G_PACKED_CERT_CN_KEY)) && o_strlen(dn_exploded[i]) > 3) {
        cn_valid = 1;
      } else if (0 == o_strncasecmp(G_PACKED_CERT_OU_KEY, dn_exploded[i], o_strlen(G_PACKED_CERT_OU_KEY)) && 0 == o_strcmp(G_PACKED_CERT_OU_VALUE, dn_exploded[i]+o_strlen(G_PACKED_CERT_OU_KEY))) {
        ou_valid = 1;
      }
    }
    ber_memvfree((void **)dn_exploded);
    
    if (!c_valid || !o_valid || !cn_valid || !ou_valid) {
      ret = G_ERROR_PARAM;
      y_log_message(Y_LOG_LEVEL_DEBUG, "validate_packed_leaf_certificate - Invalid dn - C:%s - O:%s - OU:%s - CN:%s", c_valid?"valid":"invalid", o_valid?"valid":"invalid", ou_valid?"valid":"invalid", cn_valid?"valid":"invalid");
      break;
    }
    
    if (gnutls_x509_crt_get_basic_constraints(cert, &critial, &ca, NULL) < 0) {
      ret = G_ERROR;
      y_log_message(Y_LOG_LEVEL_DEBUG, "validate_packed_leaf_certificate - Error gnutls_x509_crt_get_basic_constraints");
      break;
    }
    
    if (ca) {
      ret = G_ERROR_PARAM;
      y_log_message(Y_LOG_LEVEL_DEBUG, "validate_packed_leaf_certificate - Error basic constraints for CA is set to true");
      break;
    }
    
    if (gnutls_x509_crt_get_extension_by_oid(cert, G_PACKED_OID_AAGUID, 0, aaguid_oid, &aaguid_oid_len, NULL) >= 0) {
      if (aaguid_oid_len != AAGUID_LEN+2) {
        ret = G_ERROR_PARAM;
        y_log_message(Y_LOG_LEVEL_DEBUG, "validate_packed_leaf_certificate - Invalid aaguid_oid_len size %zu", aaguid_oid_len);
        break;
      }
      
      if (memcmp(aaguid_oid+2, aaguid, AAGUID_LEN)) {
        ret = G_ERROR_PARAM;
        y_log_message(Y_LOG_LEVEL_DEBUG, "validate_packed_leaf_certificate - Invalid aaguid_oid match");
        break;
      }
    }
    
  } while (0);
  
  return ret;
}

/**
 * 
 * Validate the attStmt object under the packed format
 * https://w3c.github.io/webauthn/#sctn-packed-attestation
 * (Step) Hey girl, when you smile
 * You got to know that you drive me wild
 * 
 */
static json_t * check_attestation_packed(json_t * j_params, cbor_item_t * auth_data, cbor_item_t * att_stmt, const unsigned char * client_data, gnutls_pubkey_t g_key) {
  json_t * j_error = json_array(), * j_return;
  cbor_item_t * key, * alg = NULL, * sig = NULL, * x5c_array = NULL, * cert_leaf = NULL;
  size_t i, client_data_hash_len = 32, cert_export_len = 128, cert_export_b64_len = 0;
  char * message;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_datum_t cert_dat, data, signature, cert_issued_by;
  int ret, sig_alg = GNUTLS_SIGN_UNKNOWN;
  unsigned char client_data_hash[32], cert_export[128], cert_export_b64[256];

  data.data = NULL;
  UNUSED(j_params);
  
  if (j_error != NULL) {
    do {
      for (i=0; i<cbor_map_size(att_stmt); i++) {
        key = cbor_map_handle(att_stmt)[i].key;
        if (cbor_isa_string(key)) {
          if (0 == o_strncmp((const char *)cbor_string_handle(key), "alg", MIN(o_strlen("alg"), cbor_string_length(key))) && cbor_isa_negint(cbor_map_handle(att_stmt)[i].value)) {
            alg = cbor_map_handle(att_stmt)[i].value;
            if (cbor_get_int(alg) == 6) {
              sig_alg = GNUTLS_SIGN_ECDSA_SHA256;
            } else if (cbor_get_int(alg) == 34) {
              sig_alg = GNUTLS_SIGN_ECDSA_SHA384;
            } else if (cbor_get_int(alg) == 35) {
              sig_alg = GNUTLS_SIGN_ECDSA_SHA512;
            }
            if (sig_alg == GNUTLS_SIGN_UNKNOWN) {
              json_array_append_new(j_error, json_string("Signature algorithm not supported"));
              break;
            }
          } else if (0 == o_strncmp((const char *)cbor_string_handle(key), "sig", MIN(o_strlen("sig"), cbor_string_length(key))) && cbor_isa_bytestring(cbor_map_handle(att_stmt)[i].value)) {
            sig = cbor_map_handle(att_stmt)[i].value;
          } else if (0 == o_strncmp((const char *)cbor_string_handle(key), "x5c", MIN(o_strlen("x5c"), cbor_string_length(key))) && cbor_isa_array(cbor_map_handle(att_stmt)[i].value) && cbor_array_size(cbor_map_handle(att_stmt)[i].value)) {
            x5c_array = cbor_map_handle(att_stmt)[i].value;
          } else if (0 == o_strncmp((const char *)cbor_string_handle(key), "ecdaaKeyId", MIN(o_strlen("ecdaaKeyId"), cbor_string_length(key)))) {
            json_array_append_new(j_error, json_string("ecdaaKeyId not supported"));
            break;
          }
        } else {
          message = msprintf("attStmt map element %zu key is not a string", i);
          json_array_append_new(j_error, json_string(message));
          o_free(message);
          break;
        }
      }
      
      if (json_array_size(j_error)) {
        break;
      }
      
      if (alg == NULL || sig == NULL) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_packed - Error alg or sig are not mapped in att_stmt");
        break;
      }
      
      if (!generate_digest_raw(digest_SHA256, client_data, o_strlen((char *)client_data), client_data_hash, &client_data_hash_len)) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_packed - Error generate_digest_raw client_data");
        break;
      }
      
      if ((data.data = o_malloc(cbor_bytestring_length(auth_data) + client_data_hash_len)) == NULL) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_packed - Error o_malloc data.data");
        break;
      }
      
      signature.data = cbor_bytestring_handle(sig);
      signature.size = cbor_bytestring_length(sig);
      
      memcpy(data.data, cbor_bytestring_handle(auth_data), cbor_bytestring_length(auth_data));
      memcpy(data.data + cbor_bytestring_length(auth_data), client_data_hash, client_data_hash_len);
      data.size = cbor_bytestring_length(auth_data) + client_data_hash_len;
        
      // packed disable SELF attestation for now
      if (x5c_array == NULL) {
        if (gnutls_pubkey_verify_data2(g_key, sig_alg, 0, &data, &signature)) {
          json_array_append_new(j_error, json_string("Invalid signature"));
          break;
        }
        
        cert_export_b64_len = 0;
        cert_export_b64[0] = '\0';
      } else {
        if (gnutls_x509_crt_init(&cert)) {
          json_array_append_new(j_error, json_string("check_attestation_packed - Error gnutls_x509_crt_init"));
          break;
        }
        if (gnutls_pubkey_init(&pubkey)) {
          json_array_append_new(j_error, json_string("check_attestation_packed - Error gnutls_pubkey_init"));
          break;
        }

        cert_leaf = cbor_array_get(x5c_array, 0);
        cert_dat.data = cbor_bytestring_handle(cert_leaf);
        cert_dat.size = cbor_bytestring_length(cert_leaf);
        
        if ((ret = gnutls_x509_crt_import(cert, &cert_dat, GNUTLS_X509_FMT_DER)) < 0) {
          json_array_append_new(j_error, json_string("Error importing x509 certificate"));
          y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_packed - Error gnutls_pcert_import_x509_raw: %d", ret);
          break;
        }
        
        if ((ret = gnutls_pubkey_import_x509(pubkey, cert, 0)) < 0) {
          json_array_append_new(j_error, json_string("Error importing x509 certificate"));
          y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_packed - Error gnutls_pubkey_import_x509: %d", ret);
          break;
        }
        
        if (gnutls_pubkey_verify_data2(pubkey, sig_alg, 0, &data, &signature)) {
          json_array_append_new(j_error, json_string("Invalid signature"));
          break;
        }
        
        if (validate_packed_leaf_certificate(cert, (cbor_bytestring_handle(auth_data)+ATTESTED_CRED_DATA_OFFSET)) != G_OK) {
          json_array_append_new(j_error, json_string("Invalid certificate"));
          break;
        }
        
        if ((ret = gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA256, cert_export, &cert_export_len)) < 0) {
          json_array_append_new(j_error, json_string("Error exporting x509 certificate"));
          y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_packed - Error gnutls_x509_crt_get_key_id: %d", ret);
          break;
        }
        
        if (json_object_get(j_params, "root-ca-list") != json_null() && validate_certificate_from_root(j_params, cert, x5c_array) != G_OK) {
          json_array_append_new(j_error, json_string("Unrecognized certificate authority"));
          if (gnutls_x509_crt_get_issuer_dn2(cert, &cert_issued_by) >= 0) {
            message = msprintf("Unrecognized certificate autohority: %.*s", cert_issued_by.size, cert_issued_by.data);
            y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_packed - %s", message);
            o_free(message);
            gnutls_free(cert_issued_by.data);
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_packed - Unrecognized certificate autohority (unable to get issuer dn)");
          }
          break;
        }
        
        if (!o_base64_encode(cert_export, cert_export_len, cert_export_b64, &cert_export_b64_len)) {
          json_array_append_new(j_error, json_string("Internal error"));
          y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_packed - Error o_base64_encode cert_export");
          break;
        }
      }
      
    } while (0);
    
    if (json_array_size(j_error)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
    } else {
      j_return = json_pack("{sis{ss%}}", "result", G_OK, "data", "certificate", cert_export_b64, cert_export_b64_len);
    }
    json_decref(j_error);
    gnutls_x509_crt_deinit(cert);
    gnutls_pubkey_deinit(pubkey);
    o_free(data.data);
    if (cert_leaf != NULL) {
      cbor_decref(&cert_leaf);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_packed - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

/**
 * 
 * Validate the attStmt object under the Android SafetyNet format
 * https://w3c.github.io/webauthn/#sctn-android-safetynet-attestation
 * (step) hey girl, in your eyes
 * I see a picture of me all the time
 * 
 */
static json_t * check_attestation_android_safetynet(json_t * j_params, cbor_item_t * auth_data, cbor_item_t * att_stmt, const unsigned char * client_data) {
  json_t * j_error = json_array(), * j_return;
  unsigned char pubkey_export[1024] = {0}, cert_export[32] = {0}, cert_export_b64[64], client_data_hash[32], * nonce_base = NULL, nonce_base_hash[32], * nonce_base_hash_b64 = NULL, * header_cert_decoded = NULL;
  char * message = NULL, * response_token = NULL, issued_to[128] = {0}, * jwt_header = NULL;
  size_t pubkey_export_len = 1024, cert_export_len = 32, cert_export_b64_len, issued_to_len = 128, client_data_hash_len = 32, nonce_base_hash_len = 32, nonce_base_hash_b64_len = 0, header_cert_decoded_len = 0;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  cbor_item_t * key, * response = NULL;
  int i, ret;
  jwt_t * j_response = NULL;
  json_t * j_header_x5c = NULL, * j_cert = NULL, * j_header = NULL, * j_value = NULL;
  gnutls_datum_t cert_dat;
  int has_ver = 0;
  
  if (j_error != NULL) {
    do {
      // Step 1
      if (!cbor_isa_map(att_stmt) || cbor_map_size(att_stmt) != 2) {
        json_array_append_new(j_error, json_string("CBOR map value 'attStmt' invalid format"));
        break;
      }
      for (i=0; i<2; i++) {
        key = cbor_map_handle(att_stmt)[i].key;
        if (cbor_isa_string(key)) {
          if (0 == o_strncmp((const char *)cbor_string_handle(key), "ver", MIN(o_strlen("ver"), cbor_string_length(key))) && cbor_isa_string(cbor_map_handle(att_stmt)[i].value)) {
            has_ver = 1;
          } else if (0 == o_strncmp((const char *)cbor_string_handle(key), "response", MIN(o_strlen("response"), cbor_string_length(key))) && cbor_isa_bytestring(cbor_map_handle(att_stmt)[i].value)) {
            response = cbor_map_handle(att_stmt)[i].value;
          } else {
            message = msprintf("attStmt map element %d key is not valid: '%.*s'", i, cbor_string_length(key), cbor_string_handle(key));
            json_array_append_new(j_error, json_string(message));
            o_free(message);
            break;
          }
        } else {
          message = msprintf("attStmt map element %d key is not a string", i);
          json_array_append_new(j_error, json_string(message));
          o_free(message);
          break;
        }
      }
      
      if (!has_ver) {
        json_array_append_new(j_error, json_string("version invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error ver missing");
        break;
      }

      if (!generate_digest_raw(digest_SHA256, client_data, o_strlen((char *)client_data), client_data_hash, &client_data_hash_len)) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error generate_digest_raw client_data");
        break;
      }
      
      if ((nonce_base = o_malloc(32 + cbor_bytestring_length(auth_data))) == NULL) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error allocating resources for nonce_base");
        break;
      }
      memcpy(nonce_base, cbor_bytestring_handle(auth_data), cbor_bytestring_length(auth_data));
      memcpy(nonce_base+cbor_bytestring_length(auth_data), client_data_hash, client_data_hash_len);
      
      if (!generate_digest_raw(digest_SHA256, nonce_base, 32 + cbor_bytestring_length(auth_data), nonce_base_hash, &nonce_base_hash_len)) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error generate_digest_raw nonce_base");
        break;
      }
      
      if ((nonce_base_hash_b64 = o_malloc(64)) == NULL) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error allocating resources for nonce_base_hash_b64");
        break;
      }

      if (!o_base64_encode(nonce_base_hash, 32, nonce_base_hash_b64, &nonce_base_hash_b64_len)) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error o_base64_encode for nonce_base_hash_b64");
        break;
      }
      
      if (response == NULL) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error response missing");
        break;
      }
      
      if ((response_token = o_strndup((const char *)cbor_bytestring_handle(response), cbor_bytestring_length(response))) == NULL) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error o_strndup for response_token");
        break;
      }
      
      if (r_jwt_init(&j_response) != RHN_OK) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error r_jwt_init");
        break;
      }
      
      if (r_jwt_parse(j_response, response_token, 0) != RHN_OK) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error r_jwt_parse");
        break;
      }
      
      if (o_strcmp(r_jwt_get_claim_str_value(j_response, "nonce"), (const char *)nonce_base_hash_b64)) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error nonce invalid");
        break;
      }
      
      if (json_integer_value(json_object_get(j_params, "ctsProfileMatch")) != -1 && json_integer_value(json_object_get(j_params, "ctsProfileMatch")) != ((j_value = r_jwt_get_claim_json_t_value(j_response, "ctsProfileMatch"))==json_true()?1:0)) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error ctsProfileMatch invalid");
        json_decref(j_value);
        j_value = NULL;
        break;
      }
      json_decref(j_value);
      j_value = NULL;
      
      if (json_integer_value(json_object_get(j_params, "basicIntegrity")) != -1 && json_integer_value(json_object_get(j_params, "basicIntegrity")) != ((j_value = r_jwt_get_claim_json_t_value(j_response, "basicIntegrity"))==json_true()?1:0)) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error basicIntegrity invalid");
        j_value = NULL;
        break;
      }
      json_decref(j_value);
      j_value = NULL;
      
      if (r_jwt_verify_signature(j_response, NULL, 0) != RHN_OK) {
        json_array_append_new(j_error, json_string("Invalid signature"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error r_jwt_verify_signature");
        break;
      }
      
      if ((j_header_x5c = r_jwt_get_header_json_t_value(j_response, "x5c")) == NULL) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error parsing x5c JSON");
        break;
      }
      
      if (!json_is_string((j_cert = json_array_get(j_header_x5c, 0)))) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error x5c leaf not a string");
        break;
      }
      
      if ((header_cert_decoded = o_malloc(json_string_length(j_cert))) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error allocating resources for header_cert_decoded");
        break;
      }
      
      if (!o_base64_decode((const unsigned char *)json_string_value(j_cert), json_string_length(j_cert), header_cert_decoded, &header_cert_decoded_len)) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error o_base64_decode x5c leaf");
        break;
      }
      
      if (gnutls_x509_crt_init(&cert)) {
        json_array_append_new(j_error, json_string("internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error gnutls_x509_crt_init");
        break;
      }
      if (gnutls_pubkey_init(&pubkey)) {
        json_array_append_new(j_error, json_string("internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error gnutls_pubkey_init");
        break;
      }
      cert_dat.data = header_cert_decoded;
      cert_dat.size = header_cert_decoded_len;
      if ((ret = gnutls_x509_crt_import(cert, &cert_dat, GNUTLS_X509_FMT_DER)) < 0) {
        json_array_append_new(j_error, json_string("Error importing x509 certificate"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error gnutls_pcert_import_x509_raw: %d", ret);
        break;
      }
      if ((ret = gnutls_pubkey_import_x509(pubkey, cert, 0)) < 0) {
        json_array_append_new(j_error, json_string("Error importing x509 certificate"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error gnutls_pubkey_import_x509: %d", ret);
        break;
      }
      if ((ret = gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA256, cert_export, &cert_export_len)) < 0) {
        json_array_append_new(j_error, json_string("Error exporting x509 certificate"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error gnutls_x509_crt_get_key_id: %d", ret);
        break;
      }
      if ((ret = gnutls_x509_crt_get_dn(cert, issued_to, &issued_to_len)) < 0) {
        json_array_append_new(j_error, json_string("Error x509 dn"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error gnutls_x509_crt_get_dn: %d", ret);
        break;
      }
      if (o_strnstr(issued_to, SAFETYNET_ISSUED_TO, issued_to_len) == NULL) {
        json_array_append_new(j_error, json_string("Error x509 dn"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - safetynet certificate issued for %.*s", issued_to_len, issued_to);
        break;
      }
      if (json_object_get(j_params, "google-root-ca-r2") != json_null()) {
        if ((ret = validate_safetynet_ca_root(j_params, cert, j_header_x5c)) == G_ERROR_UNAUTHORIZED) {
          json_array_append_new(j_error, json_string("Error x509 certificate chain validation"));
          break;
        } else if (ret != G_OK) {
          json_array_append_new(j_error, json_string("response invalid"));
          y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - safetynet certificate chain certificate validation error");
          break;
        }
      }
      if (!o_base64_encode(cert_export, cert_export_len, cert_export_b64, &cert_export_b64_len)) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error o_base64_encode cert_export");
        break;
      }
      if ((ret = gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_PEM, pubkey_export, &pubkey_export_len)) < 0) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error gnutls_pubkey_export: %d", ret);
        break;
      }
      
    } while (0);

    if (json_array_size(j_error)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
    } else {
      j_return = json_pack("{sis{ss%}}", "result", G_OK, "data", "certificate", cert_export_b64, cert_export_b64_len);
    }
    json_decref(j_error);
    json_decref(j_header);
    json_decref(j_header_x5c);
    gnutls_pubkey_deinit(pubkey);
    gnutls_x509_crt_deinit(cert);
    r_jwt_free(j_response);
    o_free(nonce_base);
    o_free(nonce_base_hash_b64);
    o_free(response_token);
    o_free(header_cert_decoded);
    o_free(jwt_header);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

/**
 * 
 * Validate the attStmt object under the fido-u2f format
 * https://w3c.github.io/webauthn/#sctn-fido-u2f-attestation
 * Gonna get to you girl
 * Really want you in my world
 * 
 */
static json_t * check_attestation_fido_u2f(json_t * j_params, unsigned char * credential_id, size_t credential_id_len, unsigned char * cert_x, size_t cert_x_len, unsigned char * cert_y, size_t cert_y_len, cbor_item_t * att_stmt, unsigned char * rpid_hash, size_t rpid_hash_len, const unsigned char * client_data) {
  json_t * j_error = json_array(), * j_return;
  cbor_item_t * key = NULL, * x5c = NULL, * sig = NULL, * att_cert = NULL;
  int i, ret;
  char * message = NULL;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_datum_t cert_dat, data, signature, cert_issued_by;
  unsigned char data_signed[200], client_data_hash[32], cert_export[32], cert_export_b64[64];
  size_t data_signed_offset = 0, client_data_hash_len = 32, cert_export_len = 32, cert_export_b64_len = 0;
  
  if (j_error != NULL) {
    do {
      if (gnutls_x509_crt_init(&cert)) {
        json_array_append_new(j_error, json_string("check_attestation_fido_u2f - Error gnutls_x509_crt_init"));
        break;
      }
      if (gnutls_pubkey_init(&pubkey)) {
        json_array_append_new(j_error, json_string("check_attestation_fido_u2f - Error gnutls_pubkey_init"));
        break;
      }
      
      // Step 1
      if (att_stmt == NULL || !cbor_isa_map(att_stmt) || cbor_map_size(att_stmt) != 2) {
        json_array_append_new(j_error, json_string("CBOR map value 'attStmt' invalid format"));
        break;
      }
      for (i=0; i<2; i++) {
        key = cbor_map_handle(att_stmt)[i].key;
        if (cbor_isa_string(key)) {
          if (0 == o_strncmp((const char *)cbor_string_handle(key), "x5c", MIN(o_strlen("x5c"), cbor_string_length(key)))) {
            x5c = cbor_map_handle(att_stmt)[i].value;
          } else if (0 == o_strncmp((const char *)cbor_string_handle(key), "sig", MIN(o_strlen("sig"), cbor_string_length(key)))) {
            sig = cbor_map_handle(att_stmt)[i].value;
          } else {
            message = msprintf("attStmt map element %d key is not valid: '%.*s'", i, cbor_string_length(key), cbor_string_handle(key));
            json_array_append_new(j_error, json_string(message));
            o_free(message);
            break;
          }
        } else {
          message = msprintf("attStmt map element %d key is not a string", i);
          json_array_append_new(j_error, json_string(message));
          o_free(message);
          break;
        }
      }
      if (x5c == NULL || !cbor_isa_array(x5c) || cbor_array_size(x5c) != 1) {
        json_array_append_new(j_error, json_string("CBOR map value 'x5c' invalid format"));
        break;
      }
      att_cert = cbor_array_get(x5c, 0);
      cert_dat.data = cbor_bytestring_handle(att_cert);
      cert_dat.size = cbor_bytestring_length(att_cert);
      if ((ret = gnutls_x509_crt_import(cert, &cert_dat, GNUTLS_X509_FMT_DER)) < 0) {
        json_array_append_new(j_error, json_string("Error importing x509 certificate"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_fido_u2f - Error gnutls_pcert_import_x509_raw: %d", ret);
        break;
      }
      if (json_object_get(j_params, "root-ca-list") != json_null() && validate_certificate_from_root(j_params, cert, x5c) != G_OK) {
        json_array_append_new(j_error, json_string("Unrecognized certificate authority"));
        if (gnutls_x509_crt_get_issuer_dn2(cert, &cert_issued_by) >= 0) {
          message = msprintf("Unrecognized certificate autohority: %.*s", cert_issued_by.size, cert_issued_by.data);
          y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_fido_u2f - %s", message);
          o_free(message);
          gnutls_free(cert_issued_by.data);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_fido_u2f - Unrecognized certificate autohority (unable to get issuer dn)");
        }
        break;
      }
      if ((ret = gnutls_pubkey_import_x509(pubkey, cert, 0)) < 0) {
        json_array_append_new(j_error, json_string("Error importing x509 certificate"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_fido_u2f - Error gnutls_pubkey_import_x509: %d", ret);
        break;
      }
      if ((ret = gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA256, cert_export, &cert_export_len)) < 0) {
        json_array_append_new(j_error, json_string("Error exporting x509 certificate"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_fido_u2f - Error gnutls_x509_crt_get_key_id: %d", ret);
        break;
      }
      if (!o_base64_encode(cert_export, cert_export_len, cert_export_b64, &cert_export_b64_len)) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_fido_u2f - Error o_base64_encode cert_export");
        break;
      }
      if (!generate_digest_raw(digest_SHA256, client_data, o_strlen((char *)client_data), client_data_hash, &client_data_hash_len)) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error generate_digest_raw client_data");
        break;
      }

      if (sig == NULL || !cbor_isa_bytestring(sig)) {
        json_array_append_new(j_error, json_string("Error sig is not a bytestring"));
        break;
      }
      
      // Build bytestring to verify signature
      data_signed[0] = 0x0;
      data_signed_offset = 1;
      
      memcpy(data_signed+data_signed_offset, rpid_hash, rpid_hash_len);
      data_signed_offset += rpid_hash_len;
      
      memcpy(data_signed+data_signed_offset, client_data_hash, client_data_hash_len);
      data_signed_offset+=client_data_hash_len;
      
      memcpy(data_signed+data_signed_offset, credential_id, credential_id_len);
      data_signed_offset+=credential_id_len;
      
      data_signed[data_signed_offset] = 0x04;
      data_signed_offset++;
      
      memcpy(data_signed+data_signed_offset, cert_x, cert_x_len);
      data_signed_offset+=cert_x_len;
      
      memcpy(data_signed+data_signed_offset, cert_y, cert_y_len);
      data_signed_offset+=cert_y_len;
        
      // Let's verify sig over data_signed
      data.data = data_signed;
      data.size = data_signed_offset;
      
      signature.data = cbor_bytestring_handle(sig);
      signature.size = cbor_bytestring_length(sig);
      
      if (gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_ECDSA_SHA256, 0, &data, &signature)) {
        json_array_append_new(j_error, json_string("Invalid signature"));
      }
      
    } while (0);
    
    if (json_array_size(j_error)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
    } else {
      j_return = json_pack("{sis{ss%}}", "result", G_OK, "data", "certificate", cert_export_b64, cert_export_b64_len);
    }
    json_decref(j_error);
    gnutls_pubkey_deinit(pubkey);
    gnutls_x509_crt_deinit(cert);
    if (att_cert != NULL) {
      cbor_decref(&att_cert);
    }
    
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

/**
 * 
 * It's like the New Kids On The Block
 * 
 * You have to validate the credential by following
 * the registration procedure step by step
 * Because the w3c said so
 * https://w3c.github.io/webauthn/#registering-a-new-credential
 * 
 */
static json_t * register_new_attestation(struct config_module * config, json_t * j_params, json_t * j_scheme_data, json_t * j_credential) {
  json_t * j_return, * j_client_data = NULL, * j_error, * j_result, * j_pubkey = NULL, * j_cert = NULL, * j_query, * j_element = NULL;
  unsigned char * client_data = NULL, * challenge_b64 = NULL, * att_obj = NULL, * cbor_bs_handle = NULL, rpid_hash[32], * fmt = NULL, * credential_id_b64 = NULL, * cbor_auth_data, * cred_pub_key, cert_x[256], cert_y[256], pubkey_export[1024];
  char * challenge_hash = NULL, * message = NULL;
  const char * rpid = NULL;
  size_t client_data_len = 0, challenge_b64_len = 0, att_obj_len = 0, rpid_hash_len = 32, fmt_len = 0, credential_id_len = 0, credential_id_b64_len, cbor_auth_data_len, cred_pub_key_len, cert_x_len = 0, cert_y_len = 0, pubkey_export_len = 1024, index = 0, cbor_bs_handle_len, rpid_len;
  uint32_t counter = 0;
  int ret = G_OK, res, status, has_x = 0, has_y = 0, key_type_valid = 0, key_alg_valid = 0;
  unsigned int i;
  struct cbor_load_result cbor_result;
  cbor_item_t * item = NULL, * key = NULL, * auth_data = NULL, * att_stmt = NULL, * cbor_cose = NULL, * cbor_key, * cbor_value;
  gnutls_pubkey_t g_key = NULL;
  gnutls_datum_t g_x, g_y;
  gnutls_ecc_curve_t curve = GNUTLS_ECC_CURVE_INVALID;
  
  if (j_scheme_data != NULL) {
    j_error = json_array();
    if (j_error != NULL) {
      do {
        if (!json_string_length(json_object_get(json_object_get(j_scheme_data, "credential"), "rawId"))) {
          json_array_append_new(j_error, json_string("rawId mandatory"));
          ret = G_ERROR_PARAM;
          break;
        }
        if (!json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON"))) {
          json_array_append_new(j_error, json_string("clientDataJSON mandatory"));
          ret = G_ERROR_PARAM;
          break;
        }
        if ((client_data = o_malloc(json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON"))+1)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error allocating resources for client_data");
          json_array_append_new(j_error, json_string("Internal error"));
          ret = G_ERROR_MEMORY;
          break;
        }
        if (!o_base64_decode((const unsigned char *)json_string_value(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON")), json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON")), client_data, &client_data_len)) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "register_new_attestation - Error o_base64_decode client_data");
          json_array_append_new(j_error, json_string("Internal error"));
          ret = G_ERROR_PARAM;
          break;
        }
        client_data[client_data_len] = '\0';
        j_client_data = json_loads((const char *)client_data, JSON_DECODE_ANY, NULL);
        if (j_client_data == NULL) {
          json_array_append_new(j_error, json_string("Error parsing JSON client data"));
          ret = G_ERROR_PARAM;
          break;
        }
        // Step 3
        if (0 != o_strcmp(json_string_value(json_object_get(j_client_data, "type")), "webauthn.create")) {
          json_array_append_new(j_error, json_string("clientDataJSON.type invalid"));
          ret = G_ERROR_PARAM;
          break;
        }
        // Step 4
        if (!json_string_length(json_object_get(j_client_data, "challenge"))) {
          json_array_append_new(j_error, json_string("clientDataJSON.challenge mandatory"));
          ret = G_ERROR_PARAM;
          break;
        }
        if ((challenge_b64 = o_malloc(json_string_length(json_object_get(j_client_data, "challenge"))+3)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error allocating resources for challenge_b64");
          json_array_append_new(j_error, json_string("Internal error"));
          ret = G_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_2_base64((unsigned char *)json_string_value(json_object_get(j_client_data, "challenge")), json_string_length(json_object_get(j_client_data, "challenge")), challenge_b64, &challenge_b64_len)) {
          json_array_append_new(j_error, json_string("clientDataJSON.challenge invalid format"));
          ret = G_ERROR_PARAM;
          break;
        }
        challenge_b64[challenge_b64_len] = '\0';
        if ((challenge_hash = generate_hash(config->hash_algorithm, (const char *)challenge_b64)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error generate_hash for challenge_b64");
          json_array_append_new(j_error, json_string("Internal error"));
          ret = G_ERROR;
          break;
        }
        if (0 != o_strcmp(challenge_hash, json_string_value(json_object_get(j_credential, "challenge_hash")))) {
          json_array_append_new(j_error, json_string("clientDataJSON.challenge invalid"));
          ret = G_ERROR_PARAM;
          break;
        }
        // Step 5
        if (!json_string_length(json_object_get(j_client_data, "origin"))) {
          json_array_append_new(j_error, json_string("clientDataJSON.origin mandatory"));
          ret = G_ERROR_PARAM;
          break;
        }
        if (0 != o_strcmp(json_string_value(json_object_get(j_params, "rp-origin")), json_string_value(json_object_get(j_client_data, "origin")))) {
          message = msprintf("clientDataJSON.origin invalid - Client send %s, required %s", json_string_value(json_object_get(j_client_data, "origin")), json_string_value(json_object_get(j_params, "rp-origin")));
          json_array_append_new(j_error, json_string(message));
          o_free(message);
          ret = G_ERROR_PARAM;
          break;
        }
        // Step 6 ??
        
        if (!json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "attestationObject"))) {
          json_array_append_new(j_error, json_string("attestationObject required"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        if ((att_obj = o_malloc(json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "attestationObject")))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error allocating resources for o_malloc");
          ret = G_ERROR_MEMORY;
          break;
        }
        if (!o_base64_decode((unsigned char *)json_string_value(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "attestationObject")), json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "attestationObject")), att_obj, &att_obj_len)) {
          json_array_append_new(j_error, json_string("attestationObject invalid base64"));
          ret = G_ERROR_PARAM;
          break;
        }

        // Step 7
        item = cbor_load(att_obj, att_obj_len, &cbor_result);
        if (cbor_result.error.code != CBOR_ERR_NONE) {
          json_array_append_new(j_error, json_string("attestationObject invalid cbor"));
          ret = G_ERROR_PARAM;
          break;
        }
        if (!cbor_isa_map(item)) {
          json_array_append_new(j_error, json_string("attestationObject invalid cbor item"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        // Check attestation object
        if (cbor_map_size(item) != 3) {
          json_array_append_new(j_error, json_string("attestationObject invalid cbor item"));
          ret = G_ERROR_PARAM;
          break;
        }

        for (i=0; i<3; i++) {
          key = cbor_map_handle(item)[i].key;
          if (cbor_isa_string(key)) {
            if (0 == o_strncmp((const char *)cbor_string_handle(key), "fmt", MIN(o_strlen("fmt"), cbor_string_length(key)))) {
              if (!cbor_isa_string(cbor_map_handle(item)[i].value)) {
                json_array_append_new(j_error, json_string("CBOR map value 'fmt' isnt't a string"));
                ret = G_ERROR_PARAM;
                break;
              } else {
                fmt_len = cbor_string_length(cbor_map_handle(item)[i].value);
                fmt = cbor_string_handle(cbor_map_handle(item)[i].value);
              }
            } else if (0 == o_strncmp((const char *)cbor_string_handle(key), "attStmt", MIN(o_strlen("attStmt"), cbor_string_length(key)))) {
              att_stmt = cbor_map_handle(item)[i].value;
            } else if (0 == o_strncmp((const char *)cbor_string_handle(key), "authData", MIN(o_strlen("authData"), cbor_string_length(key)))) {
              auth_data = cbor_map_handle(item)[i].value;
              if (!cbor_isa_bytestring(auth_data) || cbor_bytestring_length(auth_data) < 56 || cbor_bytestring_is_indefinite(auth_data)) {
                json_array_append_new(j_error, json_string("CBOR map value 'authData' is invalid"));
                ret = G_ERROR_PARAM;
                break;
              }
            } else {
              message = msprintf("CBOR map element %d is not an expected item", i);
              json_array_append_new(j_error, json_string(message));
              o_free(message);
              ret = G_ERROR_PARAM;
              break;
            }
          }
        }
        
        // Step 9
        if (auth_data == NULL) {
          json_array_append_new(j_error, json_string("authData invalid"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        cbor_bs_handle = cbor_bytestring_handle(auth_data);
        cbor_bs_handle_len = cbor_bytestring_length(auth_data);
        if (o_strstr(json_string_value(json_object_get(j_params, "rp-origin")), "://") == NULL) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "register_new_attestation - rp-origin invalid");
          json_array_append_new(j_error, json_string("Internal error"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        if (o_strstr(json_string_value(json_object_get(j_params, "rp-origin")), "://") != NULL) {
          rpid = o_strstr(json_string_value(json_object_get(j_params, "rp-origin")), "://")+3;
        } else {
          rpid = json_string_value(json_object_get(j_params, "rp-origin"));
        }
        if (o_strchr(rpid, ':') != NULL) {
          rpid_len = o_strchr(rpid, ':') - rpid;
        } else {
          rpid_len = o_strlen(rpid);
        }
        
        if (!generate_digest_raw(digest_SHA256, (unsigned char *)rpid, rpid_len, rpid_hash, &rpid_hash_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error generate_digest_raw");
          json_array_append_new(j_error, json_string("Internal error"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        if (0 != memcmp(cbor_bs_handle, rpid_hash, rpid_hash_len)) {
          json_array_append_new(j_error, json_string("authData.rpIdHash invalid"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        // Step 10
        if (!(cbor_bs_handle[FLAGS_OFFSET] & FLAG_USER_PRESENT)) {
          json_array_append_new(j_error, json_string("authData.userPresent not set"));
          ret = G_ERROR_PARAM;
          break;
        }
        if (!(cbor_bs_handle[FLAGS_OFFSET] & FLAG_AT)) {
          json_array_append_new(j_error, json_string("authData.Attested credential data not set"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        // Step 11 ignored for now
        //y_log_message(Y_LOG_LEVEL_DEBUG, "authData.userVerified: %d", !!(cbor_bs_handle[FLAGS_OFFSET] & FLAG_USER_VERIFY));
        
        // Step 12 ignored for now (no extension)
        //y_log_message(Y_LOG_LEVEL_DEBUG, "authData.Extension: %d", !!(cbor_bs_handle[FLAGS_OFFSET] & FLAG_ED));
        
        credential_id_len = cbor_bs_handle[CRED_ID_L_OFFSET+1] | (cbor_bs_handle[CRED_ID_L_OFFSET] << 8);
        if (cbor_bs_handle_len < CRED_ID_L_OFFSET+2+credential_id_len) {
          json_array_append_new(j_error, json_string("auth_data invalid size"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        credential_id_b64 = o_malloc(credential_id_len*2);
        if (credential_id_b64 == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error o_malloc for credential_id_b64");
          json_array_append_new(j_error, json_string("Internal error"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        if (!o_base64_encode(cbor_bs_handle+CRED_ID_L_OFFSET+2, credential_id_len, credential_id_b64, &credential_id_b64_len)) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "register_new_attestation - Error o_base64_encode for credential_id_b64");
          json_array_append_new(j_error, json_string("Internal error"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        // Compare credential_id_b64 with rawId
        if (memcmp(credential_id_b64, json_string_value(json_object_get(json_object_get(j_scheme_data, "credential"), "rawId")), MIN(json_string_length(json_object_get(json_object_get(j_scheme_data, "credential"), "rawId")), credential_id_b64_len))) {
          json_array_append_new(j_error, json_string("Invalid rawId"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        // Extract public key from auth_data COSE structure

        // Extract credential ID
        cbor_auth_data_len = cbor_bytestring_length(auth_data);
        cbor_auth_data = cbor_bytestring_handle(auth_data);
        
        cred_pub_key = cbor_auth_data+CREDENTIAL_ID_OFFSET+credential_id_len;
        cred_pub_key_len = cbor_auth_data_len-CREDENTIAL_ID_OFFSET-credential_id_len;
        cbor_cose = cbor_load(cred_pub_key, cred_pub_key_len, &cbor_result);
        if (cbor_result.error.code != CBOR_ERR_NONE) {
          json_array_append_new(j_error, json_string("Invalid COSE key"));
          y_log_message(Y_LOG_LEVEL_DEBUG, "register_new_attestation - Error cbor_load cbor_cose");
          ret = G_ERROR_PARAM;
          break;
        }
        
        if (!cbor_isa_map(cbor_cose)) {
          json_array_append_new(j_error, json_string("Invalid COSE key"));
          y_log_message(Y_LOG_LEVEL_DEBUG, "register_new_attestation - Error cbor_cose not a map");
          ret = G_ERROR_PARAM;
          break;
        }
        
        for (i=0; i<cbor_map_size(cbor_cose); i++) {
          cbor_key = cbor_map_handle(cbor_cose)[i].key;
          cbor_value = cbor_map_handle(cbor_cose)[i].value;
          if (cbor_isa_negint(cbor_key) && cbor_get_int(cbor_key) == 1 && cbor_isa_bytestring(cbor_value)) {
            has_x = 1;
            memcpy(cert_x, cbor_bytestring_handle(cbor_value), cbor_bytestring_length(cbor_value));
            cert_x_len = cbor_bytestring_length(cbor_value);
            g_x.data = cert_x;
            g_x.size = cbor_bytestring_length(cbor_value);
          } else if (cbor_isa_negint(cbor_key) && cbor_get_int(cbor_key) == 2 && cbor_isa_bytestring(cbor_value)) {
            has_y = 1;
            memcpy(cert_y, cbor_bytestring_handle(cbor_value), cbor_bytestring_length(cbor_value));
            cert_y_len = cbor_bytestring_length(cbor_value);
            g_y.data = cert_y;
            g_y.size = cbor_bytestring_length(cbor_value);
          } else if (cbor_isa_uint(cbor_key) && cbor_get_int(cbor_key) == 1 && cbor_isa_uint(cbor_value) && cbor_get_int(cbor_value) == 2) {
            key_type_valid = 1;
          } else if (cbor_isa_uint(cbor_key) && cbor_get_int(cbor_key) == 3 && cbor_isa_negint(cbor_value)) {
            if (cbor_get_int(cbor_value) == 6 || cbor_get_int(cbor_value) == 34 || cbor_get_int(cbor_value) == 35) {
              json_array_foreach(json_object_get(j_params, "pubKey-cred-params"), index, j_element) {
                if (cbor_get_int(cbor_value) == 6 && json_integer_value(json_object_get(j_element, "alg")) == ECDSA256) {
                  key_alg_valid = 1;
                  curve = GNUTLS_ECC_CURVE_SECP256R1;
                } else if (cbor_get_int(cbor_value) == 34 && json_integer_value(json_object_get(j_element, "alg")) == ECDSA384) {
                  key_alg_valid = 1;
                  curve = GNUTLS_ECC_CURVE_SECP384R1;
                } else if (cbor_get_int(cbor_value) == 35 && json_integer_value(json_object_get(j_element, "alg")) == ECDSA512) {
                  key_alg_valid = 1;
                  curve = GNUTLS_ECC_CURVE_SECP521R1;
                }
              }
            }
          }
        }
        
        if (!has_x || !has_y || !key_type_valid || !key_alg_valid) {
          json_array_append_new(j_error, json_string("Invalid COSE key"));
          y_log_message(Y_LOG_LEVEL_DEBUG, "register_new_attestation - Error invalid COSE key has_x %d && has_y %d && key_type_valid %d && key_alg_valid %d", has_x, has_y, key_type_valid, key_alg_valid);
          ret = G_ERROR_PARAM;
          break;
        }
        
        if (gnutls_pubkey_init(&g_key)) {
          json_array_append_new(j_error, json_string("Internal error"));
          y_log_message(Y_LOG_LEVEL_DEBUG, "register_new_attestation - Error gnutls_pubkey_init");
          ret = G_ERROR_PARAM;
          break;
        }
        if (gnutls_pubkey_import_ecc_raw(g_key, curve, &g_x, &g_y) < 0) {
          json_array_append_new(j_error, json_string("Internal error"));
          y_log_message(Y_LOG_LEVEL_DEBUG, "register_new_attestation - error gnutls_pubkey_import_ecc_raw");
          ret = G_ERROR_PARAM;
          break;
        }
        if ((ret = gnutls_pubkey_export(g_key, GNUTLS_X509_FMT_PEM, pubkey_export, &pubkey_export_len)) < 0) {
          json_array_append_new(j_error, json_string("Error exporting pubkey"));
          y_log_message(Y_LOG_LEVEL_DEBUG, "register_new_attestation - Error gnutls_pubkey_export: %d", ret);
          ret = G_ERROR_PARAM;
          break;
        }
        
        // Steps 13-14
        if (0 == o_strncmp("packed", (char *)fmt, MIN(fmt_len, o_strlen("packed"))) && (json_object_get(json_object_get(j_params, "fmt"), "packed") == json_true())) {
          j_result = check_attestation_packed(j_params, auth_data, att_stmt, client_data, g_key);
          if (check_result_value(j_result, G_ERROR_PARAM)) {
            json_array_extend(j_error, json_object_get(j_result, "error"));
            ret = G_ERROR_PARAM;
          } else if (!check_result_value(j_result, G_OK)) {
            ret = G_ERROR_PARAM;
            y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error check_attestation_packed");
            json_array_append_new(j_error, json_string("internal error"));
          } else {
            j_cert = json_incref(json_object_get(json_object_get(j_result, "data"), "certificate"));
          }
          json_decref(j_result);
        } else if (0 == o_strncmp("tpm", (char *)fmt, MIN(fmt_len, o_strlen("tpm"))) && (json_object_get(json_object_get(j_params, "fmt"), "tpm") == json_true())) {
          json_array_append_new(j_error, json_string("Format 'tpm' not supported yet"));
          ret = G_ERROR_PARAM;
        } else if (0 == o_strncmp("android-key", (char *)fmt, MIN(fmt_len, o_strlen("android-key"))) && (json_object_get(json_object_get(j_params, "fmt"), "android-key") == json_true())) {
          json_array_append_new(j_error, json_string("Format 'android-key' not supported yet"));
          ret = G_ERROR_PARAM;
        } else if (0 == o_strncmp("android-safetynet", (char *)fmt, MIN(fmt_len, o_strlen("android-safetynet"))) && (json_object_get(json_object_get(j_params, "fmt"), "android-safetynet") == json_true())) {
          j_result = check_attestation_android_safetynet(j_params, auth_data, att_stmt, client_data);
          if (check_result_value(j_result, G_ERROR_PARAM)) {
            json_array_extend(j_error, json_object_get(j_result, "error"));
            ret = G_ERROR_PARAM;
          } else if (!check_result_value(j_result, G_OK)) {
            ret = G_ERROR_PARAM;
            y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error check_attestation_android_safetynet");
            json_array_append_new(j_error, json_string("internal error"));
          } else {
            j_cert = json_incref(json_object_get(json_object_get(j_result, "data"), "certificate"));
          }
          json_decref(j_result);
        } else if (0 == o_strncmp("fido-u2f", (char *)fmt, MIN(fmt_len, o_strlen("fido-u2f"))) && (json_object_get(json_object_get(j_params, "fmt"), "fido-u2f") == json_true())) {
          j_result = check_attestation_fido_u2f(j_params, (cbor_auth_data+CREDENTIAL_ID_OFFSET), credential_id_len, cert_x, cert_x_len, cert_y, cert_y_len, att_stmt, rpid_hash, rpid_hash_len, client_data);
          if (check_result_value(j_result, G_ERROR_PARAM)) {
            json_array_extend(j_error, json_object_get(j_result, "error"));
            ret = G_ERROR_PARAM;
          } else if (!check_result_value(j_result, G_OK)) {
            ret = G_ERROR_PARAM;
            y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error check_attestation_fido_u2f");
            json_array_append_new(j_error, json_string("internal error"));
          } else {
            j_cert = json_incref(json_object_get(json_object_get(j_result, "data"), "certificate"));
          }
          json_decref(j_result);
        } else if (0 == o_strncmp("none", (char *)fmt, MIN(fmt_len, o_strlen("none"))) && (json_object_get(json_object_get(j_params, "fmt"), "none") == json_true() || json_object_get(j_params, "force-fmt-none") == json_true())) {
          if (att_stmt != NULL && cbor_isa_map(att_stmt) && cbor_map_is_definite(att_stmt) && !cbor_map_size(att_stmt)) {
            j_cert = json_string("");
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "register_new_attestation - response type 'none' has invalid format");
            json_array_append_new(j_error, json_string("response invalid"));
            ret = G_ERROR_PARAM;
          }
        } else {
          message = msprintf("Format '%.*s' is not supported by Glewlwyd WebAuthn scheme", fmt_len, fmt);
          json_array_append_new(j_error, json_string(message));
          o_free(message);
          ret = G_ERROR_PARAM;
        }
      } while (0); // This is not a loop, but a structure where you can easily cancel the rest of the process with breaks
      
      if (ret != G_OK) {
        if (json_array_size(j_error)) {
          j_return = json_pack("{sisO}", "result", ret, "error", j_error);
        } else {
          j_return = json_pack("{si}", "result", ret);
        }
      } else {
        if ((res = check_certificate(config, j_params, json_string_value(json_object_get(json_object_get(j_scheme_data, "credential"), "rawId")), json_integer_value(json_object_get(j_credential, "gswu_id")))) == G_OK) {
          j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "Credential already registered");
          status = 2;
        } else if (res == G_ERROR_UNAUTHORIZED) {
          j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "Credential unauthorized");
          status = 2;
        } else if (res != G_ERROR_NOT_FOUND) {
          j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "Internal error");
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error check_certificate");
          status = 2;
        } else {
          j_return = json_pack("{si}", "result", G_OK);
          status = 1;
        }
        counter = cbor_bs_handle[COUNTER_OFFSET+3] | (cbor_bs_handle[COUNTER_OFFSET+2] << 8) | (cbor_bs_handle[COUNTER_OFFSET+1] << 16) | (cbor_bs_handle[COUNTER_OFFSET] << 24);
        // Store credential in the database
        j_query = json_pack("{sss{siss%sOss%sOsi}s{sO}}",
                            "table", 
                            G_TABLE_WEBAUTHN_CREDENTIAL,
                            "set",
                              "gswc_status",
                              status,
                              "gswc_name",
                              fmt,
                              fmt_len,
                              "gswc_credential_id",
                              json_object_get(json_object_get(j_scheme_data, "credential"), "rawId"),
                              "gswc_public_key",
                              pubkey_export,
                              pubkey_export_len,
                              "gswc_certificate",
                              j_cert,
                              "gswc_counter",
                              counter,
                            "where",
                              "gswc_id",
                              json_object_get(j_credential, "gswc_id"));
        res = h_update(config->conn, j_query, NULL);
        json_decref(j_query);
        if (res != H_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error h_update");
        }
      }
      json_decref(j_error);
      json_decref(j_client_data);
      json_decref(j_pubkey);
      json_decref(j_cert);
      o_free(client_data);
      o_free(challenge_b64);
      o_free(challenge_hash);
      o_free(att_obj);
      o_free(credential_id_b64);
      gnutls_pubkey_deinit(g_key);
      if (item != NULL) {
        cbor_decref(&item);
      }
      if (cbor_cose != NULL) {
        cbor_decref(&cbor_cose);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error allocating resources for j_error");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "scheme_data mandatory");
  }
  return j_return;
}

/**
 * 
 */
static int check_assertion(struct config_module * config, json_t * j_params, const char * username, json_t * j_scheme_data, json_t * j_assertion) {
  int ret, res;
  unsigned char * client_data = NULL, * challenge_b64 = NULL, * auth_data = NULL, rpid_hash[32] = {0}, * flags, cdata_hash[32] = {0}, 
                  data_signed[128] = {0}, sig[128] = {0}, * counter;
  char * challenge_hash = NULL;
  const char * rpid = NULL;
  size_t client_data_len, challenge_b64_len, auth_data_len, rpid_hash_len = 32, cdata_hash_len = 32, sig_len = 128, counter_value = 0, rpid_len = 0;
  json_t * j_client_data = NULL, * j_credential = NULL, * j_query;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_datum_t pubkey_dat, data, signature;
  
  if (j_scheme_data != NULL && j_assertion != NULL) {
    do {
      ret = G_OK;
      
      if (!json_is_string(json_object_get(json_object_get(j_scheme_data, "credential"), "rawId")) || !json_string_length(json_object_get(json_object_get(j_scheme_data, "credential"), "rawId"))) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - rawId missing");
        ret = G_ERROR_PARAM;
        break;
      }
      j_credential = get_credential(config, j_params, username, json_string_value(json_object_get(json_object_get(j_scheme_data, "credential"), "rawId")));
      if (check_result_value(j_credential, G_ERROR_NOT_FOUND)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - credential ID not found");
        ret = G_ERROR_UNAUTHORIZED;
        break;
      }
      if (!json_is_string(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON")) || !json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON"))) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - clientDataJSON mandatory");
        ret = G_ERROR_PARAM;
        break;
      }
      if ((client_data = o_malloc(json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON"))+1)) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - Error allocating resources for client_data");
        ret = G_ERROR_MEMORY;
        break;
      }
      if (!o_base64_decode((const unsigned char *)json_string_value(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON")), json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON")), client_data, &client_data_len)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - Error o_base64_decode client_data");
        ret = G_ERROR_PARAM;
        break;
      }
      client_data[client_data_len] = '\0';
      j_client_data = json_loads((const char *)client_data, JSON_DECODE_ANY, NULL);
      if (j_client_data == NULL) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - Error parsing JSON client data %s", client_data);
        ret = G_ERROR_PARAM;
        break;
      }
      // Step 7
      if (0 != o_strcmp("webauthn.get", json_string_value(json_object_get(j_client_data, "type")))) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - clientDataJSON.type invalid");
        ret = G_ERROR_PARAM;
        break;
      }
      // Step 8
      if (!json_string_length(json_object_get(j_client_data, "challenge"))) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - clientDataJSON.challenge mandatory");
        ret = G_ERROR_PARAM;
        break;
      }
      if ((challenge_b64 = o_malloc(json_string_length(json_object_get(j_client_data, "challenge"))+3)) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error allocating resources for challenge_b64");
        ret = G_ERROR_MEMORY;
        break;
      }
      if (!o_base64url_2_base64((unsigned char *)json_string_value(json_object_get(j_client_data, "challenge")), json_string_length(json_object_get(j_client_data, "challenge")), challenge_b64, &challenge_b64_len)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - clientDataJSON.challenge invalid base64");
        ret = G_ERROR_PARAM;
        break;
      }
      challenge_b64[challenge_b64_len] = '\0';
      if ((challenge_hash = generate_hash(config->hash_algorithm, (const char *)challenge_b64)) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error generate_hash for challenge_b64");
        ret = G_ERROR;
        break;
      }
      if (0 != o_strcmp(challenge_hash, json_string_value(json_object_get(j_assertion, "challenge_hash")))) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - clientDataJSON.challenge invalid");
        ret = G_ERROR_PARAM;
        break;
      }
      // Step 9
      if (!json_string_length(json_object_get(j_client_data, "origin"))) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - clientDataJSON.origin mandatory");
        ret = G_ERROR_PARAM;
        break;
      }
      if (0 != o_strcmp(json_string_value(json_object_get(j_params, "rp-origin")), json_string_value(json_object_get(j_client_data, "origin")))) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - clientDataJSON.origin invalid - Client send %s, required %s", json_string_value(json_object_get(j_client_data, "origin")), json_string_value(json_object_get(j_params, "rp-origin")));
        ret = G_ERROR_PARAM;
        break;
      }
      // Step 10 ??
      
      // Step 11
      if (!json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "authenticatorData"))) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - authenticatorData mandatory");
        ret = G_ERROR_PARAM;
        break;
      }
      if ((auth_data = o_malloc(json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "authenticatorData"))+1)) == NULL) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - Error allocating resources for auth_data");
        ret = G_ERROR_PARAM;
        break;
      }
      if (!o_base64_decode((const unsigned char *)json_string_value(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "authenticatorData")), json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "authenticatorData")), auth_data, &auth_data_len)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - Error o_base64_decode auth_data");
        ret = G_ERROR_PARAM;
        break;
      }
      if (auth_data_len < 37) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - Error authenticatorData invalid");
        ret = G_ERROR_PARAM;
        break;
      }
      
      if (o_strstr(json_string_value(json_object_get(j_params, "rp-origin")), "://") != NULL) {
        rpid = o_strstr(json_string_value(json_object_get(j_params, "rp-origin")), "://")+3;
      } else {
        rpid = json_string_value(json_object_get(j_params, "rp-origin"));
      }
      if (o_strchr(rpid, ':') != NULL) {
        rpid_len = o_strchr(rpid, ':') - rpid;
      } else {
        rpid_len = o_strlen(rpid);
      }
        
      if (!generate_digest_raw(digest_SHA256, (unsigned char *)rpid, rpid_len, rpid_hash, &rpid_hash_len)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - Error generate_digest_raw for rpid_hash");
        ret = G_ERROR_PARAM;
        break;
      }
      
      if (0 != memcmp(auth_data, rpid_hash, rpid_hash_len)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - authData.rpIdHash invalid");
        ret = G_ERROR_PARAM;
        break;
      }
      flags = auth_data + FLAGS_OFFSET;
      
      // Step 12
      if (!(*flags & FLAG_USER_PRESENT)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - authData.userPresent not set");
        ret = G_ERROR_PARAM;
        break;
      }
      
      // Step 13 ignored for now
      //y_log_message(Y_LOG_LEVEL_DEBUG, "authData.userVerified: %d", !!(*flags & FLAG_USER_VERIFY));
      
      // Step 14 ignored for now (no extension)
      //y_log_message(Y_LOG_LEVEL_DEBUG, "authData.Extension: %d", !!(*flags & FLAG_ED));
      
      // Step 15
      if (!generate_digest_raw(digest_SHA256, client_data, client_data_len, cdata_hash, &cdata_hash_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - Error generate_digest_raw for cdata_hash");
        ret = G_ERROR_PARAM;
        break;
      }
      counter = auth_data + COUNTER_OFFSET;
      counter_value = counter[3] | (counter[2] << 8) | (counter[1] << 16) | (counter[0] << 24);
      
      if (gnutls_pubkey_init(&pubkey) < 0) {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - Error gnutls_pubkey_init");
        ret = G_ERROR;
        break;
      }
      pubkey_dat.data = (unsigned char *)json_string_value(json_object_get(json_object_get(j_credential, "credential"), "public_key"));
      pubkey_dat.size = json_string_length(json_object_get(json_object_get(j_credential, "credential"), "public_key"));
      if ((ret = gnutls_pubkey_import(pubkey, &pubkey_dat, GNUTLS_X509_FMT_PEM)) < 0) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - Error gnutls_pubkey_import: %d", ret);
        ret = G_ERROR;
        break;
      }
      
      if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "signature")), json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "signature")), sig, &sig_len)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - Error o_base64url_decode signature");
        ret = G_ERROR_PARAM;
        break;
      }
      
      memcpy(data_signed, auth_data, auth_data_len);
      memcpy(data_signed+auth_data_len, cdata_hash, cdata_hash_len);
      
      // Let's verify sig over data_signed
      data.data = data_signed;
      data.size = (auth_data_len+cdata_hash_len);
      
      signature.data = sig;
      signature.size = sig_len;
      
      if ((res = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_ECDSA_SHA256, 0, &data, &signature)) < 0) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - Invalid signature: %d", res);
        ret = G_ERROR_UNAUTHORIZED;
        break;
      }
      
      if ((json_integer_value(json_object_get(json_object_get(j_credential, "credential"), "counter")) || counter_value) && counter_value <= (size_t)json_integer_value(json_object_get(json_object_get(j_credential, "credential"), "counter"))) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - counter invalid");
        ret = G_ERROR_UNAUTHORIZED;
        break;
      }
    } while (0); // This is not a loop, but a structure where you can easily cancel the rest of the process with breaks
    
    if (ret == G_OK) {
      // Update assertion
      j_query = json_pack("{sss{sisi}s{sO}}",
                          "table",
                          G_TABLE_WEBAUTHN_ASSERTION,
                          "set",
                            "gswa_counter",
                            counter_value,
                            "gswa_status",
                            1,
                          "where",
                            "gswa_id",
                            json_object_get(j_assertion, "gswa_id"));
      res = h_update(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res != H_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - Error executing j_query (1)");
        config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        ret = G_ERROR_DB;
      } else {
        // Update counter in credential if necessary
        if (counter) {
          j_query = json_pack("{sss{si}s{sO}}",
                              "table",
                              G_TABLE_WEBAUTHN_CREDENTIAL,
                              "set",
                                "gswc_counter",
                                counter_value,
                              "where",
                                "gswc_id",
                                json_object_get(json_object_get(j_credential, "credential"), "gswc_id"));
          res = h_update(config->conn, j_query, NULL);
          json_decref(j_query);
          if (res != H_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - Error executing j_query (2)");
            config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
            ret = G_ERROR_DB;
          }
        }
      }
    } else if (ret == G_ERROR_PARAM) {
      j_query = json_pack("{sss{sisi}s{sO}}",
                          "table",
                          G_TABLE_WEBAUTHN_ASSERTION,
                          "set",
                            "gswa_counter",
                            counter_value,
                            "gswa_status",
                            2,
                          "where",
                            "gswa_id",
                            json_object_get(j_assertion, "gswa_id"));
      res = h_update(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res != H_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - Error executing j_query (3)");
        config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        ret = G_ERROR_DB;
      }
    } else {
      j_query = json_pack("{sss{sisi}s{sO}}",
                          "table",
                          G_TABLE_WEBAUTHN_ASSERTION,
                          "set",
                            "gswa_counter",
                            counter_value,
                            "gswa_status",
                            3,
                          "where",
                            "gswa_id",
                            json_object_get(j_assertion, "gswa_id"));
      res = h_update(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res != H_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - Error executing j_query (4)");
        config->glewlwyd_module_callback_metrics_increment_counter(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        ret = G_ERROR_DB;
      }
    }
    o_free(client_data);
    o_free(challenge_b64);
    o_free(challenge_hash);
    o_free(auth_data);
    json_decref(j_client_data);
    json_decref(j_credential);
    gnutls_pubkey_deinit(pubkey);
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

/**
 * Generates a fake credential based on the seed
 * the fake credential has the following form:
 * {
 *   credential_id: string, base64 encoding of 64 a bytes string
 *   name: string
 *   created_at: number, epoch time
 *   status: string, always "registered"
 * }
 */
static json_t * generate_credential_fake_from_seed(const char * seed) {
  unsigned char credential_id[64] = {0}, credential_id_b64[129], created_at[32], name_hash[32];
  char * seed_credential_id, * seed_name, * seed_created_at, name[32];
  time_t created_at_t;
  size_t credential_id_len = 64, credential_id_b64_len, name_hash_len = 32, created_at_len = 32;
  json_t * j_return;
  
  if ((seed_credential_id = msprintf("%s-credential_id", seed)) != NULL) {
    if (generate_digest_raw(digest_SHA512, (unsigned char *)seed_credential_id, o_strlen(seed_credential_id), credential_id, &credential_id_len)) {
      if (o_base64_encode(credential_id, credential_id_len, credential_id_b64, &credential_id_b64_len)) {
        if ((seed_name = msprintf("%s-name", seed)) != NULL) {
          if (generate_digest_raw(digest_SHA256, (unsigned char *)seed_name, o_strlen(seed_name), name_hash, &name_hash_len)) {
            if (name_hash[0]%2) {
              o_strcpy(name, "fido-u2f");
            } else {
              o_strcpy(name, "android-safetynet");
            }
            if ((seed_created_at = msprintf("%s-created_at", seed)) != NULL) {
              if (generate_digest_raw(digest_SHA256, (unsigned char *)seed_created_at, o_strlen(seed_created_at), created_at, &created_at_len)) {
                time(&created_at_t);
                created_at_t -= created_at[0] - (created_at[1] << 8);
                j_return = json_pack("{sis{sssssiss}}", 
                                     "result", 
                                     G_OK, 
                                     "credential", 
                                      "credential_id", 
                                      credential_id_b64,
                                      "name", 
                                      name,
                                      "created_at",
                                      created_at_t,
                                      "status",
                                      "registered");
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_from_seed - Error generate_digest_raw for seed_created_at");
                j_return = json_pack("{si}", "result", G_ERROR);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_from_seed - Error allocating resources for seed_created_at");
              j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
            }
            o_free(seed_created_at);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_from_seed - Error generate_digest_raw for seed_name");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_from_seed - Error allocating resources for seed_name");
          j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
        }
        o_free(seed_name);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_from_seed - Error o_base64_encode for seed_credential_id");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_from_seed - Error generate_digest_raw for seed_credential_id");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_from_seed - Error allocating resources for seed_credential_id");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  o_free(seed_credential_id);
  return j_return;
}

/**
 * Generates 1 to 3 random credentials using the seed and the username
 */
static json_t * generate_credential_fake_list(json_t * j_params, const char * username) {
  json_t * j_credential, * j_credential_sub, * j_return;
  char * seed;
  unsigned char seed_hash[32] = {0};
  size_t seed_hash_len = 32;
  unsigned int i;
  
  if ((seed = msprintf("%s%s0", username, json_string_value(json_object_get(j_params, "seed")))) != NULL) {
    j_credential = generate_credential_fake_from_seed(seed);
    if (check_result_value(j_credential, G_OK)) {
      j_return = json_pack("{sis[O]}", "result", G_OK, "credential", json_object_get(j_credential, "credential"));
      if (j_return != NULL) {
        if (generate_digest_raw(digest_SHA256, (unsigned char *)seed, o_strlen(seed), seed_hash, &seed_hash_len)) {
          for (i=0; i<seed_hash[0]%3; i++) {
            seed[o_strlen(seed)-1]++;
            j_credential_sub = generate_credential_fake_from_seed(seed);
            if (check_result_value(j_credential, G_OK)) {
              json_array_append(json_object_get(j_return, "credential"), json_object_get(j_credential_sub, "credential"));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_list - Error generate_credential_fake_from_seed at index %u", i);
            }
            json_decref(j_credential_sub);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_list - Error generate_digest_raw");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_list - Error allocating resources for j_return");
        j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_list - Error generate_credential_fake_from_seed");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_credential);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_list - Error allocating resources for seed");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  o_free(seed);
  return j_return;
}

/**
 * Generates a fake user_id based on the username provided and the seed
 */
static int generate_fake_user_id(json_t * j_params, const char * username, unsigned char * user_id) {
  char * seed;
  unsigned char seed_hash[32];
  size_t seed_hash_len = 32, seed_hash_b64_len;
  int ret;
  
  if ((seed = msprintf("%s%s-user_id", username, json_string_value(json_object_get(j_params, "seed")))) != NULL) {
    if (generate_digest_raw(digest_SHA256, (unsigned char *)seed, o_strlen(seed), seed_hash, &seed_hash_len)) {
      if (o_base64_encode(seed_hash, seed_hash_len, user_id, &seed_hash_b64_len)) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_from_seed - Error o_base64_encode");
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_from_seed - Error generate_digest_raw");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_credential_fake_from_seed - Error allocating resources for seed");
    ret = G_ERROR_MEMORY;
  }
  o_free(seed);
  return ret;
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
  return json_pack("{si ss ss ss }",
                   "result", G_OK,
                   "name", "webauthn",
                   "display_name", "WebAuthn",
                   "description", "WebAuthn scheme module");
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
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, G_ERROR_PARAM on input parameters error, another value on error)
 *                  error: array of strings containg the list of input errors, mandatory on result G_ERROR_PARAM, ignored otherwise
 *                }
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
  json_t * j_result = is_scheme_parameters_valid(j_parameters), * j_element = NULL, * j_return;
  size_t index = 0;
  char * message;
  
  if (check_result_value(j_result, G_OK)) {
    *cls = json_pack("{sO sO sO sO sI sI sO ss so sO sO sO sO sO ss s[]}",
                     "challenge-length", json_object_get(j_parameters, "challenge-length"),
                     "rp-origin", json_object_get(j_parameters, "rp-origin"),
                     "credential-expiration", json_object_get(j_parameters, "credential-expiration"),
                     "credential-assertion", json_object_get(j_parameters, "credential-assertion"),
                     "ctsProfileMatch", json_object_get(j_parameters, "ctsProfileMatch")!=NULL?json_integer_value(json_object_get(j_parameters, "ctsProfileMatch")):-1,
                     "basicIntegrity", json_object_get(j_parameters, "basicIntegrity")!=NULL?json_integer_value(json_object_get(j_parameters, "basicIntegrity")):-1,
                     "session-mandatory", json_object_get(j_parameters, "session-mandatory")!=NULL?json_object_get(j_parameters, "session-mandatory"):json_true(),
                     "seed", !json_string_length(json_object_get(j_parameters, "seed"))?"":json_string_value(json_object_get(j_parameters, "seed")),
                     "fmt", json_object_get(j_parameters, "fmt")!=NULL?json_deep_copy(json_object_get(j_parameters, "fmt")):json_pack("{sosososososo}", "packed", json_true(), "tpm", json_true(), "android-key", json_true(), "android-safetynet", json_true(), "fido-u2f", json_true(), "none", json_true()),
                     "force-fmt-none", json_object_get(j_parameters, "force-fmt-none")!=NULL?json_object_get(j_parameters, "force-fmt-none"):json_false(),
                     "google-root-ca-r2", json_string_length(json_object_get(j_parameters, "google-root-ca-r2"))?json_object_get(j_parameters, "google-root-ca-r2"):json_null(),
                     "google-root-ca-r2-content", json_object_get(j_parameters, "google-root-ca-r2-content")!=NULL?json_object_get(j_parameters, "google-root-ca-r2-content"):json_null(),
                     "root-ca-list", json_array_size(json_object_get(j_parameters, "root-ca-list"))?json_object_get(j_parameters, "root-ca-list"):json_null(),
                     "root-ca-array", json_object_get(j_parameters, "root-ca-array")!=NULL?json_object_get(j_parameters, "root-ca-array"):json_null(),
                     "mod_name", mod_name,
                     "pubKey-cred-params");
    json_array_foreach(json_object_get(j_parameters, "pubKey-cred-params"), index, j_element) {
      json_array_append_new(json_object_get((json_t *)*cls, "pubKey-cred-params"), json_pack("{sssO}", "type", "public-key", "alg", j_element));
    }
    j_return = json_pack("{si}", "result", G_OK);
  } else if (check_result_value(j_result, G_ERROR_PARAM)) {
    message = json_dumps(json_object_get(j_result, "error"), JSON_COMPACT);
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init webauthn - Error input parameters: %s", message);
    o_free(message);
    j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", json_object_get(j_result, "error"));
  } else {
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
  json_decref((json_t *)cls);
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
  json_t * j_user_id, * j_credential;
  int ret;
  
  j_user_id = get_user_id_from_username(config, (json_t *)cls, username, 0);
  if (check_result_value(j_user_id, G_OK)) {
    j_credential = get_credential_list(config, (json_t *)cls, username, 1);
    if (check_result_value(j_credential, G_OK)) {
      ret = GLEWLWYD_IS_REGISTERED;
    } else if (check_result_value(j_credential, G_ERROR_NOT_FOUND)) {
      ret = GLEWLWYD_IS_AVAILABLE;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_can_use webauthn - Error get_credential_list");
      ret = GLEWLWYD_IS_NOT_AVAILABLE;
    }
    json_decref(j_credential);
  } else if (check_result_value(j_user_id, G_ERROR_NOT_FOUND)) {
    ret = GLEWLWYD_IS_AVAILABLE;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_can_use webauthn - Error get_user_id_from_username");
    ret = GLEWLWYD_IS_NOT_AVAILABLE;
  }
  json_decref(j_user_id);
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
  UNUSED(config);
  UNUSED(http_request);
  json_t * j_return, * j_result, * j_credential, * j_user_id, * j_assertion;
  int res;

  if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "register")), "new-credential")) {
    j_user_id = get_user_id_from_username(config, (json_t *)cls, username, 1);
    if (check_result_value(j_user_id, G_OK)) {
      j_credential = generate_new_credential(config, (json_t *)cls, username);
      if (check_result_value(j_credential, G_OK)) {
        j_return = json_pack("{sis{sOsOsOsss{sOss}sO}}",
                              "result", G_OK, 
                              "response", 
                                "session", json_object_get(json_object_get(j_credential, "credential"), "session"), 
                                "challenge", json_object_get(json_object_get(j_credential, "credential"), "challenge"), 
                                "pubKey-cred-params", json_object_get((json_t *)cls, "pubKey-cred-params"),
                                "attestation-required", json_object_get((json_t *)cls, "force-fmt-none")==json_true()?"none":"direct",
                                "user",
                                  "id", json_object_get(j_user_id, "user_id"),
                                  "name", username,
                                "rpId", json_object_get((json_t *)cls, "rp-origin")
                             );
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error generate_new_credential");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_credential);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error get_user_id_from_username");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_user_id);
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "register")), "register-credential")) {
    j_credential = get_credential_from_session(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "session")));
    if (check_result_value(j_credential, G_OK)) {
      j_result = register_new_attestation(config, (json_t *)cls, j_scheme_data, json_object_get(j_credential, "credential"));
      if (check_result_value(j_result, G_OK)) {
        j_return = json_pack("{si}", "result", G_OK);
      } else if (check_result_value(j_result, G_ERROR_UNAUTHORIZED)) {
        j_return = json_pack("{sisO}", "result", G_ERROR_UNAUTHORIZED, "response", json_object_get(j_result, "error"));
      } else if (check_result_value(j_result, G_ERROR_PARAM)) {
        j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "response", json_object_get(j_result, "error"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error register_new_attestation");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_result);
    } else if (check_result_value(j_credential, G_ERROR_NOT_FOUND)) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else if (check_result_value(j_credential, G_ERROR_PARAM)) {
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error get_credential_from_session");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_credential);
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "register")), "remove-credential") && json_string_length(json_object_get(j_scheme_data, "credential_id"))) {
    j_credential = get_credential(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "credential_id")));
    if (check_result_value(j_credential, G_OK)) {
      if ((res = update_credential(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "credential_id")), 4)) == G_OK) {
        j_return = json_pack("{si}", "result", G_OK);
      } else if (res == G_ERROR_PARAM) {
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error update_credential");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else if (check_result_value(j_credential, G_ERROR_NOT_FOUND)) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error get_credential");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_credential);
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "register")), "disable-credential") && json_string_length(json_object_get(j_scheme_data, "credential_id"))) {
    j_credential = get_credential(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "credential_id")));
    if (check_result_value(j_credential, G_OK)) {
      if ((res = update_credential(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "credential_id")), 3)) == G_OK) {
        j_return = json_pack("{si}", "result", G_OK);
      } else if (res == G_ERROR_PARAM) {
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error update_credential");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else if (check_result_value(j_credential, G_ERROR_NOT_FOUND)) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error get_credential");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_credential);
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "register")), "enable-credential") && json_string_length(json_object_get(j_scheme_data, "credential_id"))) {
    j_credential = get_credential(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "credential_id")));
    if (check_result_value(j_credential, G_OK)) {
      if ((res = update_credential(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "credential_id")), 1)) == G_OK) {
        j_return = json_pack("{si}", "result", G_OK);
      } else if (res == G_ERROR_PARAM) {
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error update_credential");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else if (check_result_value(j_credential, G_ERROR_NOT_FOUND)) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error get_credential");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_credential);
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "register")), "edit-credential") && json_string_length(json_object_get(j_scheme_data, "credential_id")) && json_string_length(json_object_get(j_scheme_data, "name"))) {
    j_credential = get_credential(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "credential_id")));
    if (check_result_value(j_credential, G_OK)) {
      if ((res = update_credential_name(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "credential_id")), json_string_value(json_object_get(j_scheme_data, "name")))) == G_OK) {
        j_return = json_pack("{si}", "result", G_OK);
      } else if (res == G_ERROR_PARAM) {
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error update_credential_name");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else if (check_result_value(j_credential, G_ERROR_NOT_FOUND)) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error get_credential");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_credential);
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "register")), "trigger-assertion")) {
    j_user_id = get_user_id_from_username(config, (json_t *)cls, username, 0);
    if (check_result_value(j_user_id, G_OK)) {
      j_credential = get_credential_list(config, (json_t *)cls, username, 1);
      if (check_result_value(j_credential, G_OK)) {
        j_assertion = generate_new_assertion(config, (json_t *)cls, username, 1);
        if (check_result_value(j_assertion, G_OK)) {
          j_return = json_pack("{sis{sOsOsOs{sOss}sO}}", 
                              "result", G_OK, 
                              "response", 
                                "allowCredentials", json_object_get(j_credential, "credential"), 
                                "session", json_object_get(json_object_get(j_assertion, "assertion"), "session"), 
                                "challenge", json_object_get(json_object_get(j_assertion, "assertion"), "challenge"),
                                "user",
                                  "id", json_object_get(j_user_id, "user_id"),
                                  "name", username,
                                "rpId", json_object_get((json_t *)cls, "rp-origin")
                              );
        } else if (check_result_value(j_assertion, G_ERROR_UNAUTHORIZED)) {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger webauthn - Error register_new_assertion");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_assertion);
      } else if (check_result_value(j_credential, G_ERROR_NOT_FOUND)) {
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger webauthn - Error get_credential_list");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_credential);
    } else if (check_result_value(j_user_id, G_ERROR_NOT_FOUND)) {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error get_user_id_from_username");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_user_id);
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "register")), "validate-assertion")) {
    j_user_id = get_user_id_from_username(config, (json_t *)cls, username, 0);
    if (check_result_value(j_user_id, G_OK)) {
      j_assertion = get_assertion_from_session(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "session")), 1);
      if (check_result_value(j_assertion, G_OK)) {
        if ((res = check_assertion(config, (json_t *)cls, username, j_scheme_data, json_object_get(j_assertion, "assertion"))) == G_OK) {
          j_return = json_pack("{si}", "result", G_OK);
        } else if (res == G_ERROR_UNAUTHORIZED || res == G_ERROR_PARAM) {
          j_return = json_pack("{si}", "result", res);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error check_assertion");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else if (check_result_value(j_assertion, G_ERROR_NOT_FOUND)) {
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error get_credential");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_assertion);
    } else if (check_result_value(j_user_id, G_ERROR_NOT_FOUND)) {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate webauthn - Error get_user_id_from_username");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_user_id);
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
  json_t * j_return, * j_user_id, * j_credential_list;

  j_user_id = get_user_id_from_username(config, (json_t *)cls, username, 1);
  if (check_result_value(j_user_id, G_OK)) {
    j_credential_list = get_credential_list(config, (json_t *)cls, username, 0);
    if (check_result_value(j_credential_list, G_OK)) {
      j_return = json_pack("{sisO}", "result", G_OK, "response", json_object_get(j_credential_list, "credential"));
    } else if (check_result_value(j_credential_list, G_ERROR_NOT_FOUND)) {
      j_return = json_pack("{sis[]}", "result", G_OK, "response");
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register_get webauthn - Error get_credential_list");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_credential_list);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register_get webauthn - Error get_user_id_from_username");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_user_id);
  
  return j_return;
}

/**
 * 
 * user_auth_scheme_module_deregister
 * 
 * Deregister the scheme for a user
 * Ex: remove certificates, TOTP values, etc.
 * 
 * @return value: G_OK on success, even if no data has been removed
 *                G_ERROR on another error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: username to identify the user
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_deregister(struct config_module * config, const char * username, void * cls) {
  json_t * j_user_id, * j_credential_list, * j_credential, * j_element = NULL;
  size_t index = 0;
  int ret;

  j_user_id = get_user_id_from_username(config, (json_t *)cls, username, 1);
  if (check_result_value(j_user_id, G_OK)) {
    j_credential_list = get_credential_list(config, (json_t *)cls, username, 0);
    if (check_result_value(j_credential_list, G_OK)) {
      json_array_foreach(json_object_get(j_credential_list, "credential"), index, j_element) {
        j_credential = get_credential(config, (json_t *)cls, username, json_string_value(json_object_get(j_element, "credential_id")));
        if (check_result_value(j_credential, G_OK)) {
          if (update_credential(config, (json_t *)cls, username, json_string_value(json_object_get(j_element, "credential_id")), 4) != G_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_deregister webauthn - Error update_credential");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_deregister webauthn - Error get_credential");
        }
        json_decref(j_credential);
      }
      ret = G_OK;
    } else if (check_result_value(j_credential_list, G_ERROR_NOT_FOUND)) {
      ret = G_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_deregister webauthn - Error get_credential_list");
      ret = G_ERROR;
    }
    json_decref(j_credential_list);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_deregister webauthn - Error get_user_id_from_username");
    ret = G_ERROR;
  }
  json_decref(j_user_id);
  
  return ret;
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
  UNUSED(j_scheme_trigger);
  json_t * j_return = NULL, * j_session = config->glewlwyd_module_callback_check_user_session(config, http_request, username), * j_credential, * j_assertion, * j_user_id, * j_credential_fake;
  unsigned char user_id_fake[64];
  
  if (check_result_value(j_session, G_OK) || json_object_get((json_t *)cls, "session-mandatory") == json_false()) {
    j_credential_fake = generate_credential_fake_list((json_t *)cls, username);
    if (check_result_value(j_credential_fake, G_OK)) {
      j_user_id = get_user_id_from_username(config, (json_t *)cls, username, 0);
      if (check_result_value(j_user_id, G_OK)) {
        j_credential = get_credential_list(config, (json_t *)cls, username, 1);
        if (check_result_value(j_credential, G_OK)) {
          j_assertion = generate_new_assertion(config, (json_t *)cls, username, 0);
          if (check_result_value(j_assertion, G_OK)) {
            j_return = json_pack("{sis{sOsOsOs{sOss}sOsssi}}", 
                                "result", G_OK, 
                                "response", 
                                  "allowCredentials", json_object_get(j_credential, "credential"), 
                                  "session", json_object_get(json_object_get(j_assertion, "assertion"), "session"), 
                                  "challenge", json_object_get(json_object_get(j_assertion, "assertion"), "challenge"),
                                  "user",
                                    "id", json_object_get(j_user_id, "user_id"),
                                    "name", username,
                                  "rpId", json_object_get((json_t *)cls, "rp-origin"),
                                  "attestation-required", json_object_get((json_t *)cls, "force-fmt-none")==json_true()?"none":"direct",
                                  "timeout", 60000
                                );
            if (json_object_get((json_t *)cls, "session-mandatory") == json_false()) {
              json_array_extend(json_object_get(json_object_get(j_return, "response"), "allowCredentials"), json_object_get(j_credential_fake, "credential"));
            }
          } else if (check_result_value(j_assertion, G_ERROR_UNAUTHORIZED)) {
            j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger webauthn - Error register_new_assertion");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          json_decref(j_assertion);
        } else if (check_result_value(j_credential, G_ERROR_NOT_FOUND)) {
          if (json_object_get((json_t *)cls, "session-mandatory") == json_false()) {
            j_assertion = generate_new_assertion(config, (json_t *)cls, username, 2);
            if (check_result_value(j_assertion, G_OK)) {
              j_return = json_pack("{sis{sOsOsOs{sOss}sO}}", 
                                  "result", G_OK, 
                                  "response", 
                                    "allowCredentials", json_object_get(j_credential_fake, "credential"), 
                                    "session", json_object_get(json_object_get(j_assertion, "assertion"), "session"), 
                                    "challenge", json_object_get(json_object_get(j_assertion, "assertion"), "challenge"),
                                    "user",
                                      "id", json_object_get(j_user_id, "user_id"),
                                      "name", username,
                                    "rpId", json_object_get((json_t *)cls, "rp-origin")
                                  );
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger webauthn - Error register_new_assertion");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
            json_decref(j_assertion);
          } else {
            j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger webauthn - Error get_credential_list");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_credential);
      } else if (check_result_value(j_user_id, G_ERROR_NOT_FOUND)) {
        if (json_object_get((json_t *)cls, "session-mandatory") == json_false()) {
          if (generate_fake_user_id((json_t *)cls, username, user_id_fake) == G_OK) {
            j_assertion = generate_new_assertion(config, (json_t *)cls, username, 2);
            if (check_result_value(j_assertion, G_OK)) {
              j_return = json_pack("{sis{sOsOsOs{ssss}sO}}", 
                                  "result", G_OK, 
                                  "response", 
                                    "allowCredentials", json_object_get(j_credential_fake, "credential"), 
                                    "session", json_object_get(json_object_get(j_assertion, "assertion"), "session"), 
                                    "challenge", json_object_get(json_object_get(j_assertion, "assertion"), "challenge"),
                                    "user",
                                      "id", user_id_fake,
                                      "name", username,
                                    "rpId", json_object_get((json_t *)cls, "rp-origin")
                                  );
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger webauthn - Error register_new_assertion");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
            json_decref(j_assertion);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error generate_fake_user_id");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error get_user_id_from_username");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_user_id);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger webauthn - Error generate_credential_fake");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_credential_fake);
  } else if (check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger webauthn - Error glewlwyd_module_callback_check_user_session");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_session);
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
  UNUSED(http_request);
  int ret, res;
  json_t * j_user_id, * j_assertion;

  j_user_id = get_user_id_from_username(config, (json_t *)cls, username, 0);
  if (check_result_value(j_user_id, G_OK)) {
    j_assertion = get_assertion_from_session(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "session")), 0);
    if (check_result_value(j_assertion, G_OK)) {
      if ((res = check_assertion(config, (json_t *)cls, username, j_scheme_data, json_object_get(j_assertion, "assertion"))) == G_OK) {
        ret = G_OK;
      } else if (res == G_ERROR_UNAUTHORIZED) {
        ret = G_ERROR_UNAUTHORIZED;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate webauthn - Error check_assertion");
        ret = G_ERROR;
      }
    } else if (check_result_value(j_assertion, G_ERROR_NOT_FOUND)) {
      ret = G_ERROR_UNAUTHORIZED;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error get_credential");
      ret = G_ERROR;
    }
    json_decref(j_assertion);
  } else if (check_result_value(j_user_id, G_ERROR_NOT_FOUND)) {
    ret = G_ERROR_UNAUTHORIZED;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate webauthn - Error get_user_id_from_username");
    ret = G_ERROR;
  }
  json_decref(j_user_id);
  
  return ret;
}

/**
 * 
 * user_auth_scheme_module_identify
 * 
 * Identify the user using the scheme without the username to be previously given
 * This functionality isn't available for all schemes, because the scheme authentification
 * must be triggered without username and the authentication result must contain the username
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  username: string value of the user identified - if the function is called within /auth
 *                  response: JSON object, optional - if the function is called within /auth/scheme/trigger
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter j_scheme_data: data sent to validate the scheme for the user
 *                           in JSON format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
json_t * user_auth_scheme_module_identify(struct config_module * config, const struct _u_request * http_request, json_t * j_scheme_data, void * cls) {
  UNUSED(config);
  UNUSED(http_request);
  UNUSED(j_scheme_data);
  UNUSED(cls);
  return json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
}

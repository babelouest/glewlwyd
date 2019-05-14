/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Webauthn scheme module
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

#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <jansson.h>
#include <cbor.h>
#include <yder.h>
#include <orcania.h>
#include "../glewlwyd-common.h"

#define G_TABLE_WEBAUTHN_USER "gs_webauthn_user"
#define G_TABLE_WEBAUTHN_CREDENTIAL "gs_webauthn_credential"

#define SESSION_LENGTH 32
#define USER_ID_LENGTH 32

static json_t * is_scheme_parameters_valid(json_t * j_params) {
  json_t * j_return, * j_error, * j_element;
  size_t index;
  json_int_t pubkey;
  
  if (json_is_object(j_params)) {
    j_error = json_array();
    if (j_error != NULL) {
      if (json_integer_value(json_object_get(j_params, "challenge-length")) <= 0) {
        json_array_append_new(j_error, json_string("challenge-length is mandatory and must be a positive integer"));
      }
      if (!json_string_length(json_object_get(j_params, "rp-origin"))) {
        json_array_append_new(j_error, json_string("rp-origin is mandatory and must be a non empty string"));
      }
      if (!json_array_size(json_object_get(j_params, "pubKey-cred-params"))) {
        json_array_append_new(j_error, json_string("pubKey-cred-params is mandatory and must be a non empty JSON array"));
      } else {
        json_array_foreach(json_object_get(j_params, "pubKey-cred-params"), index, j_element) {
          pubkey = json_integer_value(j_element);
          if (pubkey != -7 && pubkey != -35 && pubkey != -36) {
            json_array_append_new(j_error, json_string("pubKey-cred-params elements values available are -7, -35, -36"));
          }
        }
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
static json_t * get_user_id_from_username(struct config_module * config, const char * username) {
  json_t * j_query, * j_result, * j_return;
  int res;
  char * username_escaped, * username_clause;
  unsigned char new_user_id[USER_ID_LENGTH] = {0}, new_user_id_b64[USER_ID_LENGTH*2] = {0};
  size_t new_user_id_b64_len;
  
  username_escaped = h_escape_string(config->conn, username);
  username_clause = msprintf(" = UPPER('%s')", username_escaped);
  j_query = json_pack("{sss[s]s{s{ssss}}}",
                      "table",
                      G_TABLE_WEBAUTHN_USER,
                      "columns",
                        "gswu_user_id AS user_id",
                      "where",
                        "UPPER(gswu_username)",
                          "operator",
                          "raw",
                          "value",
                          username_clause);
  o_free(username_clause);
  o_free(username_escaped);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      j_return = json_pack("{siss}", "result", G_OK, "user_id", json_string_value(json_object_get(json_array_get(j_result, 0), "user_id")));
    } else {
      // Generates a new user_id, and stores it in the database
      gnutls_rnd(GNUTLS_RND_NONCE, new_user_id, USER_ID_LENGTH);
      if (o_base64_encode(new_user_id, USER_ID_LENGTH, new_user_id_b64, &new_user_id_b64_len)) {
        j_query = json_pack("{sss{ssss}}",
                            "table",
                            G_TABLE_WEBAUTHN_USER,
                            "values",
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
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_id_from_username - Error o_base64_encode");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_id_from_username - Error executing j_query select");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static json_t * generate_new_credential(struct config_module * config, json_t * j_params, const char * username) {
  json_t * j_query, * j_return;
  char * username_escaped, * username_clause, * challenge_hash;
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
        username_escaped = h_escape_string(config->conn, username);
        username_clause = msprintf(" (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER('%s'))", username_escaped);
        // Disable all credentials with status 0 (new) of the same user
        j_query = json_pack("{sss{si}s{s{ssss+}si}}",
                            "table",
                            G_TABLE_WEBAUTHN_CREDENTIAL,
                            "set",
                              "gswc_status",
                              4,
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
            y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_session - Error executing j_query insert");
            j_return = json_pack("{si}", "result", G_ERROR_DB);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_session - Error executing j_query update");
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        o_free(username_clause);
        o_free(username_escaped);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_session - Error generate_hash session");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      o_free(session_hash);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_session - Error generate_hash challenge");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(challenge_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_session - Error o_base64_encode challenge");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

static json_t * get_credentials_from_session(struct config_module * config, const char * username, const char * session) {
  json_t * j_query, * j_result, * j_return;
  char * username_escaped, * username_clause;
  char * session_hash = generate_hash(config->hash_algorithm, session);
  int res;
  
  if (session_hash != NULL) {
    username_escaped = h_escape_string(config->conn, username);
    username_clause = msprintf(" = (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER('%s'))", username_escaped);
    j_query = json_pack("{sss[ssssss]s{sss{ssss}si}}",
                        "table",
                        G_TABLE_WEBAUTHN_CREDENTIAL,
                        "columns",
                          "gswc_id",
                          "gswc_session_hash AS session_hash",
                          "gswc_challenge_hash AS challenge_hash",
                          "gswc_credential_id AS credential_id",
                          "gswc_public_key AS public_key",
                          "gswc_status",
                        "where",
                          "gswc_session_hash",
                          session_hash,
                          "gswu_id",
                            "operator",
                            "raw",
                            "value",
                            username_clause,
                          "gswc_status",
                          0);
    o_free(username_clause);
    o_free(username_escaped);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        switch (json_integer_value(json_object_get(json_array_get(j_result, 0), "gswc_status"))) {
          case 0:
            json_object_set_new(json_array_get(j_result, 0), "status", json_string("new"));
            break;
          case 1:
            json_object_set_new(json_array_get(j_result, 0), "status", json_string("registered"));
            break;
          case 2:
            json_object_set_new(json_array_get(j_result, 0), "status", json_string("error"));
            break;
          case 3:
            json_object_set_new(json_array_get(j_result, 0), "status", json_string("closed"));
            break;
          default:
            y_log_message(Y_LOG_LEVEL_ERROR, "get_credentials - Error status unknown");
            break;
        }
        json_object_del(json_array_get(j_result, 0), "gswc_status");
        j_return = json_pack("{sisO}", "result", G_OK, "credentials", json_array_get(j_result, 0));
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_credentials - Error executing j_query");
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_credentials - Error generate_hash");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  o_free(session_hash);
  return j_return;
}

/**
 * 
 * Validate the attStmt object under the fido-u2f format
 * https://w3c.github.io/webauthn/#fido-u2f-attestation
 * Really want you in my world
 * 
 */
static json_t * check_attestation_fido_u2f(struct config_module * config, json_t * j_params, cbor_item_t * auth_data, cbor_item_t * att_stmt, unsigned char * rpid_hash, size_t rpid_hash_len, const char * clientDataJSON) {
  json_t * j_error = json_array(), * j_return;
  cbor_item_t * key, * x5c, * sig = NULL, * att_cert;
  int i, ret, has_x = 0, has_y = 0;
  char * message;
  gnutls_pubkey_t pubkey;
  gnutls_x509_crt_t cert;
  gnutls_datum_t cert_dat;
  unsigned char * cred_pub_key, data_signed[1024], client_data_hash[32], * cbor_auth_data, cert_x[32], cert_y[32];
  size_t cred_pub_key_len, data_signed_offset = 0, client_data_hash_len, cbor_auth_data_len, credential_id_len;
  struct cbor_load_result cbor_result;
  cbor_item_t * cbor_cose_key, * cbor_key, * cbor_value;
  
  memset(data_signed, 0, 1024);
  if (j_error != NULL) {
    if (!gnutls_pubkey_init(&pubkey) && !gnutls_x509_crt_init(&cert)) {
      // Step 1
      if (!cbor_isa_map(att_stmt) || cbor_map_size(att_stmt) != 2) {
        json_array_append_new(j_error, json_string("CBOR map value 'attStmt' invalid format"));
      } else {
        for (i=0; i<2; i++) {
          key = cbor_map_handle(att_stmt)[i].key;
          if (cbor_isa_string(key)) {
            if (0 == o_strncmp((const char *)cbor_string_handle(key), "x5c", MIN(o_strlen("x5c"), cbor_string_length(key)))) {
              x5c = cbor_map_handle(att_stmt)[i].value;
              // Step 2
              if (!cbor_isa_array(x5c) || cbor_array_size(x5c) != 1) {
                json_array_append_new(j_error, json_string("CBOR map value 'x5c' invalid format"));
              } else {
                att_cert = cbor_array_get(x5c, 0);
                cert_dat.data = cbor_bytestring_handle(att_cert);
                cert_dat.size = cbor_bytestring_length(att_cert);
                if (!(ret = gnutls_x509_crt_import(cert, &cert_dat, GNUTLS_X509_FMT_DER))) {
                  if ((ret = gnutls_pubkey_import_x509(pubkey, cert, 0))) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "Error gnutls_pubkey_import_x509 %d", ret);
                  }
                  if (generate_digest_raw(digest_SHA256, (unsigned char *)clientDataJSON, o_strlen(clientDataJSON), client_data_hash, &client_data_hash_len)) {
                    // Extract credential ID
                    cbor_auth_data_len = cbor_bytestring_length(auth_data);
                    cbor_auth_data = cbor_bytestring_handle(auth_data);
                    data_signed[0] = 0x0;
                    data_signed_offset = 1;
                    memcpy(data_signed+data_signed_offset, rpid_hash, rpid_hash_len);
                    data_signed_offset += rpid_hash_len;
                    memcpy(data_signed+data_signed_offset, client_data_hash, client_data_hash_len);
                    data_signed_offset+=client_data_hash_len;
                    credential_id_len = cbor_auth_data[54] | (cbor_auth_data[53] << 8);
                    memcpy(data_signed+data_signed_offset, cbor_auth_data+55, credential_id_len);
                    data_signed_offset+=credential_id_len;
                    // A Cose key is a CBOR data embedded ina CBOR data
                    cred_pub_key = cbor_auth_data+55+credential_id_len;
                    cred_pub_key_len = cbor_auth_data_len-55-credential_id_len;
                    cbor_cose_key = cbor_load(cred_pub_key, cred_pub_key_len, &cbor_result);
                    if (cbor_result.error.code == CBOR_ERR_NONE) {
                      if (cbor_isa_map(cbor_cose_key)) {
                        for (i=0; i<cbor_map_size(cbor_cose_key); i++) {
                          cbor_key = cbor_map_handle(cbor_cose_key)[i].key;
                          cbor_value = cbor_map_handle(cbor_cose_key)[i].value;
                          if (cbor_isa_negint(cbor_key) && cbor_get_int(cbor_key) == 1 && cbor_isa_bytestring(cbor_value) && cbor_bytestring_length(cbor_value) == 32) {
                            has_x = 1;
                            memcpy(cert_x, cbor_bytestring_handle(cbor_value), 32);
                          } else if (cbor_isa_negint(cbor_key) && cbor_get_int(cbor_key) == 2 && cbor_isa_bytestring(cbor_value) && cbor_bytestring_length(cbor_value) == 32) {
                            has_y = 1;
                            memcpy(cert_y, cbor_bytestring_handle(cbor_value), 32);
                          }
                        }
                        if (has_x && has_y) {
                          data_signed[data_signed_offset] = 0x04;
                          data_signed_offset++;
                          memcpy(data_signed+data_signed_offset, cert_x, 32);
                          data_signed_offset+=32;
                          memcpy(data_signed+data_signed_offset, cert_y, 32);
                          data_signed_offset+=32;
                          y_log_message(Y_LOG_LEVEL_DEBUG, "data_signed is %zu long", data_signed_offset);
                        } else {
                          json_array_append_new(j_error, json_string("Internal error"));
                          y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error has_x %d && has_y %d", has_x, has_y);
                        }
                      } else {
                        json_array_append_new(j_error, json_string("Internal error"));
                        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error cbor_cose_key not a map");
                      }
                    } else {
                      json_array_append_new(j_error, json_string("Internal error"));
                      y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error cbor_load cbor_cose_key");
                    }
                    cbor_decref(&cbor_cose_key);
                  } else {
                    json_array_append_new(j_error, json_string("Internal error"));
                    y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error generate_digest_raw clientDataJSON");
                  }
                } else {
                  json_array_append_new(j_error, json_string("Error importing x509 certificate"));
                  y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error gnutls_pcert_import_x509_raw: %d", ret);
                }
              }
            } else if (0 == o_strncmp((const char *)cbor_string_handle(key), "sig", MIN(o_strlen("sig"), cbor_string_length(key)))) {
              sig = cbor_map_handle(att_stmt)[i].value;
            } else {
              message = msprintf("attStmt map element %d key is not valid: '%.*s", i, cbor_string_length(key), cbor_string_handle(key));
              json_array_append_new(j_error, json_string(message));
              o_free(message);
            }
          } else {
            message = msprintf("attStmt map element %d key is not a string", i);
            json_array_append_new(j_error, json_string(message));
            o_free(message);
          }
        }
        // Let's verify sig over data_signed
        if (cbor_isa_bytestring(sig)) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "sig len %zu", cbor_bytestring_length(sig));
          gnutls_datum_t data = {
            data_signed,
            data_signed_offset
          };
          gnutls_datum_t signature = {
            cbor_bytestring_handle(sig),
            cbor_bytestring_length(sig)
          };
          if (!(ret = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_ECDSA_SHA256, 0, &data, &signature))) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "Signature verified :-)");
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "Signature not verified :-( %d", ret);
          }
        }
      }
    } else {
      json_array_append_new(j_error, json_string("Internal error"));
      y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error gnutls_pubkey_init");
    }
    
    if (json_array_size(j_error)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
    } else {
      j_return = json_pack("{si}", "result", G_OK);
    }
    json_decref(j_error);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

#define FLAG_USER_PRESENT 0x01
#define FLAG_USER_VERIFY 0x04
#define FLAG_AT 0x40
#define FLAG_ED 0x80
/**
 * 
 * Validate the attestationObject
 * Verify steps 9 to 19 in the w3c procedure
 * Ooh baybay
 * Gonna get to you girl
 * 
 */
static json_t * check_attestation_object(struct config_module * config, json_t * j_params, cbor_item_t * item, const char * clientDataJSON) {
  json_t * j_error = json_array(), * j_return, * j_result;
  cbor_item_t * key, * auth_data, * att_stmt;
  int i;
  char * message, * rpid;
  unsigned char * cbor_bs_handle, rpid_hash[32], * fmt;
  size_t rpid_hash_len = 0, fmt_len = 0;
  
  if (j_error != NULL) {
    if (cbor_map_size(item) == 3) {
      for (i=0; i<3; i++) {
        key = cbor_map_handle(item)[i].key;
        if (cbor_isa_string(key)) {
          if (0 == o_strncmp((const char *)cbor_string_handle(key), "fmt", MIN(o_strlen("fmt"), cbor_string_length(key)))) {
            if (!cbor_isa_string(cbor_map_handle(item)[i].value)) {
              json_array_append_new(j_error, json_string("CBOR map value 'fmt' isnt't a string"));
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
            }
          } else {
            message = msprintf("CBOR map element %d is not an expected item", i);
            json_array_append_new(j_error, json_string(message));
            o_free(message);
          }
        } else {
          message = msprintf("CBOR map element %d key is not a string", i);
          json_array_append_new(j_error, json_string(message));
          o_free(message);
        }
      }
      
      // Step 9
      cbor_bs_handle = cbor_bytestring_handle(auth_data);
      if (o_strstr(json_string_value(json_object_get(j_params, "rp-origin")), "://") != NULL) {
        rpid = o_strstr(json_string_value(json_object_get(j_params, "rp-origin")), "://")+3;
        memset(rpid_hash, 0, 32);
        if (generate_digest_raw(digest_SHA256, (unsigned char *)rpid, o_strlen(rpid), rpid_hash, &rpid_hash_len)) {
          if (0 != memcmp(cbor_bs_handle, rpid_hash, rpid_hash_len)) {
            json_array_append_new(j_error, json_string("authData.rpIdHash invalid"));
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_object - Error generate_digest_raw");
          json_array_append_new(j_error, json_string("Internal error"));
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_object - rp-origin invalid");
        json_array_append_new(j_error, json_string("Internal error"));
      }
      
      // Step 10
      if (!(cbor_bs_handle[32] & FLAG_USER_PRESENT)) {
        json_array_append_new(j_error, json_string("authData.userPresent not set"));
      }
      
      // Step 11 ignored for now
      y_log_message(Y_LOG_LEVEL_DEBUG, "authData.userVerified: %d", !!(cbor_bs_handle[32] & FLAG_USER_VERIFY));
      y_log_message(Y_LOG_LEVEL_DEBUG, "authData.Attested credential data: %d", !!(cbor_bs_handle[32] & FLAG_AT));
      y_log_message(Y_LOG_LEVEL_DEBUG, "authData.Extension data: %d", !!(cbor_bs_handle[32] & FLAG_ED));
      
      // Step 12 ignored for now (no extension)
      
      // Steps 13-14
      if (0 == o_strncmp("packed", (char *)fmt, MIN(fmt_len, o_strlen("packed")))) {
        json_array_append_new(j_error, json_string("fmt 'packed' not handled yet"));
      } else if (0 == o_strncmp("tpm", (char *)fmt, MIN(fmt_len, o_strlen("tpm")))) {
        json_array_append_new(j_error, json_string("fmt 'tpm' not handled yet"));
      } else if (0 == o_strncmp("android-key", (char *)fmt, MIN(fmt_len, o_strlen("android-key")))) {
        json_array_append_new(j_error, json_string("fmt 'android-key' not handled yet"));
      } else if (0 == o_strncmp("android-safetynet", (char *)fmt, MIN(fmt_len, o_strlen("android-safetynet")))) {
        json_array_append_new(j_error, json_string("fmt 'android-safetynet' not handled yet"));
      } else if (0 == o_strncmp("fido-u2f", (char *)fmt, MIN(fmt_len, o_strlen("fido-u2f")))) {
        j_result = check_attestation_fido_u2f(config, j_params, auth_data, att_stmt, cbor_bs_handle, rpid_hash_len, clientDataJSON);
        if (check_result_value(j_result, G_ERROR_PARAM)) {
          json_array_extend(j_error, json_object_get(j_result, "error"));
        } else if (!check_result_value(j_result, G_OK)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_object - Error check_attestation_fido_u2f");
          json_array_append_new(j_error, json_string("internal error"));
        }
        json_decref(j_result);
      } else {
        message = msprintf("fmt '%.*s' not handled by Glewlwyd Webauthn scheme", fmt_len, fmt);
        json_array_append_new(j_error, json_string(message));
        o_free(message);
      }
    } else {
      json_array_append_new(j_error, json_string("CBOR map item must have 3 elements"));
    }
    if (json_array_size(j_error)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
    } else {
      j_return = json_pack("{si}", "result", G_OK);
    }
    json_decref(j_error);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_object - Error allocating resources for j_error");
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
static json_t * register_new_credential(struct config_module * config, json_t * j_params, const char * username, json_t * j_scheme_data, json_t * j_credentials) {
  json_t * j_return, * j_client_data, * j_error_list, * j_result;
  unsigned char * client_data, * challenge_b64, * att_obj;
  char * challenge_hash, * message;
  size_t client_data_len, challenge_b64_len, att_obj_len;
  int ret = G_OK;
  struct cbor_load_result cbor_result;
  cbor_item_t * item;
  
  if (j_scheme_data != NULL) {
    j_error_list = json_array();
    if (j_error_list != NULL) {
      if (json_is_string(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON")) && json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON"))) {
        client_data = o_malloc(json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON"))+1);
        if (client_data != NULL) {
          if (o_base64_decode((const unsigned char *)json_string_value(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON")), json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON")), client_data, &client_data_len)) {
            client_data[client_data_len] = '\0';
            j_client_data = json_loads((const char *)client_data, JSON_DECODE_ANY, NULL);
            if (j_client_data != NULL) {
              // Step 3
              if (0 != o_strcmp(json_string_value(json_object_get(j_client_data, "type")), "webauthn.create")) {
                json_array_append_new(j_error_list, json_string("clientDataJSON.type invalid"));
                ret = G_ERROR_PARAM;
              }
              // Step 4
              if (json_string_length(json_object_get(j_client_data, "challenge"))) {
                challenge_b64 = o_malloc(json_string_length(json_object_get(j_client_data, "challenge"))+3);
                if (challenge_b64 != NULL) {
                  if (o_base64url_2_base64((unsigned char *)json_string_value(json_object_get(j_client_data, "challenge")), json_string_length(json_object_get(j_client_data, "challenge")), challenge_b64, &challenge_b64_len)) {
                    challenge_b64[challenge_b64_len] = '\0';
                    if ((challenge_hash = generate_hash(config->hash_algorithm, (const char *)challenge_b64)) != NULL) {
                      if (0 != o_strcmp(challenge_hash, json_string_value(json_object_get(j_credentials, "challenge_hash")))) {
                        json_array_append_new(j_error_list, json_string("clientDataJSON.challenge invalid"));
                        ret = G_ERROR_PARAM;
                      }
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "register_new_credential - Error generate_hash");
                      ret = G_ERROR;
                    }
                    o_free(challenge_hash);
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "register_new_credential - Error o_base64url_2_base64");
                    ret = G_ERROR;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "register_new_credential - Error allocating resources for challenge_b64");
                  ret = G_ERROR;
                }
                o_free(challenge_b64);
              } else {
                json_array_append_new(j_error_list, json_string("clientDataJSON.challenge mandatory"));
                ret = G_ERROR_PARAM;
              }
              // Step 5
              if (json_string_length(json_object_get(j_client_data, "origin"))) {
                if (0 != o_strcmp(json_string_value(json_object_get(j_params, "rp-origin")), json_string_value(json_object_get(j_client_data, "origin")))) {
                  message = msprintf("clientDataJSON.origin invalid - Client send %s, required %s", json_string_value(json_object_get(j_params, "rp-origin")), json_string_value(json_object_get(j_client_data, "origin")));
                  json_array_append_new(j_error_list, json_string(message));
                  o_free(message);
                  ret = G_ERROR_PARAM;
                }
              } else {
                json_array_append_new(j_error_list, json_string("clientDataJSON.origin mandatory"));
                ret = G_ERROR_PARAM;
              }
              // Step 6 ??
              
              if (json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "attestationObject"))) {
                att_obj = o_malloc(json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "attestationObject")));
                if (att_obj != NULL) {
                  if (o_base64_decode((unsigned char *)json_string_value(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "attestationObject")), json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "attestationObject")), att_obj, &att_obj_len)) {
                    // Step 7
                    item = cbor_load(att_obj, att_obj_len, &cbor_result);
                    if (cbor_result.error.code == CBOR_ERR_NONE) {
                      if (cbor_isa_map(item)) {
                        j_result = check_attestation_object(config, j_params, item, (const char *)client_data);
                        if (check_result_value(j_result, G_ERROR_PARAM)) {
                          json_array_extend(j_error_list, json_object_get(j_result, "error"));
                          ret = G_ERROR_PARAM;
                        } else if (!check_result_value(j_result, G_OK)) {
                          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_credential - Error check_attestation_object");
                          ret = G_ERROR;
                        }
                        json_decref(j_result);
                      } else {
                        json_array_append_new(j_error_list, json_string("attestationObject invalid cbor item"));
                        ret = G_ERROR_PARAM;
                      }
                    } else {
                      json_array_append_new(j_error_list, json_string("attestationObject invalid cbor"));
                      ret = G_ERROR_PARAM;
                    }
                    cbor_decref(&item);
                  } else {
                    json_array_append_new(j_error_list, json_string("attestationObject invalid base64"));
                    ret = G_ERROR_PARAM;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "register_new_credential - Error allocating resources for o_malloc");
                  ret = G_ERROR;
                }
                o_free(att_obj);
              } else {
                json_array_append_new(j_error_list, json_string("attestationObject required"));
                ret = G_ERROR_PARAM;
              }
            } else {
              json_array_append_new(j_error_list, json_string("Error parsing clientDataJSON"));
              ret = G_ERROR_PARAM;
            }
            json_decref(j_client_data);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "register_new_credential - Error o_base64_decode client_data");
            ret = G_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_credential - Error allocating resources for client_data");
          ret = G_ERROR;
        }
        o_free(client_data);
      } else {
        json_array_append_new(j_error_list, json_string("clientDataJSON mandatory"));
        ret = G_ERROR_PARAM;
      }
      if (ret == G_ERROR_PARAM) {
        j_return = json_pack("{sisO}", "result", ret, "error", j_error_list);
      } else {
        j_return = json_pack("{si}", "result", G_OK);
      }
      json_decref(j_error_list);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_new_credential - Error allocating resources for j_error_list");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "scheme_data mandatory");
  }
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
                   "webauthn",
                   "display_name",
                   "Webauthn",
                   "description",
                   "Webauthn scheme module",
                   "parameters",
                     "mock-value",
                       "type",
                       "string",
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
 * @parameter cls: will contain an allocated void * pointer that will be sent back
 *                 as void * in all module functions
 * 
 */
int user_auth_scheme_module_init(struct config_module * config, json_t * j_parameters, void ** cls) {
  UNUSED(config);
  json_t * j_result = is_scheme_parameters_valid(j_parameters), * j_element;
  int ret;
  size_t index;
  
  if (check_result_value(j_result, G_OK)) {
    *cls = json_pack("{sOsOs[]}",
                     "challenge-length", json_object_get(j_parameters, "challenge-length"),
                     "rp-origin", json_object_get(j_parameters, "rp-origin"),
                     "pubKey-cred-params");
    json_array_foreach(json_object_get(j_parameters, "pubKey-cred-params"), index, j_element) {
      json_array_append_new(json_object_get((json_t *)*cls, "pubKey-cred-params"), json_pack("{sssO}", "type", "public-key", "alg", j_element));
    }
    ret = G_OK;
  } else if (check_result_value(j_result, G_ERROR_PARAM)) {
    ret = G_ERROR_PARAM;
  } else {
    ret = G_ERROR;
  }
  json_decref(j_result);
  return ret;
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
  return GLEWLWYD_IS_AVAILABLE;
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
json_t * user_auth_scheme_module_register(struct config_module * config, const struct _u_request * http_request, int from_admin, const char * username, json_t * j_scheme_data, void * cls) {
  UNUSED(config);
  UNUSED(http_request);
  UNUSED(from_admin);
  json_t * j_return, * j_result, * j_credential, * j_user_id;

  if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "register")), "new-credential")) {
    j_user_id = get_user_id_from_username(config, username);
    if (check_result_value(j_user_id, G_OK)) {
      j_credential = generate_new_credential(config, (json_t *)cls, username);
      if (check_result_value(j_credential, G_OK)) {
        j_return = json_pack("{sis{sOsOsOs{sOss}sO}}", 
                              "result", G_OK, 
                              "response", 
                                "session", json_object_get(json_object_get(j_credential, "credential"), "session"), 
                                "challenge", json_object_get(json_object_get(j_credential, "credential"), "challenge"), 
                                "pubKey-cred-params", json_object_get((json_t *)cls, "pubKey-cred-params"),
                                "user",
                                  "id", json_object_get(j_user_id, "user_id"),
                                  "name", username,
                                "rp-origin", json_object_get((json_t *)cls, "rp-origin")
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
    j_credential = get_credentials_from_session(config, username, json_string_value(json_object_get(j_scheme_data, "session")));
    if (check_result_value(j_credential, G_OK)) {
      j_result = register_new_credential(config, (json_t *)cls, username, j_scheme_data, json_object_get(j_credential, "credentials"));
      if (check_result_value(j_result, G_OK)) {
        j_return = json_pack("{si}", "result", G_OK);
      } else if (check_result_value(j_result, G_ERROR_UNAUTHORIZED)) {
        j_return = json_pack("{sisO}", "result", G_ERROR_UNAUTHORIZED, "error", json_object_get(j_result, "error"));
      } else if (check_result_value(j_result, G_ERROR_PARAM)) {
        j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", json_object_get(j_result, "error"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error register_new_credential");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_result);
    } else if (check_result_value(j_credential, G_ERROR_NOT_FOUND)) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error get_credentials");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_credential);
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
json_t * user_auth_scheme_module_register_get(struct config_module * config, const struct _u_request * http_request, int from_admin, const char * username, void * cls) {
  UNUSED(config);
  UNUSED(http_request);
  UNUSED(from_admin);
  json_t * j_return = json_pack("{sis{ss}}", "result", G_OK, "response", "grut", "plop");
  
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
  UNUSED(j_scheme_trigger);
  json_t * j_return = NULL;
  
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
  UNUSED(config);
  UNUSED(http_request);
  int ret = G_ERROR_UNAUTHORIZED;
  
  return ret;
}

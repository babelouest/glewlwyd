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
#include <jwt.h>
#include <jansson.h>
#include <cbor.h>
#include <yder.h>
#include <orcania.h>
#include "../glewlwyd-common.h"

#define G_TABLE_WEBAUTHN_USER       "gs_webauthn_user"
#define G_TABLE_WEBAUTHN_CREDENTIAL "gs_webauthn_credential"
#define G_TABLE_WEBAUTHN_ASSERTION  "gs_webauthn_assertion"

#define SESSION_LENGTH 32
#define USER_ID_LENGTH 32

#define FLAG_USER_PRESENT 0x01
#define FLAG_USER_VERIFY 0x04
#define FLAG_AT 0x40
#define FLAG_ED 0x80

#define COUNTER_LEN 4
#define AAGUID_LEN 16
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

static json_t * is_scheme_parameters_valid(json_t * j_params) {
  json_t * j_return, * j_error, * j_element;
  size_t index;
  json_int_t pubkey;
  
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
        json_array_append_new(j_error, json_string("google-root-ca-r2 is optional and must be a non empty string"));
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
  
  username_escaped = h_escape_string(config->conn, username);
  username_clause = msprintf(" = UPPER('%s')", username_escaped);
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
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static json_t * get_credential_list(struct config_module * config, const char * username, int restrict_to_registered) {
  json_t * j_query, * j_result, * j_return, * j_element;
  int res;
  char * username_escaped, * username_clause;
  size_t index;
  
  username_escaped = h_escape_string(config->conn, username);
  username_clause = msprintf(" = (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER('%s'))", username_escaped);
  j_query = json_pack("{sss[ssss]s{s{ssss}}}",
                      "table",
                      G_TABLE_WEBAUTHN_CREDENTIAL,
                      "columns",
                        "gswc_credential_id AS credential_id",
                        "gswc_name AS name",
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gswc_created_at) AS created_at", "gswc_created_at AS created_at", "EXTRACT(EPOCH FROM gswc_created_at) AS created_at"),
                        "gswc_status",
                      "where",
                        "gswu_id",
                          "operator",
                          "raw",
                          "value",
                          username_clause);
  o_free(username_clause);
  o_free(username_escaped);
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
            j_return = json_pack("{si}", "result", G_ERROR_DB);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_credential - Error executing j_query update");
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        o_free(username_clause);
        o_free(username_escaped);
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
        if (mock < 2) {
          username_escaped = h_escape_string(config->conn, username);
          username_clause = msprintf(" (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER('%s'))", username_escaped);
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
              j_return = json_pack("{si}", "result", G_ERROR_DB);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_assertion - Error executing j_query update");
            j_return = json_pack("{si}", "result", G_ERROR_DB);
          }
          o_free(username_clause);
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
  char * username_escaped, * username_clause, * expiration_clause;
  char * session_hash;
  int res;
  time_t now;
  
  if (o_strlen(session)) {
    session_hash = generate_hash(config->hash_algorithm, session);
    if (session_hash != NULL) {
      time(&now);
      username_escaped = h_escape_string(config->conn, username);
      username_clause = msprintf(" = (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER('%s'))", username_escaped);
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

static json_t * get_credential(struct config_module * config, const char * username, const char * credential_id) {
  json_t * j_query, * j_result, * j_return;
  char * username_escaped, * username_clause;
  int res;
  
  username_escaped = h_escape_string(config->conn, username);
  username_clause = msprintf(" = (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER('%s'))", username_escaped);
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
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static int update_credential(struct config_module * config, const char * username, const char * credential_id, int status) {
  json_t * j_query;
  char * username_escaped, * username_clause;
  int res, ret;
  
  username_escaped = h_escape_string(config->conn, username);
  username_clause = msprintf(" = (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER('%s'))", username_escaped);
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
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_credential - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static int update_credential_name(struct config_module * config, const char * username, const char * credential_id, const char * name) {
  json_t * j_query;
  char * username_escaped, * username_clause;
  int res, ret;
  
  username_escaped = h_escape_string(config->conn, username);
  username_clause = msprintf(" = (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER('%s'))", username_escaped);
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
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_credential - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static json_t * get_assertion_from_session(struct config_module * config, json_t * j_params, const char * username, const char * session, int mock) {
  json_t * j_query, * j_result, * j_return;
  char * username_escaped, * username_clause, * expiration_clause;
  char * session_hash;
  int res;
  time_t now;
  
  if (o_strlen(session)) {
    session_hash = generate_hash(config->hash_algorithm, session);
    if (session_hash != NULL) {
      time(&now);
      username_escaped = h_escape_string(config->conn, username);
      username_clause = msprintf(" = (SELECT gswu_id FROM "G_TABLE_WEBAUTHN_USER" WHERE UPPER(gswu_username) = UPPER('%s'))", username_escaped);
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

static int check_certificate(struct config_module * config, json_t * j_cert, json_int_t gswu_id) {
  json_t * j_query, * j_result;
  int res, ret;
  
  j_query = json_pack("{sss[s]s{sOsi}}",
                      "table",
                      G_TABLE_WEBAUTHN_CREDENTIAL,
                      "columns",
                        "gswu_id",
                      "where",
                        "gswc_certificate",
                        j_cert,
                        "gswc_status",
                        1);
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
    ret = G_ERROR_DB;
  }
  return ret;
}

static int validate_safetynet_ca_root(json_t * j_params, gnutls_x509_crt_t cert_leaf, json_t * j_header_x5c) {
  gnutls_x509_crt_t cert_x509[(json_array_size(j_header_x5c)+1)], root_x509 = NULL;
  gnutls_x509_trust_list_t tlist = NULL;
  int ret = G_OK;
  unsigned int result, i;
  json_t * j_cert;
  unsigned char * header_cert_decoded;
  size_t header_cert_decoded_len, len;
  gnutls_datum_t cert_dat;
  FILE *fl;
  char * cert_content;
  
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
    fl = fopen(json_string_value(json_object_get(j_params, "google-root-ca-r2")), "r");
    if (fl != NULL) {
      fseek(fl, 0, SEEK_END);
      len = ftell(fl);
      cert_content = malloc(len);
      if (cert_content != NULL) {
        fseek(fl, 0, SEEK_SET);
        fread(cert_content, 1, len, fl);
        fclose(fl);
        cert_dat.data = (unsigned char *)cert_content;
        cert_dat.size = len;
        if (!gnutls_x509_crt_init(&cert_x509[json_array_size(j_header_x5c)]) && 
            !gnutls_x509_crt_import(cert_x509[json_array_size(j_header_x5c)], &cert_dat, GNUTLS_X509_FMT_DER)) {
          if (!gnutls_x509_crt_init(&root_x509) && 
              !gnutls_x509_crt_import(root_x509, &cert_dat, GNUTLS_X509_FMT_DER)) {
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
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "validate_safetynet_ca_root - Error allocating resources for cert_content");
        ret = G_ERROR_MEMORY;
      }
      o_free(cert_content);
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

/**
 * 
 * Validate the attStmt object under the Android SafetyNet format
 * https://w3c.github.io/webauthn/#android-safetynet-attestation
 * (step) hey girl, in your eyes
 * I see a picture of me all the time
 * 
 */
static json_t * check_attestation_android_safetynet(json_t * j_params, cbor_item_t * auth_data, cbor_item_t * att_stmt, const unsigned char * client_data) {
  json_t * j_error = json_array(), * j_return;
  unsigned char pubkey_export[1024] = {0}, cert_export[32] = {0}, cert_export_b64[64], client_data_hash[32], * nonce_base = NULL, nonce_base_hash[32], * nonce_base_hash_b64 = NULL, * header_cert_decoded;
  char * message, * response_token, * header_x5c, issued_to[128];
  size_t pubkey_export_len = 1024, cert_export_len = 32, cert_export_b64_len, issued_to_len = 128, client_data_hash_len = 32, nonce_base_hash_len = 32, nonce_base_hash_b64_len = 0, header_cert_decoded_len = 0;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  cbor_item_t * key, * response;
  int i, ret;
  jwt_t * j_response = NULL, * j_response_signed = NULL;
  json_t * j_header_x5c = NULL, * j_cert = NULL;
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
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error o_base64_encode for nonce_base_hash_b64");
        break;
      }
      
      if ((response_token = o_strndup((const char *)cbor_bytestring_handle(response), cbor_bytestring_length(response))) == NULL) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error o_strndup for response_token");
        break;
      }
      
      if (jwt_decode(&j_response, response_token, NULL, 0)) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error jwt_decode response_token");
        break;
      }
      
      if (o_strcmp(jwt_get_grant(j_response, "nonce"), (const char *)nonce_base_hash_b64)) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error nonce invalid");
        break;
      }
      
      if (json_integer_value(json_object_get(j_params, "ctsProfileMatch")) != -1 && json_integer_value(json_object_get(j_params, "ctsProfileMatch")) != jwt_get_grant_bool(j_response, "ctsProfileMatch")) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error ctsProfileMatch invalid");
        break;
      }
      
      if (json_integer_value(json_object_get(j_params, "basicIntegrity")) != -1 && json_integer_value(json_object_get(j_params, "basicIntegrity")) != jwt_get_grant_bool(j_response, "basicIntegrity")) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error basicIntegrity invalid");
        break;
      }
      
      if ((header_x5c = jwt_get_headers_json(j_response, "x5c")) == NULL) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error jwt_get_headers_json x5c");
        break;
      }
      
      if ((j_header_x5c = json_loads(header_x5c, JSON_DECODE_ANY, NULL)) == NULL) {
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
        json_array_append_new(j_error, json_string("internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error allocating resources for header_cert_decoded");
        break;
      }
      
      if (!o_base64_decode((const unsigned char *)json_string_value(j_cert), json_string_length(j_cert), header_cert_decoded, &header_cert_decoded_len)) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error o_base64_decode x5c leaf");
        break;
      }
      
      if (gnutls_x509_crt_init(&cert)) {
        json_array_append_new(j_error, json_string("check_attestation_android_safetynet - Error gnutls_x509_crt_init"));
        break;
      }
      if (gnutls_pubkey_init(&pubkey)) {
        json_array_append_new(j_error, json_string("check_attestation_android_safetynet - Error gnutls_pubkey_init"));
        break;
      }
      cert_dat.data = header_cert_decoded;
      cert_dat.size = header_cert_decoded_len;
      if ((ret = gnutls_x509_crt_import(cert, &cert_dat, GNUTLS_X509_FMT_DER)) < 0) {
        json_array_append_new(j_error, json_string("Error importing x509 certificate"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error gnutls_pcert_import_x509_raw: %d", ret);
        break;
      }
      if ((ret = gnutls_pubkey_import_x509(pubkey, cert, 0)) < 0) {
        json_array_append_new(j_error, json_string("Error importing x509 certificate"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error gnutls_pubkey_import_x509: %d", ret);
        break;
      }
      if ((ret = gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA256, cert_export, &cert_export_len)) < 0) {
        json_array_append_new(j_error, json_string("Error exporting x509 certificate"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error gnutls_x509_crt_get_key_id: %d", ret);
        break;
      }
      if ((ret = gnutls_x509_crt_get_dn(cert, issued_to, &issued_to_len)) < 0) {
        json_array_append_new(j_error, json_string("Error x509 dn"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error gnutls_x509_crt_get_dn: %d", ret);
        break;
      }
      if (o_strnstr(issued_to, SAFETYNET_ISSUED_TO, issued_to_len) == NULL) {
        json_array_append_new(j_error, json_string("Error x509 dn"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - safetynet certificate issued for %.*s", issued_to_len, issued_to);
        break;
      }
      if (json_object_get(j_params, "google-root-ca-r2") != json_null()) {
        if ((ret = validate_safetynet_ca_root(j_params, cert, j_header_x5c)) == G_ERROR_UNAUTHORIZED) {
          json_array_append_new(j_error, json_string("Error x509 certificate chain validation"));
          break;
        } else if (ret != G_OK) {
          json_array_append_new(j_error, json_string("internal error"));
          y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - safetynet certificate chain certificate validation error");
          break;
        }
      }
      if (!o_base64_encode(cert_export, cert_export_len, cert_export_b64, &cert_export_b64_len)) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error o_base64_encode cert_export");
        break;
      }
      if ((ret = gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_PEM, pubkey_export, &pubkey_export_len)) < 0) {
        json_array_append_new(j_error, json_string("Error exporting x509 certificate"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error gnutls_pubkey_export: %d", ret);
        break;
      }
      
      if (jwt_decode(&j_response_signed, response_token, pubkey_export, pubkey_export_len)) {
        json_array_append_new(j_error, json_string("response invalid"));
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_attestation_android_safetynet - Error jwt_decode response_token with signature");
        break;
      }
      
    } while (0);

    if (json_array_size(j_error)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
    } else {
      j_return = json_pack("{sis{ss%}}", "result", G_OK, "data", "certificate", cert_export_b64, cert_export_b64_len);
    }
    json_decref(j_error);
    json_decref(j_header_x5c);
    gnutls_pubkey_deinit(pubkey);
    gnutls_x509_crt_deinit(cert);
    jwt_free(j_response);
    jwt_free(j_response_signed);
    o_free(nonce_base);
    o_free(nonce_base_hash_b64);
    o_free(response_token);
    o_free(header_cert_decoded);
    o_free(header_x5c);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_android_safetynet - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

/**
 * 
 * Validate the attStmt object under the fido-u2f format
 * https://w3c.github.io/webauthn/#fido-u2f-attestation
 * Gonna get to you girl
 * Really want you in my world
 * 
 */
static json_t * check_attestation_fido_u2f(unsigned char * credential_id, size_t credential_id_len, unsigned char * cert_x, unsigned char * cert_y, cbor_item_t * att_stmt, unsigned char * rpid_hash, size_t rpid_hash_len, const unsigned char * client_data) {
  json_t * j_error = json_array(), * j_return;
  cbor_item_t * key, * x5c, * sig = NULL, * att_cert;
  int i, ret;
  char * message;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t cert = NULL;
  gnutls_datum_t cert_dat, data, signature;
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
      if (!cbor_isa_map(att_stmt) || cbor_map_size(att_stmt) != 2) {
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
      if (!cbor_isa_array(x5c) || cbor_array_size(x5c) != 1) {
        json_array_append_new(j_error, json_string("CBOR map value 'x5c' invalid format"));
        break;
      }
      att_cert = cbor_array_get(x5c, 0);
      cert_dat.data = cbor_bytestring_handle(att_cert);
      cert_dat.size = cbor_bytestring_length(att_cert);
      if ((ret = gnutls_x509_crt_import(cert, &cert_dat, GNUTLS_X509_FMT_DER)) < 0) {
        json_array_append_new(j_error, json_string("Error importing x509 certificate"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error gnutls_pcert_import_x509_raw: %d", ret);
        break;
      }
      if ((ret = gnutls_pubkey_import_x509(pubkey, cert, 0)) < 0) {
        json_array_append_new(j_error, json_string("Error importing x509 certificate"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error gnutls_pubkey_import_x509: %d", ret);
        break;
      }
      if ((ret = gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA256, cert_export, &cert_export_len)) < 0) {
        json_array_append_new(j_error, json_string("Error exporting x509 certificate"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error gnutls_x509_crt_get_key_id: %d", ret);
        break;
      }
      if (!o_base64_encode(cert_export, cert_export_len, cert_export_b64, &cert_export_b64_len)) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error o_base64_encode cert_export");
        break;
      }
      if (!generate_digest_raw(digest_SHA256, client_data, o_strlen((char *)client_data), client_data_hash, &client_data_hash_len)) {
        json_array_append_new(j_error, json_string("Internal error"));
        y_log_message(Y_LOG_LEVEL_ERROR, "check_attestation_fido_u2f - Error generate_digest_raw client_data");
        break;
      }

      if (!cbor_isa_bytestring(sig)) {
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
      
      memcpy(data_signed+data_signed_offset, cert_x, 32);
      data_signed_offset+=32;
      
      memcpy(data_signed+data_signed_offset, cert_y, 32);
      data_signed_offset+=32;
      
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
    cbor_decref(&att_cert);
    
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
  json_t * j_return, * j_client_data = NULL, * j_error, * j_result, * j_pubkey = NULL, * j_cert = NULL, * j_query, * j_element;
  unsigned char * client_data = NULL, * challenge_b64 = NULL, * att_obj = NULL, * cbor_bs_handle = NULL, rpid_hash[32], * fmt = NULL, * credential_id_b64 = NULL, * cbor_auth_data, * cred_pub_key, cert_x[32], cert_y[32], pubkey_export[1024];
  char * challenge_hash = NULL, * message = NULL, * rpid = NULL;
  size_t client_data_len = 0, challenge_b64_len = 0, att_obj_len = 0, rpid_hash_len = 32, fmt_len = 0, credential_id_len = 0, credential_id_b64_len, cbor_auth_data_len, cred_pub_key_len, pubkey_export_len = 1024, index;
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
        if (!json_is_string(json_object_get(json_object_get(j_scheme_data, "credential"), "rawId")) || !json_string_length(json_object_get(json_object_get(j_scheme_data, "credential"), "rawId"))) {
          json_array_append_new(j_error, json_string("rawId mandatory"));
          ret = G_ERROR_PARAM;
          break;
        }
        if (!json_is_string(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON")) || !json_string_length(json_object_get(json_object_get(json_object_get(j_scheme_data, "credential"), "response"), "clientDataJSON"))) {
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
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error o_base64_decode client_data");
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
        }
        // Step 5
        if (!json_string_length(json_object_get(j_client_data, "origin"))) {
          json_array_append_new(j_error, json_string("clientDataJSON.origin mandatory"));
          ret = G_ERROR_PARAM;
          break;
        }
        if (0 != o_strcmp(json_string_value(json_object_get(j_params, "rp-origin")), json_string_value(json_object_get(j_client_data, "origin")))) {
          message = msprintf("clientDataJSON.origin invalid - Client send %s, required %s", json_string_value(json_object_get(j_params, "rp-origin")), json_string_value(json_object_get(j_client_data, "origin")));
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
        cbor_bs_handle = cbor_bytestring_handle(auth_data);
        if (o_strstr(json_string_value(json_object_get(j_params, "rp-origin")), "://") == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - rp-origin invalid");
          json_array_append_new(j_error, json_string("Internal error"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        rpid = o_strstr(json_string_value(json_object_get(j_params, "rp-origin")), "://")+3;
        if (!generate_digest_raw(digest_SHA256, (unsigned char *)rpid, o_strlen(rpid), rpid_hash, &rpid_hash_len)) {
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
        //y_log_message(Y_LOG_LEVEL_DEBUG, "authData.Extension data: %d", !!(cbor_bs_handle[FLAGS_OFFSET] & FLAG_ED));
        
        credential_id_len = cbor_bs_handle[CRED_ID_L_OFFSET+1] | (cbor_bs_handle[CRED_ID_L_OFFSET] << 8);
        credential_id_b64 = o_malloc(credential_id_len*2);
        if (credential_id_b64 == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error o_malloc for credential_id_b64");
          json_array_append_new(j_error, json_string("Internal error"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        if (!o_base64_encode(cbor_bs_handle+CRED_ID_L_OFFSET, credential_id_len, credential_id_b64, &credential_id_b64_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error o_base64_encode for credential_id_b64");
          json_array_append_new(j_error, json_string("Internal error"));
          ret = G_ERROR_PARAM;
          break;
        }
        
        // Extract public key from auth_data COSE structure

        // Extract credential ID
        cbor_auth_data_len = cbor_bytestring_length(auth_data);
        cbor_auth_data = cbor_bytestring_handle(auth_data);
        
        // A Cose key is a CBOR data embedded ina CBOR data
        credential_id_len = cbor_auth_data[CRED_ID_L_OFFSET+1] | (cbor_auth_data[CRED_ID_L_OFFSET] << 8);
        
        cred_pub_key = cbor_auth_data+CREDENTIAL_ID_OFFSET+credential_id_len;
        cred_pub_key_len = cbor_auth_data_len-CREDENTIAL_ID_OFFSET-credential_id_len;
        cbor_cose = cbor_load(cred_pub_key, cred_pub_key_len, &cbor_result);
        if (cbor_result.error.code != CBOR_ERR_NONE) {
          json_array_append_new(j_error, json_string("Internal error"));
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error cbor_load cbor_cose");
          break;
        }
        
        if (!cbor_isa_map(cbor_cose)) {
          json_array_append_new(j_error, json_string("Internal error"));
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error cbor_cose not a map");
          break;
        }
        
        for (i=0; i<cbor_map_size(cbor_cose); i++) {
          cbor_key = cbor_map_handle(cbor_cose)[i].key;
          cbor_value = cbor_map_handle(cbor_cose)[i].value;
          if (cbor_isa_negint(cbor_key) && cbor_get_int(cbor_key) == 1 && cbor_isa_bytestring(cbor_value) && cbor_bytestring_length(cbor_value) == 32) {
            has_x = 1;
            memcpy(cert_x, cbor_bytestring_handle(cbor_value), 32);
          } else if (cbor_isa_negint(cbor_key) && cbor_get_int(cbor_key) == 2 && cbor_isa_bytestring(cbor_value) && cbor_bytestring_length(cbor_value) == 32) {
            has_y = 1;
            memcpy(cert_y, cbor_bytestring_handle(cbor_value), 32);
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
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error invalid COSE key has_x %d && has_y %d && key_type_valid %d && key_alg_valid %d", has_x, has_y, key_type_valid, key_alg_valid);
          break;
        }
        
        g_x.data = cert_x;
        g_x.size = 32;
        g_y.data = cert_y;
        g_y.size = 32;
        if (gnutls_pubkey_init(&g_key)) {
          json_array_append_new(j_error, json_string("Internal error"));
          y_log_message(Y_LOG_LEVEL_DEBUG, "register_new_attestation - Error gnutls_pubkey_init");
        }
        if (gnutls_pubkey_import_ecc_raw(g_key, curve, &g_x, &g_y) < 0) {
          json_array_append_new(j_error, json_string("Internal error"));
          y_log_message(Y_LOG_LEVEL_DEBUG, "register_new_attestation - error gnutls_pubkey_import_ecc_raw");
        }
        if ((ret = gnutls_pubkey_export(g_key, GNUTLS_X509_FMT_PEM, pubkey_export, &pubkey_export_len)) < 0) {
          json_array_append_new(j_error, json_string("Error exporting pubkey"));
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_attestation - Error gnutls_pubkey_export: %d", ret);
          break;
        }
        
        // Steps 13-14
        if (0 == o_strncmp("packed", (char *)fmt, MIN(fmt_len, o_strlen("packed")))) {
          json_array_append_new(j_error, json_string("fmt 'packed' not handled yet"));
          ret = G_ERROR_PARAM;
        } else if (0 == o_strncmp("tpm", (char *)fmt, MIN(fmt_len, o_strlen("tpm")))) {
          json_array_append_new(j_error, json_string("fmt 'tpm' not handled yet"));
          ret = G_ERROR_PARAM;
        } else if (0 == o_strncmp("android-key", (char *)fmt, MIN(fmt_len, o_strlen("android-key")))) {
          json_array_append_new(j_error, json_string("fmt 'android-key' not handled yet"));
          ret = G_ERROR_PARAM;
        } else if (0 == o_strncmp("android-safetynet", (char *)fmt, MIN(fmt_len, o_strlen("android-safetynet")))) {
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
        } else if (0 == o_strncmp("fido-u2f", (char *)fmt, MIN(fmt_len, o_strlen("fido-u2f")))) {
          j_result = check_attestation_fido_u2f((cbor_auth_data+CREDENTIAL_ID_OFFSET), credential_id_len, cert_x, cert_y, att_stmt, rpid_hash, rpid_hash_len, client_data);
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
        } else {
          message = msprintf("fmt '%.*s' not handled by Glewlwyd Webauthn scheme", fmt_len, fmt);
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
        if ((res = check_certificate(config, j_cert, json_integer_value(json_object_get(j_credential, "gswu_id")))) == G_OK) {
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
  char * challenge_hash = NULL, * rpid = NULL;
  size_t client_data_len, challenge_b64_len, auth_data_len, rpid_hash_len = 32, cdata_hash_len = 32, sig_len = 128, counter_value = 0;
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
      j_credential = get_credential(config, username, json_string_value(json_object_get(json_object_get(j_scheme_data, "credential"), "rawId")));
      if (check_result_value(j_credential, G_ERROR_NOT_FOUND)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - credential ID not found");
        ret = G_ERROR_PARAM;
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
        y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - Error o_base64_decode client_data");
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
      }
      // Step 9
      if (!json_string_length(json_object_get(j_client_data, "origin"))) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - clientDataJSON.origin mandatory");
        ret = G_ERROR_PARAM;
        break;
      }
      if (0 != o_strcmp(json_string_value(json_object_get(j_params, "rp-origin")), json_string_value(json_object_get(j_client_data, "origin")))) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_assertion - clientDataJSON.origin invalid - Client send %s, required %s", json_string_value(json_object_get(j_params, "rp-origin")), json_string_value(json_object_get(j_client_data, "origin")));
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
        y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - Error o_base64_decode auth_data");
        ret = G_ERROR_PARAM;
        break;
      }
      if (auth_data_len != 37) {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - Error authenticatorData invalid");
        ret = G_ERROR_PARAM;
        break;
      }
      rpid = o_strstr(json_string_value(json_object_get(j_params, "rp-origin")), "://")+3;
      if (!generate_digest_raw(digest_SHA256, (unsigned char *)rpid, o_strlen(rpid), rpid_hash, &rpid_hash_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - Error generate_digest_raw for rpid_hash");
        ret = G_ERROR_PARAM;
        break;
      }
      
      if (0 != memcmp(auth_data, rpid_hash, rpid_hash_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - authData.rpIdHash invalid");
        ret = G_ERROR_PARAM;
        break;
      }
      flags = auth_data + FLAGS_OFFSET;
      
      // Step 12
      if (!(*flags & FLAG_USER_PRESENT)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - authData.userPresent not set");
        ret = G_ERROR_PARAM;
        break;
      }
      
      // Step 13 ignored for now
      //y_log_message(Y_LOG_LEVEL_DEBUG, "authData.userVerified: %d", !!(*flags & FLAG_USER_VERIFY));
      //y_log_message(Y_LOG_LEVEL_DEBUG, "authData.Extension data: %d", !!(*flags & FLAG_ED));
      
      // Step 14 ignored for now (no extension)
      
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
        y_log_message(Y_LOG_LEVEL_ERROR, "check_assertion - Error gnutls_pubkey_import: %d", ret);
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
  return json_pack("{sisssssss{s{ssso}s{ssso}s{ssso}s{ssso}s{ssso}s{ssso}s{ssso}s{ssso}}}",
                   "result",
                   G_OK,
                   "name",
                   "webauthn",
                   "display_name",
                   "Webauthn",
                   "description",
                   "Webauthn scheme module",
                   "parameters",
                     "challenge-length",
                       "type",
                       "number",
                       "mandatory",
                       json_true(),
                     "credential-expiration",
                       "type",
                       "number",
                       "mandatory",
                       json_true(),
                     "credential-assertion",
                       "type",
                       "number",
                       "mandatory",
                       json_true(),
                     "rp-origin",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                     "pubKey-cred-params",
                       "type",
                       "array",
                       "mandatory",
                       json_true(),
                     "ctsProfileMatch",
                       "type",
                       "boolean",
                       "mandatory",
                       json_false(),
                     "basicIntegrity",
                       "type",
                       "boolean",
                       "mandatory",
                       json_false(),
                     "google-root-ca-r2",
                       "type",
                       "string",
                       "mandatory",
                       json_false());
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
int user_auth_scheme_module_init(struct config_module * config, json_t * j_parameters, const char * mod_name, void ** cls) {
  UNUSED(config);
  json_t * j_result = is_scheme_parameters_valid(j_parameters), * j_element;
  int ret;
  size_t index;
  char * message;
  
  if (check_result_value(j_result, G_OK)) {
    *cls = json_pack("{sO sO sO sO sI sI sO ss so ss s[]}",
                     "challenge-length", json_object_get(j_parameters, "challenge-length"),
                     "rp-origin", json_object_get(j_parameters, "rp-origin"),
                     "credential-expiration", json_object_get(j_parameters, "credential-expiration"),
                     "credential-assertion", json_object_get(j_parameters, "credential-assertion"),
                     "ctsProfileMatch", json_object_get(j_parameters, "ctsProfileMatch")!=NULL?json_integer_value(json_object_get(j_parameters, "ctsProfileMatch")):-1,
                     "basicIntegrity", json_object_get(j_parameters, "basicIntegrity")!=NULL?json_integer_value(json_object_get(j_parameters, "basicIntegrity")):-1,
                     "session-mandatory", json_object_get(j_parameters, "session-mandatory")!=NULL?json_object_get(j_parameters, "session-mandatory"):json_true(),
                     "seed", !json_string_length(json_object_get(j_parameters, "seed"))?"":json_string_value(json_object_get(j_parameters, "seed")),
                     "google-root-ca-r2", json_string_length(json_object_get(j_parameters, "google-root-ca-r2"))?json_object_get(j_parameters, "google-root-ca-r2"):json_null(),
                     "mod_name", mod_name,
                     "pubKey-cred-params");
    json_array_foreach(json_object_get(j_parameters, "pubKey-cred-params"), index, j_element) {
      json_array_append_new(json_object_get((json_t *)*cls, "pubKey-cred-params"), json_pack("{sssO}", "type", "public-key", "alg", j_element));
    }
    ret = G_OK;
  } else if (check_result_value(j_result, G_ERROR_PARAM)) {
    message = json_dumps(json_object_get(j_result, "error"), JSON_COMPACT);
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init webauthn - Error input parameters: %s", message);
    o_free(message);
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
  json_t * j_user_id, * j_credential;
  int ret;
  
  j_user_id = get_user_id_from_username(config, (json_t *)cls, username, 0);
  if (check_result_value(j_user_id, G_OK)) {
    j_credential = get_credential_list(config, username, 1);
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
        j_return = json_pack("{sis{sOsOsOs{sOss}sO}}", 
                              "result", G_OK, 
                              "response", 
                                "session", json_object_get(json_object_get(j_credential, "credential"), "session"), 
                                "challenge", json_object_get(json_object_get(j_credential, "credential"), "challenge"), 
                                "pubKey-cred-params", json_object_get((json_t *)cls, "pubKey-cred-params"),
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
        j_return = json_pack("{sisO}", "result", G_ERROR_UNAUTHORIZED, "error", json_object_get(j_result, "error"));
      } else if (check_result_value(j_result, G_ERROR_PARAM)) {
        j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", json_object_get(j_result, "error"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error register_new_attestation");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_result);
    } else if (check_result_value(j_credential, G_ERROR_NOT_FOUND)) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error get_credential_from_session");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_credential);
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "register")), "remove-credential") && json_string_length(json_object_get(j_scheme_data, "credential_id"))) {
    j_credential = get_credential(config, username, json_string_value(json_object_get(j_scheme_data, "credential_id")));
    if (check_result_value(j_credential, G_OK)) {
      if ((res = update_credential(config, username, json_string_value(json_object_get(j_scheme_data, "credential_id")), 4)) == G_OK) {
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
    j_credential = get_credential(config, username, json_string_value(json_object_get(j_scheme_data, "credential_id")));
    if (check_result_value(j_credential, G_OK)) {
      if ((res = update_credential(config, username, json_string_value(json_object_get(j_scheme_data, "credential_id")), 3)) == G_OK) {
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
    j_credential = get_credential(config, username, json_string_value(json_object_get(j_scheme_data, "credential_id")));
    if (check_result_value(j_credential, G_OK)) {
      if ((res = update_credential(config, username, json_string_value(json_object_get(j_scheme_data, "credential_id")), 1)) == G_OK) {
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
    j_credential = get_credential(config, username, json_string_value(json_object_get(j_scheme_data, "credential_id")));
    if (check_result_value(j_credential, G_OK)) {
      if ((res = update_credential_name(config, username, json_string_value(json_object_get(j_scheme_data, "credential_id")), json_string_value(json_object_get(j_scheme_data, "name")))) == G_OK) {
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
      j_credential = get_credential_list(config, username, 1);
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
        } else if (res == G_ERROR_UNAUTHORIZED) {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
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
  UNUSED(cls);
  json_t * j_return, * j_user_id, * j_credential_list;

  j_user_id = get_user_id_from_username(config, (json_t *)cls, username, 1);
  if (check_result_value(j_user_id, G_OK)) {
    j_credential_list = get_credential_list(config, username, 0);
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
        j_credential = get_credential_list(config, username, 1);
        if (check_result_value(j_credential, G_OK)) {
          j_assertion = generate_new_assertion(config, (json_t *)cls, username, 0);
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
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register webauthn - Error check_assertion");
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

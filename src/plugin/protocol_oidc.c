/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * OpenID Connect Core plugin
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
#include <jansson.h>
#include <jwt.h>
#include <yder.h>
#include <orcania.h>
#include <ulfius.h>
#include "../glewlwyd-common.h"
#include "../../docs/resources/ulfius/glewlwyd_resource.h"

#define OAUTH2_SALT_LENGTH 16
#define OIDC_REFRESH_TOKEN_LENGTH 128

#define GLEWLWYD_ACCESS_TOKEN_EXP_DEFAULT 3600
#define GLEWLWYD_REFRESH_TOKEN_EXP_DEFAULT 1209600
#define GLEWLWYD_CODE_EXP_DEFAULT 600

#define GLEWLWYD_CHECK_JWT_USERNAME "myrddin"
#define GLEWLWYD_CHECK_JWT_SCOPE    "caledonia"

#define GLEWLWYD_PLUGIN_OIDC_TABLE_CODE                "gpo_code"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SCOPE          "gpo_code_scope"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SHEME          "gpo_code_scheme"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN       "gpo_refresh_token"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN_SCOPE "gpo_refresh_token_scope"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_ACCESS_TOKEN        "gpo_access_token"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_ACCESS_TOKEN_SCOPE  "gpo_access_token_scope"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_ID_TOKEN            "gpo_id_token"

// Authorization types available
#define GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE 0
#define GLEWLWYD_AUTHORIZATION_TYPE_TOKEN              1
#define GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN           2
#define GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN      3
#define GLEWLWYD_AUTHORIZATION_TYPE_DELETE_TOKEN       4

#define GLEWLWYD_AUTHORIZATION_TYPE_NONE_STORE               0
#define GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE_STORE 1
#define GLEWLWYD_AUTHORIZATION_TYPE_TOKEN_STORE              2
#define GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN_STORE           4
#define GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN_STORE      8
#define GLEWLWYD_AUTHORIZATION_TYPE_DELETE_TOKEN_STORE       16

struct _oidc_config {
  struct config_plugin             * glewlwyd_config;
  int                                jwt_key_size;
  jwt_t                            * jwt_key;
  const char                       * name;
  json_t                           * j_params;
  json_int_t                         access_token_duration;
  json_int_t                         refresh_token_duration;
  json_int_t                         code_duration;
  unsigned short int                 refresh_token_rolling;
  unsigned short int                 auth_type_enabled[4];
  pthread_mutex_t                    insert_lock;
  struct _glewlwyd_resource_config * glewlwyd_resource_config;
};

static struct _u_map * get_map(const struct _u_request * request) {
  if (0 == o_strcmp(request->http_verb, "POST")) {
    return request->map_post_body;
  } else {
    return request->map_url;
  }
}

/**
 *
 * Generates a query string based on url and post parameters of a request
 * Returned value must be o_free'd after use
 *
 */
static char * generate_query_parameters(struct _u_map * map) {
  char * query = NULL, * param, * value;
  const char ** keys;
  int i;
  
  if (map == NULL) {
    return NULL;
  } else {
    if (map != NULL) {
      keys = u_map_enum_keys(map);
      for (i=0; keys[i] != NULL; i++) {
        if (u_map_get(map, keys[i]) != NULL) {
          value = url_encode((char *)u_map_get(map, keys[i]));
          param = msprintf("%s=%s", keys[i], value);
          o_free(value);
          if (query == NULL) {
            query = o_strdup(param);
          } else {
            query = mstrcatf(query, "&%s", param);
          }
          o_free(param);
        } else {
          if (query == NULL) {
            query = o_strdup(keys[i]);
          } else {
            query = mstrcatf(query, "&%s", keys[i]);
          }
        }
      }
    }
  }
  
  return query;
}

static int json_array_has_string(json_t * j_array, const char * value) {
  json_t * j_element;
  size_t index;
  
  json_array_foreach(j_array, index, j_element) {
    if (json_is_string(j_element) && 0 == o_strcmp(value, json_string_value(j_element))) {
      return 1;
    }
  }
  return 0;
}

static int serialize_id_token(struct _oidc_config * config, uint auth_type, const char * id_token, const char * username, const char * client_id, time_t now, const char * issued_for, const char * user_agent) {
  json_t * j_query;
  int res, ret;
  char * issued_at_clause, * id_token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, id_token);
  
  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_id_token - Error pthread_mutex_lock");
    ret = G_ERROR;
  } else {
    if (issued_for != NULL && now > 0 && id_token_hash != NULL) {
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        issued_at_clause = msprintf("FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        issued_at_clause = msprintf("TO_TIMESTAMP(%u)", (now));
      } else { // HOEL_DB_TYPE_SQLITE
        issued_at_clause = msprintf("%u", (now));
      }
      j_query = json_pack("{sss{sisosos{ss}ssssss}}",
                          "table",
                          GLEWLWYD_PLUGIN_OIDC_TABLE_ID_TOKEN,
                          "values",
                            "gpoi_authorization_type",
                            auth_type,
                            "gpoi_username",
                            username!=NULL?json_string(username):json_null(),
                            "gpoi_client_id",
                            client_id!=NULL?json_string(client_id):json_null(),
                            "gpoi_issued_at",
                              "raw",
                              issued_at_clause,
                            "gpoi_issued_for",
                            issued_for,
                            "gpoi_user_agent",
                            user_agent!=NULL?user_agent:"",
                            "gpoi_hash",
                            id_token_hash);
      o_free(issued_at_clause);
      res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_id_token - Error executing j_query");
        ret = G_ERROR_DB;
      }
    } else {
      ret = G_ERROR_PARAM;
    }
    pthread_mutex_unlock(&config->insert_lock);
    o_free(id_token_hash);
  }
  return ret;
}

static char * generate_id_token(struct _oidc_config * config, const char * username, json_t * j_user, json_t * j_client, time_t now, time_t auth_time, const char * nonce, json_t * j_amr, const char * access_token) {
  jwt_t * jwt = NULL;
  char * token = NULL, * property = NULL, * amr, at_hash_encoded[128] = {0};
  unsigned char at_hash[128] = {0};
  json_t * j_element, * j_value, * j_amr_obj;
  size_t index, index_p, at_hash_len = 128, at_hash_encoded_len = 0;
  int alg = GNUTLS_DIG_UNKNOWN;
  gnutls_datum_t at_data;
  
  if ((jwt = jwt_dup(config->jwt_key)) != NULL) {
    jwt_add_grant(jwt, "iss", json_string_value(json_object_get(config->j_params, "iss")));
    jwt_add_grant(jwt, "sub", username);
    jwt_add_grant(jwt, "aud", json_string_value(json_object_get(j_client, "client_id")));
    jwt_add_grant_int(jwt, "exp", (now + config->access_token_duration));
    jwt_add_grant_int(jwt, "iat", now);
    jwt_add_grant_int(jwt, "auth_time", auth_time);
    if (o_strlen(nonce)) {
      jwt_add_grant(jwt, "nonce", nonce);
    }
    //jwt_add_grant(jwt, "acr", "plop"); // TODO?
    if (j_amr != NULL && json_array_size(j_amr)) {
      j_amr_obj = json_pack("{sO}", "amr", j_amr);
      amr = json_dumps(j_amr_obj, JSON_COMPACT);
      jwt_add_grants_json(jwt, amr);
      o_free(amr);
      json_decref(j_amr_obj);
    }
    if (access_token != NULL) {
      // Hash access_token using the key size for the hash size (SHA style of course!)
      // take the half left of the has, then encode in base64-url it
      if (config->jwt_key_size == 256) alg = GNUTLS_DIG_SHA256;
      else if (config->jwt_key_size == 384) alg = GNUTLS_DIG_SHA384;
      else if (config->jwt_key_size == 512) alg = GNUTLS_DIG_SHA512;
      if (alg != GNUTLS_DIG_UNKNOWN) {
        at_data.data = (unsigned char*)access_token;
        at_data.size = o_strlen(access_token);
        if (gnutls_fingerprint(alg, &at_data, at_hash, &at_hash_len) == GNUTLS_E_SUCCESS) {
          if (o_base64url_encode(at_hash, at_hash_len/2, (unsigned char *)at_hash_encoded, &at_hash_encoded_len)) {
            jwt_add_grant(jwt, "at_hash", at_hash_encoded);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "generate_id_token - Error o_base64url_encode");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_id_token - Error gnutls_fingerprint");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_id_token - Error digest algorithm size '%d' not supported", config->jwt_key_size);
      }
    }
    jwt_add_grant(jwt, "azp", json_string_value(json_object_get(j_client, "client_id")));
    if (json_object_get(config->j_params, "additional-parameters") != NULL && j_user != NULL) {
      json_array_foreach(json_object_get(config->j_params, "additional-parameters"), index, j_element) {
        if (json_is_string(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter")))) && json_string_length(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter"))))) {
          jwt_add_grant(jwt, json_string_value(json_object_get(j_element, "token-parameter")), json_string_value(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter")))));
        } else if (json_is_array(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter"))))) {
          json_array_foreach(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter"))), index_p, j_value) {
            property = mstrcatf(property, ",%s", json_string_value(j_value));
          }
          if (o_strlen(property)) {
            jwt_add_grant(jwt, json_string_value(json_object_get(j_element, "token-parameter")), property+1); // Skip first ','
          } else {
            jwt_add_grant(jwt, json_string_value(json_object_get(j_element, "token-parameter")), "");
          }
          o_free(property);
          property = NULL;
        }
      }
    }
    token = jwt_encode_str(jwt);
    if (token == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_id_token - oidc - Error jwt_encode_str");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_id_token - oidc - Error jwt_dup");
  }
  jwt_free(jwt);
  return token;
}

static int serialize_access_token(struct _oidc_config * config, uint auth_type, json_int_t gpor_id, const char * username, const char * client_id, const char * scope_list, time_t now, const char * issued_for, const char * user_agent) {
  json_t * j_query, * j_last_id;
  int res, ret, i;
  char * issued_at_clause, ** scope_array = NULL;
  
  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_access_token - Error pthread_mutex_lock");
    ret = G_ERROR;
  } else {
    if (issued_for != NULL && now > 0) {
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        issued_at_clause = msprintf("FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        issued_at_clause = msprintf("TO_TIMESTAMP(%u)", (now));
      } else { // HOEL_DB_TYPE_SQLITE
        issued_at_clause = msprintf("%u", (now));
      }
      j_query = json_pack("{sss{sisososos{ss}ssss}}",
                          "table",
                          GLEWLWYD_PLUGIN_OIDC_TABLE_ACCESS_TOKEN,
                          "values",
                            "gpoa_authorization_type",
                            auth_type,
                            "gpor_id",
                            gpor_id?json_integer(gpor_id):json_null(),
                            "gpoa_username",
                            username!=NULL?json_string(username):json_null(),
                            "gpoa_client_id",
                            client_id!=NULL?json_string(client_id):json_null(),
                            "gpoa_issued_at",
                              "raw",
                              issued_at_clause,
                            "gpoa_issued_for",
                            issued_for,
                            "gpoa_user_agent",
                            user_agent!=NULL?user_agent:"");
      o_free(issued_at_clause);
      res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        j_last_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn);
        if (j_last_id != NULL) {
          if (split_string(scope_list, " ", &scope_array) > 0) {
            j_query = json_pack("{sss[]}",
                                "table",
                                GLEWLWYD_PLUGIN_OIDC_TABLE_ACCESS_TOKEN_SCOPE,
                                "values");
            if (j_query != NULL) {
              for (i=0; scope_array[i] != NULL; i++) {
                json_array_append_new(json_object_get(j_query, "values"), json_pack("{sOss}", "gpoa_id", j_last_id, "gpoas_scope", scope_array[i]));
              }
              res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
              json_decref(j_query);
              if (res == H_OK) {
                ret = G_OK;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_access_token - Error executing j_query (2)");
                ret = G_ERROR_DB;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_access_token - Error json_pack");
              ret = G_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_access_token - Error split_string");
            ret = G_ERROR;
          }
          free_string_array(scope_array);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_access_token - Error h_last_insert_id");
          ret = G_ERROR_DB;
        }
        json_decref(j_last_id);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_access_token - Error executing j_query (1)");
        ret = G_ERROR_DB;
      }
    } else {
      ret = G_ERROR_PARAM;
    }
    pthread_mutex_unlock(&config->insert_lock);
  }
  return ret;
}

static char * generate_access_token(struct _oidc_config * config, const char * username, json_t * j_user, const char * scope_list, time_t now) {
  char salt[OAUTH2_SALT_LENGTH + 1] = {0};
  jwt_t * jwt = NULL;
  char * token = NULL, * property = NULL;
  json_t * j_element, * j_value;
  size_t index, index_p;
  
  if ((jwt = jwt_dup(config->jwt_key)) != NULL) {
    rand_string_nonce(salt, OAUTH2_SALT_LENGTH);
    jwt_add_grant(jwt, "username", username);
    jwt_add_grant(jwt, "salt", salt);
    jwt_add_grant(jwt, "type", "access_token");
    jwt_add_grant_int(jwt, "iat", now);
    jwt_add_grant_int(jwt, "expires_in", config->access_token_duration);
    if (scope_list != NULL) {
      jwt_add_grant(jwt, "scope", scope_list);
    }
    if (json_object_get(config->j_params, "additional-parameters") != NULL && j_user != NULL) {
      json_array_foreach(json_object_get(config->j_params, "additional-parameters"), index, j_element) {
        if (json_is_string(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter")))) && json_string_length(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter"))))) {
          jwt_add_grant(jwt, json_string_value(json_object_get(j_element, "token-parameter")), json_string_value(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter")))));
        } else if (json_is_array(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter"))))) {
          json_array_foreach(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter"))), index_p, j_value) {
            property = mstrcatf(property, ",%s", json_string_value(j_value));
          }
          if (o_strlen(property)) {
            jwt_add_grant(jwt, json_string_value(json_object_get(j_element, "token-parameter")), property+1); // Skip first ','
          } else {
            jwt_add_grant(jwt, json_string_value(json_object_get(j_element, "token-parameter")), "");
          }
          o_free(property);
          property = NULL;
        }
      }
    }
    token = jwt_encode_str(jwt);
    if (token == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_access_token - oidc - Error jwt_encode_str");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_access_token - oidc - Error jwt_dup");
  }
  jwt_free(jwt);
  return token;
}

static json_t * serialize_refresh_token(struct _oidc_config * config, uint auth_type, json_int_t gpoc_id, const char * username, const char * client_id, const char * scope_list, time_t now, json_int_t duration, uint rolling, const char * token, const char * issued_for, const char * user_agent) {
  char * token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token);
  json_t * j_query, * j_return, * j_last_id;
  int res, i;
  char * issued_at_clause, * expires_at_clause, * last_seen_clause, ** scope_array = NULL;
  
  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_refresh_token - Error pthread_mutex_lock");
    j_return = json_pack("{si}", "result", G_ERROR);
  } else {
    if (token_hash != NULL && username != NULL && issued_for != NULL && now > 0 && duration > 0) {
      json_error_t error;
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        issued_at_clause = msprintf("FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        issued_at_clause = msprintf("TO_TIMESTAMP(%u)", (now));
      } else { // HOEL_DB_TYPE_SQLITE
        issued_at_clause = msprintf("%u", (now));
      }
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        last_seen_clause = msprintf("FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        last_seen_clause = msprintf("TO_TIMESTAMP(%u)", (now));
      } else { // HOEL_DB_TYPE_SQLITE
        last_seen_clause = msprintf("%u", (now));
      }
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)duration));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)duration ));
      } else { // HOEL_DB_TYPE_SQLITE
        expires_at_clause = msprintf("%u", (now + (unsigned int)duration));
      }
      j_query = json_pack_ex(&error, 0, "{sss{si so ss so s{ss} s{ss} s{ss} sI si ss ss ss}}",
                          "table",
                          GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                          "values",
                            "gpor_authorization_type",
                            auth_type,
                            "gpoc_id",
                            gpoc_id?json_integer(gpoc_id):json_null(),
                            "gpor_username",
                            username,
                            "gpor_client_id",
                            client_id!=NULL?json_string(client_id):json_null(),
                            "gpor_issued_at",
                              "raw",
                              issued_at_clause,
                            "gpor_last_seen",
                              "raw",
                              last_seen_clause,
                            "gpor_expires_at",
                              "raw",
                              expires_at_clause,
                            "gpor_duration",
                            duration,
                            "gpor_rolling_expiration",
                            rolling,
                            "gpor_token_hash",
                            token_hash,
                            "gpor_issued_for",
                            issued_for,
                            "gpor_user_agent",
                            user_agent!=NULL?user_agent:"");
      o_free(issued_at_clause);
      o_free(expires_at_clause);
      o_free(last_seen_clause);
      res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        j_last_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn);
        if (j_last_id != NULL) {
          if (split_string(scope_list, " ", &scope_array) > 0) {
            j_query = json_pack("{sss[]}",
                                "table",
                                GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN_SCOPE,
                                "values");
            if (j_query != NULL) {
              for (i=0; scope_array[i] != NULL; i++) {
                json_array_append_new(json_object_get(j_query, "values"), json_pack("{sOss}", "gpor_id", j_last_id, "gpors_scope", scope_array[i]));
              }
              res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
              json_decref(j_query);
              if (res == H_OK) {
                j_return = json_pack("{sisO}", "result", G_OK, "gpor_id", j_last_id);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_refresh_token - Error executing j_query (2)");
                j_return = json_pack("{si}", "result", G_ERROR_DB);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_refresh_token - Error json_pack");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_refresh_token - Error split_string");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          free_string_array(scope_array);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_refresh_token - Error h_last_insert_id");
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        json_decref(j_last_id);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_refresh_token - Error executing j_query (1)");
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    }
    o_free(token_hash);
    pthread_mutex_unlock(&config->insert_lock);
  }
  return j_return;
}

static char * generate_refresh_token() {
  char * token = o_malloc((OIDC_REFRESH_TOKEN_LENGTH+1)*sizeof(char));
  
  if (token != NULL) {
    if (rand_string(token, OIDC_REFRESH_TOKEN_LENGTH) == NULL) {
      o_free(token);
      token = NULL;
    }
  }
  return token;
}

static int is_authorization_type_enabled(struct _oidc_config * config, uint authorization_type) {
  return (authorization_type <= 4)?config->auth_type_enabled[authorization_type]:0;
}

static json_t * check_client_valid(struct _oidc_config * config, const char * client_id, const char * client_header_login, const char * client_header_password, const char * redirect_uri, const char * scope_list, unsigned short authorization_type) {
  json_t * j_client, * j_element = NULL, * j_return;
  int uri_found, authorization_type_enabled;
  size_t index = 0;
  
  if (client_id == NULL) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid - Error client_id is NULL");
    return json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (client_header_login != NULL && 0 != o_strcmp(client_header_login, client_id)) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid - Error, client_id specified is different from client_id in the basic auth header");
    return json_pack("{si}", "result", G_ERROR_PARAM);
  }
  j_client = config->glewlwyd_config->glewlwyd_callback_check_client_valid(config->glewlwyd_config, client_id, client_header_password, scope_list);
  if (check_result_value(j_client, G_OK)) {
    if (client_header_password != NULL && json_object_get(json_object_get(j_client, "client"), "confidential") != json_true()) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid - Error, confidential client must be authentified with its password");
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    } else {
      if (redirect_uri != NULL) {
        uri_found = 0;
        json_array_foreach(json_object_get(json_object_get(j_client, "client"), "redirect_uri"), index, j_element) {
          if (0 == o_strcmp(json_string_value(j_element), redirect_uri)) {
            uri_found = 1;
          }
        }
      } else {
        uri_found = 1;
      }
      
      authorization_type_enabled = 0;
      json_array_foreach(json_object_get(json_object_get(j_client, "client"), "authorization_type"), index, j_element) {
        if (authorization_type == GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE && 0 == o_strcmp(json_string_value(j_element), "code")) {
          authorization_type_enabled = 1;
        } else if (authorization_type == GLEWLWYD_AUTHORIZATION_TYPE_TOKEN && 0 == o_strcmp(json_string_value(j_element), "token")) {
          authorization_type_enabled = 1;
        } else if (authorization_type == GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN && 0 == o_strcmp(json_string_value(j_element), "id_token")) {
          authorization_type_enabled = 1;
        } else if (authorization_type == GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN && 0 == o_strcmp(json_string_value(j_element), "refresh_token")) {
          authorization_type_enabled = 1;
          uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
        } else if (authorization_type == GLEWLWYD_AUTHORIZATION_TYPE_DELETE_TOKEN && 0 == o_strcmp(json_string_value(j_element), "delete_token")) {
          authorization_type_enabled = 1;
          uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
        }
      }
      if (!uri_found) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid - Error, redirect_uri '%s' is invalid for the client '%s'", redirect_uri, client_id);
      }
      if (!authorization_type_enabled) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid - Error, authorization type is not enabled for the client '%s'", client_id);
      }
      if (uri_found && authorization_type_enabled) {
        j_return = json_pack("{sisO}", "result", G_OK, "client", json_object_get(j_client, "client"));
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid - Error, client '%s' is invalid", client_id);
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  json_decref(j_client);
  return j_return;
}

static int set_amr_list_for_code(struct _oidc_config * config, json_int_t gpoc_id, json_t * j_amr) {
  json_t * j_query, * j_element;
  int ret;
  size_t index;
  
  if (j_amr != NULL) {
    if (json_array_size(j_amr)) {
      j_query = json_pack("{sss[]}", "table", GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SHEME, "values");
      if (j_query != NULL) {
        json_array_foreach(j_amr, index, j_element) {
          json_array_append_new(json_object_get(j_query, "values"), json_pack("{sIsO}", "gpoc_id", gpoc_id, "gpoch_scheme_module", j_element));
        }
        if (h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL) == H_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "set_amr_list_for_code - Error executing j_query (1)");
          ret = G_ERROR_DB;
        }
        json_decref(j_query);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_amr_list_for_code - Error allocating resources for j_query");
        ret = G_ERROR_MEMORY;
      }
    } else {
      j_query = json_pack("{sss{sIss}}", "table", GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SHEME, "values", "gpoc_id", gpoc_id, "gpoch_scheme_module", "session");
      if (h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL) == H_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_amr_list_for_code - Error executing j_query (2)");
        ret = G_ERROR_DB;
      }
      json_decref(j_query);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_amr_list_for_code - Error param %s", json_dumps(j_amr, JSON_ENCODE_ANY));
    ret = G_ERROR_PARAM;
  }
  return ret;
}

static char * generate_authorization_code(struct _oidc_config * config, const char * username, const char * client_id, const char * scope_list, const char * redirect_uri, const char * issued_for, const char * user_agent, const char * nonce, json_t * j_amr, int auth_type) {
  char * code = NULL, * code_hash = NULL, * expiration_clause, ** scope_array = NULL;
  json_t * j_query, * j_code_id;
  int res, i;
  time_t now;

  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error pthread_mutex_lock");
  } else {
    code = o_malloc(33*sizeof(char));
    if (code != NULL) {
      if (rand_string_nonce(code, 32) != NULL) {
        code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code);
        if (code_hash != NULL) {
          time(&now);
          if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
            expiration_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)config->code_duration ));
          } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
            expiration_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)config->code_duration ));
          } else { // HOEL_DB_TYPE_SQLITE
            expiration_clause = msprintf("%u", (now + (unsigned int)config->code_duration ));
          }
          j_query = json_pack("{sss{sssssssssssssssis{ss}}}",
                              "table",
                              GLEWLWYD_PLUGIN_OIDC_TABLE_CODE,
                              "values",
                                "gpoc_username",
                                username,
                                "gpoc_client_id",
                                client_id,
                                "gpoc_redirect_uri",
                                redirect_uri,
                                "gpoc_code_hash",
                                code_hash,
                                "gpoc_issued_for",
                                issued_for,
                                "gpoc_user_agent",
                                user_agent!=NULL?user_agent:"",
                                "gpoc_nonce",
                                nonce!=NULL?nonce:"",
                                "gpoc_authorization_type",
                                auth_type,
                                "gpoc_expires_at",
                                  "raw",
                                  expiration_clause);
          o_free(expiration_clause);
          res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
          json_decref(j_query);
          if (res != H_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error executing j_query (1)");
            o_free(code);
            code = NULL;
          } else {
            if (scope_list != NULL) {
              j_code_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn);
              if (j_code_id != NULL) {
                j_query = json_pack("{sss[]}",
                                    "table",
                                    GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SCOPE,
                                    "values");
                if (split_string(scope_list, " ", &scope_array) > 0) {
                  for (i=0; scope_array[i] != NULL; i++) {
                    json_array_append_new(json_object_get(j_query, "values"), json_pack("{sOss}", "gpoc_id", j_code_id, "gpocs_scope", scope_array[i]));
                  }
                  res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
                  json_decref(j_query);
                  if (res != H_OK) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error executing j_query (2)");
                    o_free(code);
                    code = NULL;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error split_string");
                  o_free(code);
                  code = NULL;
                }
                free_string_array(scope_array);
                if (set_amr_list_for_code(config, json_integer_value(j_code_id), j_amr) != G_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error set_amr_list_for_code");
                  o_free(code);
                  code = NULL;
                }
                json_decref(j_code_id);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error h_last_insert_id");
                o_free(code);
                code = NULL;
              }
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error glewlwyd_callback_generate_hash");
          o_free(code);
          code = NULL;
        }
        o_free(code_hash);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error rand_string");
        o_free(code);
        code = NULL;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error allocating resources for code");
    }
    pthread_mutex_unlock(&config->insert_lock);
  }

  return code;
}

static char * get_login_url(struct _oidc_config * config, const struct _u_request * request, const char * url, const char * client_id, const char * scope_list) {
  char * plugin_url = config->glewlwyd_config->glewlwyd_callback_get_plugin_external_url(config->glewlwyd_config, json_string_value(json_object_get(config->j_params, "name"))),
       * url_params = generate_query_parameters(request->map_url),
       * url_callback = msprintf("%s/%s?%s", plugin_url, url, url_params),
       * login_url = config->glewlwyd_config->glewlwyd_callback_get_login_url(config->glewlwyd_config, client_id, scope_list, url_callback);
  o_free(plugin_url);
  o_free(url_params);
  o_free(url_callback);
  return login_url;
}

static json_t * get_scope_parameters(struct _oidc_config * config, const char * scope) {
  json_t * j_element = NULL, * j_return = NULL;
  size_t index = 0;
  
  json_array_foreach(json_object_get(config->j_params, "scope"), index, j_element) {
    if (0 == o_strcmp(scope, json_string_value(json_object_get(j_element, "name")))) {
      j_return = json_incref(j_element);
    }
  }
  return j_return;
}

static int disable_authorization_code(struct _oidc_config * config, json_int_t gpoc_id) {
  json_t * j_query;
  int res;
  
  j_query = json_pack("{sss{si}s{sI}}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_CODE,
                      "set",
                        "gpoc_enabled",
                        0,
                      "where",
                        "gpoc_id",
                        gpoc_id);
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc disable_authorization_code - Error executing j_query");
    return G_ERROR_DB;
  }
}

static json_t * get_amr_list_from_code(struct _oidc_config * config, json_int_t gpoc_id) {
  json_t * j_query, * j_result, * j_return, * j_element;
  int ret;
  size_t index;
  
  j_query = json_pack("{sss[s]s{sI}}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SHEME,
                      "columns",
                        "gpoch_scheme_module",
                      "where",
                        "gpoc_id",
                        gpoc_id);
  ret = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (ret == H_OK) {
    if (json_array_size(j_result)) {
      j_return = json_pack("{sis[]}", "result", G_OK, "amr");
      if (j_return != NULL) {
        json_array_foreach(j_result, index, j_element) {
          json_array_append(json_object_get(j_return, "amr"), json_object_get(j_element, "gpoch_scheme_module"));
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_amr_list_from_code - Error allocating resources for j_return");
        j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_amr_list_from_code - Error executing query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static json_t * validate_authorization_code(struct _oidc_config * config, const char * code, const char * client_id, const char * redirect_uri) {
  char * code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code), * expiration_clause = NULL, * scope_list = NULL, * tmp;
  json_t * j_query, * j_result = NULL, * j_result_scope = NULL, * j_return, * j_element = NULL, * j_scope_param;
  int res;
  size_t index = 0;
  json_int_t maximum_duration = config->refresh_token_duration, maximum_duration_override = -1;
  int rolling_refresh = config->refresh_token_rolling, rolling_refresh_override = -1;
  
  if (code_hash != NULL) {
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expiration_clause = o_strdup("> NOW()");
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expiration_clause = o_strdup("> NOW()");
    } else { // HOEL_DB_TYPE_SQLITE
      expiration_clause = o_strdup("> (strftime('%s','now'))");
    }
    j_query = json_pack("{sss[sss]s{sssssssis{ssss}}}",
                        "table",
                        GLEWLWYD_PLUGIN_OIDC_TABLE_CODE,
                        "columns",
                          "gpoc_username AS username",
                          "gpoc_nonce AS nonce",
                          "gpoc_id",
                        "where",
                          "gpoc_client_id",
                          client_id,
                          "gpoc_redirect_uri",
                          redirect_uri,
                          "gpoc_code_hash",
                          code_hash,
                          "gpoc_enabled",
                          1,
                          "gpoc_expires_at",
                            "operator",
                            "raw",
                            "value",
                            expiration_clause);
    o_free(expiration_clause);
    res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        j_query = json_pack("{sss[s]s{sO}}",
                            "table",
                            GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SCOPE,
                            "columns",
                              "gpocs_scope AS name",
                            "where",
                              "gpoc_id",
                              json_object_get(json_array_get(j_result, 0), "gpoc_id"));
        res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result_scope, NULL);
        json_decref(j_query);
        if (res == H_OK && json_array_size(j_result_scope) > 0) {
          if (!json_object_set_new(json_array_get(j_result, 0), "scope", json_array())) {
            json_array_foreach(j_result_scope, index, j_element) {
              if (scope_list == NULL) {
                scope_list = o_strdup(json_string_value(json_object_get(j_element, "name")));
              } else {
                tmp = msprintf("%s %s", scope_list, json_string_value(json_object_get(j_element, "name")));
                o_free(scope_list);
                scope_list = tmp;
              }
              if ((j_scope_param = get_scope_parameters(config, json_string_value(json_object_get(j_element, "name")))) != NULL) {
                json_object_update(j_element, j_scope_param);
                json_decref(j_scope_param);
              }
              if (json_object_get(j_element, "refresh-token-rolling") != NULL && rolling_refresh_override != 0) {
                rolling_refresh_override = json_object_get(j_element, "refresh-token-rolling")==json_true();
              }
              if (json_integer_value(json_object_get(j_element, "refresh-token-duration")) && (json_integer_value(json_object_get(j_element, "refresh-token-duration")) < maximum_duration_override || maximum_duration_override == -1)) {
                maximum_duration_override = json_integer_value(json_object_get(j_element, "refresh-token-duration"));
              }
              json_array_append(json_object_get(json_array_get(j_result, 0), "scope"), j_element);
            }
            if (rolling_refresh_override > -1) {
              rolling_refresh = rolling_refresh_override;
            }
            if (maximum_duration_override > -1) {
              maximum_duration = maximum_duration_override;
            }
            json_object_set_new(json_array_get(j_result, 0), "scope_list", json_string(scope_list));
            json_object_set_new(json_array_get(j_result, 0), "refresh-token-rolling", rolling_refresh?json_true():json_false());
            json_object_set_new(json_array_get(j_result, 0), "refresh-token-duration", json_integer(maximum_duration));
            j_return = json_pack("{sisO}", "result", G_OK, "code", json_array_get(j_result, 0));
            o_free(scope_list);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_authorization_code - Error allocating resources for json_array()");
            j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_authorization_code - Error executing j_query (2)");
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        json_decref(j_result_scope);
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_authorization_code - Error executing j_query (1)");
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_authorization_code - Error glewlwyd_callback_generate_hash");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  o_free(code_hash);
  return j_return;
}

static json_t * validate_session_client_scope(struct _oidc_config * config, const struct _u_request * request, const char * client_id, const char * scope) {
  json_t * j_session, * j_grant, * j_return, * j_scope_session, * j_scope_grant = NULL, * j_group = NULL, * j_scheme;
  const char * scope_session, * group = NULL;
  char * scope_filtered = NULL, * tmp;
  size_t index = 0;
  json_int_t scopes_authorized = 0, scopes_granted = 0;
  int group_allowed;
  
  j_session = config->glewlwyd_config->glewlwyd_callback_check_session_valid(config->glewlwyd_config, request, scope);
  if (check_result_value(j_session, G_OK)) {
    j_grant = config->glewlwyd_config->glewlwyd_callback_get_client_granted_scopes(config->glewlwyd_config, client_id, json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), scope);
    if (check_result_value(j_grant, G_OK)) {
      if (json_array_size(json_object_get(json_object_get(j_grant, "grant"), "scope"))) {
        // Count and store the number of granted scopes
        json_array_foreach(json_object_get(json_object_get(j_grant, "grant"), "scope"), index, j_scope_grant) {
          scopes_granted += json_object_get(j_scope_grant, "granted")==json_true();
        }
        json_object_set_new(json_object_get(j_session, "session"), "scopes_granted", json_integer(scopes_granted));
        json_object_set_new(json_object_get(j_session, "session"), "amr", json_array());
        
        json_object_foreach(json_object_get(json_object_get(j_session, "session"), "scope"), scope_session, j_scope_session) {
          // Evaluate if the scope is granted for the client
          json_array_foreach(json_object_get(json_object_get(j_grant, "grant"), "scope"), index, j_scope_grant) {
            if (0 == o_strcmp(scope_session, json_string_value(json_object_get(j_scope_grant, "name")))) {
              json_object_set(j_scope_session, "granted", json_object_get(j_scope_grant, "granted"));
            }
          }
        
          // Evaluate if the scope is authorized
          if (json_object_get(j_scope_session, "available") == json_true()) {
            if (json_object_get(j_scope_session, "password_required") == json_true() && json_object_get(j_scope_session, "password_authenticated") == json_true()) {
              if (!json_array_has_string(json_object_get(json_object_get(j_session, "session"), "amr"), "password")) {
                json_array_append_new(json_object_get(json_object_get(j_session, "session"), "amr"), json_string("password"));
              }
            }
            if (json_object_get(j_scope_session, "password_required") == json_true() && json_object_get(j_scope_session, "password_authenticated") == json_false()) {
              json_object_set_new(j_scope_session, "authorized", json_false());
            } else if ((json_object_get(j_scope_session, "password_required") == json_true() && json_object_get(j_scope_session, "password_authenticated") == json_true()) || json_object_get(j_scope_session, "password_required") == json_false()) {
              json_object_foreach(json_object_get(j_scope_session, "schemes"), group, j_group) {
                group_allowed = 0;
                json_array_foreach(j_group, index, j_scheme) {
                  if (!group_allowed && json_object_get(j_scheme, "scheme_authenticated") == json_true()) {
                    if (!json_array_has_string(json_object_get(json_object_get(j_session, "session"), "amr"), json_string_value(json_object_get(j_scheme, "scheme_type")))) {
                      json_array_append(json_object_get(json_object_get(j_session, "session"), "amr"), json_object_get(j_scheme, "scheme_type"));
                    }
                    group_allowed = 1;
                  }
                }
                if (!group_allowed) {
                  json_object_set_new(j_scope_session, "authorized", json_false());
                }
              }
              if (json_object_get(j_scope_session, "authorized") == NULL) {
                json_object_set_new(j_scope_session, "authorized", json_true());
                scopes_authorized++;
                if (json_object_get(j_scope_session, "granted") == json_true()) {
                  if (scope_filtered == NULL) {
                    scope_filtered = o_strdup(scope_session);
                  } else {
                    tmp = msprintf("%s %s", scope_filtered, scope_session);
                    o_free(scope_filtered);
                    scope_filtered = tmp;
                  }
                }
              } else if (json_object_get(j_scope_session, "granted") == json_true()) {
                json_object_set_new(json_object_get(j_session, "session"), "authorization_required", json_true());
              }
            } else {
              json_object_set_new(j_scope_session, "authorized", json_false());
            }
          } else {
            json_object_set_new(j_scope_session, "authorized", json_false());
          }
        }
        json_object_set_new(json_object_get(j_session, "session"), "scopes_authorized", json_integer(scopes_authorized));
        if (json_object_get(json_object_get(j_session, "session"), "authorization_required") == NULL) {
          json_object_set_new(json_object_get(j_session, "session"), "authorization_required", json_false());
        }
        if (scope_filtered != NULL) {
          json_object_set_new(json_object_get(j_session, "session"), "scope_filtered", json_string(scope_filtered));
          o_free(scope_filtered);
        } else {
          json_object_set_new(json_object_get(j_session, "session"), "scope_filtered", json_string(""));
          json_object_set_new(json_object_get(j_session, "session"), "authorization_required", json_true());
        }
        if (scopes_authorized && scopes_granted) {
          j_return = json_pack("{sisO}", "result", G_OK, "session", json_object_get(j_session, "session"));
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_session_client_scope - Error glewlwyd_callback_get_client_granted_scopes");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_grant);
  } else if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  } else if (check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_session_client_scope - Error glewlwyd_callback_check_session_valid");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_session);
  return j_return;
}

static json_t * validate_refresh_token(struct _oidc_config * config, const char * refresh_token) {
  json_t * j_return, * j_query, * j_result, * j_result_scope, * j_element;
  char * token_hash, * expires_at_clause;
  int res;
  size_t index = 0;
  time_t now;

  if (refresh_token != NULL) {
    token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, refresh_token);
    if (token_hash != NULL) {
      time(&now);
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
      } else { // HOEL_DB_TYPE_SQLITE
        expires_at_clause = msprintf("> %u", (now));
      }
      j_query = json_pack("{sss[sssssssss]s{sssis{ssss}}}",
                          "table",
                          GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                          "columns",
                            "gpor_id",
                            "gpoc_id",
                            "gpor_username AS username",
                            "gpor_client_id AS client_id",
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_issued_at) AS issued_at", "gpor_issued_at AS issued_at", "EXTRACT(EPOCH FROM gpor_issued_at) AS issued_at"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_expires_at) AS expired_at", "gpor_expires_at AS expired_at", "EXTRACT(EPOCH FROM gpor_expires_at) AS expired_at"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_last_seen) AS last_seen", "gpor_last_seen AS last_seen", "EXTRACT(EPOCH FROM gpor_last_seen) AS last_seen"),
                            "gpor_duration AS duration",
                            "gpor_rolling_expiration",
                          "where",
                            "gpor_token_hash",
                            token_hash,
                            "gpor_enabled",
                            1,
                            "gpor_expires_at",
                              "operator",
                              "raw",
                              "value",
                              expires_at_clause);
      o_free(expires_at_clause);
      res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result) > 0) {
          json_object_set(json_array_get(j_result, 0), "rolling_expiration", json_integer_value(json_object_get(json_array_get(j_result, 0), "gpor_rolling_expiration"))?json_true():json_false());
          json_object_del(json_array_get(j_result, 0), "gpor_rolling_expiration");
          j_query = json_pack("{sss[s]s{sO}}",
                              "table",
                              GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN_SCOPE,
                              "columns",
                                "gpors_scope AS scope",
                              "where",
                                "gpor_id",
                                json_object_get(json_array_get(j_result, 0), "gpor_id"));
          res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result_scope, NULL);
          if (res == H_OK) {
            if (!json_object_set_new(json_array_get(j_result, 0), "scope", json_array())) {
              json_array_foreach(j_result_scope, index, j_element) {
                json_array_append(json_object_get(json_array_get(j_result, 0), "scope"), json_object_get(j_element, "scope"));
              }
              j_return = json_pack("{sisO}", "result", G_OK, "token", json_array_get(j_result, 0));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_refresh_token - Error json_object_set_new");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
            json_decref(j_result_scope);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_refresh_token - Error executing j_query (2)");
            j_return = json_pack("{si}", "result", G_ERROR_DB);
          }
          json_decref(j_query);
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_refresh_token - Error executing j_query (1)");
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_refresh_token - Error glewlwyd_callback_generate_hash");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(token_hash);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

static json_t * refresh_token_list_get(struct _oidc_config * config, const char * username, const char * pattern, size_t offset, size_t limit, const char * sort) {
  json_t * j_query, * j_result, * j_return, * j_element = NULL;
  int res;
  size_t index = 0, token_hash_dec_len = 0;
  char * pattern_escaped, * pattern_clause;
  unsigned char token_hash_dec[128];
  
  j_query = json_pack("{sss[ssssssssss]s{ss}sisiss}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                      "columns",
                        "gpor_token_hash",
                        "gpor_authorization_type",
                        "gpor_client_id AS client_id",
                        SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_issued_at) AS issued_at", "gpor_issued_at AS issued_at", "EXTRACT(EPOCH FROM gpor_issued_at) AS issued_at"),
                        SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_expires_at) AS expires_at", "gpor_expires_at AS expires_at", "EXTRACT(EPOCH FROM gpor_expires_at) AS expires_at"),
                        SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_last_seen) AS last_seen", "gpor_last_seen AS last_seen", "EXTRACT(EPOCH FROM gpor_last_seen) AS last_seen"),
                        "gpor_rolling_expiration",
                        "gpor_issued_for AS issued_for",
                        "gpor_user_agent AS user_agent",
                        "gpor_enabled",
                      "where",
                        "gpor_username",
                        username,
                      "offset",
                      offset,
                      "limit",
                      limit,
                      "order_by",
                      "gpor_last_seen DESC");
  if (sort != NULL) {
    json_object_set_new(j_query, "order_by", json_string(sort));
  }
  if (pattern != NULL) {
    pattern_escaped = h_escape_string(config->glewlwyd_config->glewlwyd_config->conn, pattern);
    pattern_clause = msprintf("IN (SELECT gpor_id FROM "GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN" WHERE gpor_user_agent LIKE '%%%s%%' OR gpor_issued_for LIKE '%%%s%%')", pattern_escaped, pattern_escaped);
    json_object_set_new(json_object_get(j_query, "where"), "gpor_id", json_pack("{ssss}", "operator", "raw", "value", pattern_clause));
    o_free(pattern_clause);
    o_free(pattern_escaped);
  }
  res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      json_object_set(j_element, "rolling_expiration", (json_integer_value(json_object_get(j_element, "gpor_rolling_expiration"))?json_true():json_false()));
      json_object_set(j_element, "enabled", (json_integer_value(json_object_get(j_element, "gpor_enabled"))?json_true():json_false()));
      json_object_del(j_element, "gpor_rolling_expiration");
      json_object_del(j_element, "gpor_enabled");
      if (o_base64_2_base64url((unsigned char *)json_string_value(json_object_get(j_element, "gpor_token_hash")), json_string_length(json_object_get(j_element, "gpor_token_hash")), token_hash_dec, &token_hash_dec_len)) {
        json_object_set_new(j_element, "token_hash", json_stringn((char *)token_hash_dec, token_hash_dec_len));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_list_get - Error o_base64_2_base64url");
        json_object_set_new(j_element, "token_hash", json_string("error"));
      }
      json_object_del(j_element, "gpor_token_hash");
      switch(json_integer_value(json_object_get(j_element, "gpor_authorization_type"))) {
        case GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE:
          json_object_set_new(j_element, "authorization_type", json_string("code"));
          break;
        default:
          json_object_set_new(j_element, "authorization_type", json_string("unknown"));
          break;
      }
      json_object_del(j_element, "gpor_authorization_type");
    }
    j_return = json_pack("{sisO}", "result", G_OK, "refresh_token", j_result);
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_list_get - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static int refresh_token_disable(struct _oidc_config * config, const char * username, const char * token_hash) {
  json_t * j_query, * j_result;
  int res, ret;
  unsigned char token_hash_dec[128];
  size_t token_hash_dec_len = 0;
  
  if (o_base64url_2_base64((unsigned char *)token_hash, o_strlen(token_hash), token_hash_dec, &token_hash_dec_len)) {
    j_query = json_pack("{sss[ss]s{ssss%}}",
                        "table",
                        GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                        "columns",
                          "gpor_id",
                          "gpor_enabled",
                        "where",
                          "gpor_username",
                          username,
                          "gpor_token_hash",
                          token_hash_dec,
                          token_hash_dec_len);
    res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gpor_enabled"))) {
          j_query = json_pack("{sss{si}s{ssss%}}",
                              "table",
                              GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                              "set",
                                "gpor_enabled",
                                0,
                              "where",
                                "gpor_username",
                                username,
                                "gpor_token_hash",
                                token_hash_dec,
                                token_hash_dec_len);
          res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "refresh_token_disable - token '[...%s]' disabled", token_hash + (o_strlen(token_hash) - (o_strlen(token_hash)>=8?8:o_strlen(token_hash))));
            ret = G_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_disable - Error executing j_query (2)");
            ret = G_ERROR_DB;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "refresh_token_disable - Error token '[...%s]' already disabled", token_hash + (o_strlen(token_hash) - (o_strlen(token_hash)>=8?8:o_strlen(token_hash))));
          ret = G_ERROR_PARAM;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "refresh_token_disable - Error token '[...%s]' not found", token_hash + (o_strlen(token_hash) - (o_strlen(token_hash)>=8?8:o_strlen(token_hash))));
        ret = G_ERROR_NOT_FOUND;
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_disable - Error executing j_query (1)");
      ret = G_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_disable - Error o_base64url_2_base64");
    ret = G_ERROR_PARAM;
  }
  return ret;
}

static int update_refresh_token(struct _oidc_config * config, json_int_t gpor_id, json_int_t refresh_token_duration, int disable, time_t now) {
  json_t * j_query;
  int res, ret;
  char * expires_at_clause, * last_seen_clause;

  if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
    last_seen_clause = msprintf("FROM_UNIXTIME(%u)", (now));
  } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
    last_seen_clause = msprintf("TO_TIMESTAMP(%u)", now);
  } else { // HOEL_DB_TYPE_SQLITE
    last_seen_clause = msprintf("%u", (now));
  }
  j_query = json_pack("{sss{s{ss}}s{sI}}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                      "set",
                        "gpor_last_seen",
                          "raw",
                          last_seen_clause,
                      "where",
                        "gpor_id",
                        gpor_id);
  o_free(last_seen_clause);
  if (refresh_token_duration) {
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)refresh_token_duration));
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)refresh_token_duration));
    } else { // HOEL_DB_TYPE_SQLITE
      expires_at_clause = msprintf("%u", (now + (unsigned int)refresh_token_duration));
    }
    json_object_set_new(json_object_get(j_query, "set"), "gpor_expires_at", json_pack("{ss}", "raw", expires_at_clause));
    o_free(expires_at_clause);
  }
  if (disable) {
    json_object_set_new(json_object_get(j_query, "set"), "gpor_enabled", json_integer(0));
  }
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc update_refresh_token - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static char * get_state_param(const char * state_value) {
  char * state_encoded, * state_param;
  
  if (state_value == NULL) {
    state_param = o_strdup("");
  } else {
    state_encoded = url_encode(state_value);
    state_param = msprintf("&state=%s", state_encoded);
    o_free(state_encoded);
  }
  return state_param;
}

static json_t * validate_endpoint_auth(const struct _u_request * request, struct _u_response * response, void * user_data, int auth_type) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  char * redirect_url = NULL, * issued_for = NULL, ** scope_list = NULL, * state_param;
  json_t * j_session = NULL, * j_client = NULL;
  json_t * j_return;
  
  state_param = get_state_param(u_map_get(get_map(request), "state"));
  
  // Let's use again the loop do {} while (false); to avoid too much embeded if statements
  do {
    // Check if client is allowed to perform this request
    j_client = check_client_valid(config, u_map_get(get_map(request), "client_id"), request->auth_basic_user, request->auth_basic_password, u_map_get(get_map(request), "redirect_uri"), u_map_get(get_map(request), "scope"), GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE);
    if (!check_result_value(j_client, G_OK)) {
      // client is not authorized
      response->status = 302;
      redirect_url = msprintf("%s%serror=unauthorized_client%s%s", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"), (u_map_get(get_map(request), "state")!=NULL?"&state=":""), (u_map_get(get_map(request), "state")!=NULL?u_map_get(get_map(request), "state"):""));
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }

    // Check if the query parameter 'g_continue' exists, otherwise redirect to login page
    if (!u_map_has_key(get_map(request), "g_continue")) {
      // Redirect to login page
      response->status = 302;
      redirect_url = get_login_url(config, request, "auth", u_map_get(get_map(request), "client_id"), u_map_get(get_map(request), "scope"));
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }
    
    // Check if at least one scope has been provided
    if (!o_strlen(u_map_get(get_map(request), "scope"))) {
      // Scope is not allowed for this user
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_auth_endpoint - scope list is missing or empty or scope 'openid' missing");
      response->status = 302;
      redirect_url = msprintf("%s%serror=invalid_scope%s", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"), state_param);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }

    // Split scope list into scope array
    if (!split_string(u_map_get(get_map(request), "scope"), " ", &scope_list)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_auth_endpoint - Error split_string");
      response->status = 302;
      redirect_url = msprintf("%s%sserver_error", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"));
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      j_return = json_pack("{si}", "result", G_ERROR);
      break;
    }

    // Check that the scope 'openid' is provided, otherwise return error
    if (!string_array_has_value((const char **)scope_list, "openid")) {
      // Scope openid missing
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_auth_endpoint - scope 'openid' missing");
      response->status = 302;
      redirect_url = msprintf("%s%serror=invalid_scope%s", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"), state_param);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }

    // Check that the session is valid for this user with this scope list
    j_session = validate_session_client_scope(config, request, u_map_get(get_map(request), "client_id"), u_map_get(get_map(request), "scope"));
    if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
      // Redirect to login page
      response->status = 302;
      redirect_url = get_login_url(config, request, "auth", u_map_get(get_map(request), "client_id"), u_map_get(get_map(request), "scope"));
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    } else if (check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
      // Scope is not allowed for this user
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_auth_endpoint - scope list '%s' is invalid for user '%s'", u_map_get(get_map(request), "scope"), json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")));
      response->status = 302;
      redirect_url = msprintf("%s%serror=invalid_scope%s", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"), state_param);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    } else if (!check_result_value(j_session, G_OK)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_auth_endpoint - Error validate_session_client_scope");
      response->status = 302;
      redirect_url = msprintf("%s%sserver_error", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"));
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }

    // Session may be valid but another level of authentication may be requested
    if (json_object_get(json_object_get(j_session, "session"), "authorization_required") == json_true()) {
      // Redirect to login page
      redirect_url = get_login_url(config, request, "auth", u_map_get(get_map(request), "client_id"), u_map_get(get_map(request), "scope"));
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      response->status = 302;
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }
    
    // User has granted access to the cleaned scope list for this client
    // Generate code, generate the url and redirect to it
    issued_for = get_client_hostname(request);
    if (issued_for == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_auth_endpoint - Error get_client_hostname");
      redirect_url = msprintf("%s%serror=server_error", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"));
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      response->status = 302;
      j_return = json_pack("{si}", "result", G_ERROR);
      break;
    }
    
    // Trigger the use of this session to reset use of some schemes
    if (config->glewlwyd_config->glewlwyd_callback_trigger_session_used(config->glewlwyd_config, request, json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered"))) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_auth_endpoint - Error glewlwyd_callback_trigger_session_used");
      redirect_url = msprintf("%s%sserver_error", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"));
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      response->status = 302;
      j_return = json_pack("{si}", "result", G_ERROR);
      break;
    }
    
    // nonce parameter is required for some authorization types
    if ((auth_type & GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN) && !u_map_has_key(get_map(request), "nonce")) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_auth_endpoint - nonce required");
      redirect_url = msprintf("%s%sinvalid_request", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"));
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      response->status = 302;
      j_return = json_pack("{si}", "result", G_ERROR);
      break;
    }
    
    j_return = json_pack("{sisOsOss}", "result", G_OK, "session", json_object_get(j_session, "session"), "client", json_object_get(j_client, "client"), "issued_for", issued_for);
  } while (0);

  o_free(issued_for);
  o_free(state_param);
  json_decref(j_session);
  json_decref(j_client);
  free_string_array(scope_list);
  
  return j_return;
}

static char get_url_separator(const char * redirect_uri, int implicit_flow) {
  char sep = implicit_flow?'#':'?';
  
  if (o_strchr(redirect_uri, sep) != NULL) {
    sep = '&';
  }
  
  return sep;
}

/**
 * The second step of authentiation code
 * Validates if code, client_id and redirect_uri sent are valid, then returns a token set
 */
static int check_auth_type_access_token_request (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  const char * code = u_map_get(request->map_post_body, "code"), 
             * client_id = u_map_get(request->map_post_body, "client_id"),
             * redirect_uri = u_map_get(request->map_post_body, "redirect_uri");
  char * issued_for = get_client_hostname(request), * id_token;
  json_t * j_code, * j_body, * j_refresh_token, * j_client, * j_user, * j_amr;
  time_t now;
  char * refresh_token = NULL, * access_token = NULL;
  
  if (code == NULL || client_id == NULL || redirect_uri == NULL) {
    response->status = 400;
  } else {
    j_client = check_client_valid(config, client_id, request->auth_basic_user, request->auth_basic_password, redirect_uri, NULL, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE);
    if (check_result_value(j_client, G_OK)) {
      j_code = validate_authorization_code(config, code, client_id, redirect_uri);
      if (check_result_value(j_code, G_OK)) {
        j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, json_string_value(json_object_get(json_object_get(j_code, "code"), "username")));
        if (check_result_value(j_user, G_OK)) {
          time(&now);
          if ((refresh_token = generate_refresh_token()) != NULL) {
            j_refresh_token = serialize_refresh_token(config, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, json_integer_value(json_object_get(json_object_get(j_code, "code"), "gpoc_id")), json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), client_id, json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")), now, json_integer_value(json_object_get(json_object_get(j_code, "code"), "refresh-token-duration")), json_object_get(json_object_get(j_code, "code"), "refresh-token-rolling")==json_true(), refresh_token, issued_for, u_map_get_case(request->map_header, "user-agent"));
            if (check_result_value(j_refresh_token, G_OK)) {
              if ((access_token = generate_access_token(config, json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), json_object_get(j_user, "user"), json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")), now)) != NULL) {
                if (serialize_access_token(config, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, json_integer_value(json_object_get(j_refresh_token, "gpor_id")), json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), client_id, json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")), now, issued_for, u_map_get_case(request->map_header, "user-agent")) == G_OK) {
                  j_amr = get_amr_list_from_code(config, json_integer_value(json_object_get(json_object_get(j_code, "code"), "gpoc_id")));
                  if (check_result_value(j_amr, G_OK)) {
                    if ((id_token = generate_id_token(config, json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), json_object_get(j_user, "user"), json_object_get(j_client, "client"), now, config->glewlwyd_config->glewlwyd_callback_get_session_age(config->glewlwyd_config, request, json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list"))), json_string_value(json_object_get(json_object_get(j_code, "code"), "nonce")), json_object_get(j_amr, "amr"), access_token)) != NULL) {
                      if (serialize_id_token(config, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, id_token, json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), client_id, now, issued_for, u_map_get_case(request->map_header, "user-agent")) == G_OK) {
                        if (disable_authorization_code(config, json_integer_value(json_object_get(json_object_get(j_code, "code"), "gpoc_id"))) == G_OK) {
                          j_body = json_pack("{sssssssisIssss}",
                                                "token_type",
                                                "bearer",
                                                "access_token",
                                                access_token,
                                                "refresh_token",
                                                refresh_token,
                                                "iat",
                                                now,
                                                "expires_in",
                                                config->access_token_duration,
                                                "scope",
                                                json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")),
                                                "id_token",
                                                id_token);
                          ulfius_set_json_body_response(response, 200, j_body);
                          json_decref(j_body);
                        } else {
                          y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error disable_authorization_code");
                          j_body = json_pack("{ss}", "error", "server_error");
                          ulfius_set_json_body_response(response, 500, j_body);
                          json_decref(j_body);
                        }
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error serialize_id_token");
                        j_body = json_pack("{ss}", "error", "server_error");
                        ulfius_set_json_body_response(response, 500, j_body);
                        json_decref(j_body);
                      }
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error serialize_access_token");
                      j_body = json_pack("{ss}", "error", "server_error");
                      ulfius_set_json_body_response(response, 500, j_body);
                      json_decref(j_body);
                    }
                    o_free(id_token);
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error generate_id_token");
                    j_body = json_pack("{ss}", "error", "server_error");
                    ulfius_set_json_body_response(response, 500, j_body);
                    json_decref(j_body);
                  }
                  json_decref(j_amr);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error get_amr_list_from_code");
                  j_body = json_pack("{ss}", "error", "server_error");
                  ulfius_set_json_body_response(response, 500, j_body);
                  json_decref(j_body);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error generate_access_token");
                j_body = json_pack("{ss}", "error", "server_error");
                ulfius_set_json_body_response(response, 500, j_body);
                json_decref(j_body);
              }
              o_free(access_token);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error serialize_refresh_token");
              j_body = json_pack("{ss}", "error", "server_error");
              ulfius_set_json_body_response(response, 500, j_body);
              json_decref(j_body);
            }
            json_decref(j_refresh_token);
            o_free(refresh_token);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error generate_refresh_token");
            j_body = json_pack("{ss}", "error", "server_error");
            ulfius_set_json_body_response(response, 500, j_body);
            json_decref(j_body);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error glewlwyd_plugin_callback_get_user");
          j_body = json_pack("{ss}", "error", "server_error");
          ulfius_set_json_body_response(response, 500, j_body);
          json_decref(j_body);
        }
        json_decref(j_user);
      } else {
        j_body = json_pack("{ss}", "error", "invalid_code");
        ulfius_set_json_body_response(response, 403, j_body);
        json_decref(j_body);
      }
      json_decref(j_code);
    } else {
      j_body = json_pack("{ss}", "error", "unauthorized_client");
      ulfius_set_json_body_response(response, 403, j_body);
      json_decref(j_body);
    }
    json_decref(j_client);
  }
  o_free(issued_for);
  return U_CALLBACK_CONTINUE;
}

/**
 * Get a new access_token from a valid refresh_token
 */
static int get_access_token_from_refresh (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  const char * refresh_token = u_map_get(request->map_post_body, "refresh_token");
  json_t * j_refresh, * json_body, * j_client, * j_user;
  time_t now;
  char * access_token, * scope_joined = NULL, * issued_for;
  int has_error = 0, has_issues = 0;

  if (refresh_token != NULL && o_strlen(refresh_token)) {
    j_refresh = validate_refresh_token(config, refresh_token);
    if (check_result_value(j_refresh, G_OK)) {
      if (json_object_get(json_object_get(j_refresh, "token"), "client_id") != json_null()) {
        j_client = check_client_valid(config, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")), request->auth_basic_user, request->auth_basic_password, NULL, NULL, GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN);
        if (!check_result_value(j_client, G_OK)) {
          has_issues = 1;
        } else if (request->auth_basic_user == NULL && request->auth_basic_password == NULL && json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "oidc get_access_token_from_refresh - client '%s' is invalid or is not confidential", request->auth_basic_user);
          has_issues = 1;
        }
        json_decref(j_client);
      }
      time(&now);
      issued_for = get_client_hostname(request);
      scope_joined = join_json_string_array(json_object_get(json_object_get(j_refresh, "token"), "scope"), " ");
      if (scope_joined == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc get_access_token_from_refresh - Error join_json_string_array");
        has_error = 1;
      }
      if (update_refresh_token(config, json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "gpor_id")), (json_object_get(json_object_get(j_refresh, "token"), "rolling_expiration") == json_true())?json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "duration")):0, 0, now) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc get_access_token_from_refresh - Error update_refresh_token");
        has_error = 1;
      }
      if (!has_error && !has_issues) {
        j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "username")));
        if (check_result_value(j_user, G_OK)) {
          if ((access_token = generate_access_token(config, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "username")), json_object_get(j_user, "user"), scope_joined, now)) != NULL) {
            if (serialize_access_token(config, GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN, 0, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "username")), json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")), scope_joined, now, issued_for, u_map_get_case(request->map_header, "user-agent")) == G_OK) {
              json_body = json_pack("{sssssIss}",
                                    "access_token", access_token,
                                    "token_type", "bearer",
                                    "expires_in", config->access_token_duration,
                                    "scope", scope_joined);
              ulfius_set_json_body_response(response, 200, json_body);
              json_decref(json_body);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc get_access_token_from_refresh - Error serialize_access_token");
              response->status = 500;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc get_access_token_from_refresh - Error generate_client_access_token");
            response->status = 500;
          }
          o_free(access_token);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "oidc get_access_token_from_refresh - Error glewlwyd_plugin_callback_get_user");
          response->status = 500;
        }
        json_decref(j_user);
      } else if (has_issues) {
        response->status = 400;
      } else {
        response->status = 500;
      }
      o_free(issued_for);
    } else if (check_result_value(j_refresh, G_ERROR_NOT_FOUND)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc get_access_token_from_refresh - Error token not found");
      response->status = 400;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc get_access_token_from_refresh - Error validate_refresh_token");
      response->status = 500;
    }
    json_decref(j_refresh);
    o_free(scope_joined);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oidc get_access_token_from_refresh - Error token empty or missing");
    response->status = 400;
  }
  return U_CALLBACK_CONTINUE;
}

/**
 * Invalidate a refresh token
 */
static int delete_refresh_token (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  const char * refresh_token = u_map_get(request->map_post_body, "refresh_token");
  json_t * j_refresh, * j_client;
  time_t now;
  char * issued_for;
  int has_issues = 0;
  
  if (refresh_token != NULL && o_strlen(refresh_token)) {
    j_refresh = validate_refresh_token(config, refresh_token);
    if (check_result_value(j_refresh, G_OK)) {
      if (json_object_get(json_object_get(j_refresh, "token"), "client_id") != json_null()) {
        j_client = check_client_valid(config, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")), request->auth_basic_user, request->auth_basic_password, NULL, NULL, GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN);
        if (!check_result_value(j_client, G_OK)) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "oidc delete_refresh_token - client '%s' is invalid", request->auth_basic_user);
          has_issues = 1;
        } else if (request->auth_basic_user == NULL && request->auth_basic_password == NULL && json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "oidc delete_refresh_token - client '%s' is invalid or is not confidential", request->auth_basic_user);
          has_issues = 1;
        }
        json_decref(j_client);
      }
      if (!has_issues) {
        time(&now);
        issued_for = get_client_hostname(request);
        if (update_refresh_token(config, json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "gpor_id")), 0, 1, now) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc delete_refresh_token - Error update_refresh_token");
          response->status = 500;
        }
        o_free(issued_for);
      } else {
        response->status = 400;
      }
    } else if (check_result_value(j_refresh, G_ERROR_NOT_FOUND)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc delete_refresh_token - token invalid");
      response->status = 400;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc delete_refresh_token - Error validate_refresh_token");
      response->status = 500;
    }
    json_decref(j_refresh);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oidc delete_refresh_token - token missing or empty");
    response->status = 400;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_check_glewlwyd_session_or_token(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  json_t * j_session, * j_user;
  int ret = U_CALLBACK_UNAUTHORIZED;
  
  if (u_map_get(request->map_header, "Authorization") != NULL) {
    return callback_check_glewlwyd_access_token(request, response, (void*)config->glewlwyd_resource_config);
  } else {
    if (o_strlen(u_map_get(request->map_url, "impersonate"))) {
      j_session = config->glewlwyd_config->glewlwyd_callback_check_session_valid(config->glewlwyd_config, request, config->glewlwyd_config->glewlwyd_config->admin_scope);
      if (check_result_value(j_session, G_OK)) {
        j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, u_map_get(request->map_url, "impersonate"));
        if (check_result_value(j_user, G_OK)) {
          response->shared_data = json_pack("{ss}", "username", u_map_get(request->map_url, "impersonate"));
          ret = U_CALLBACK_CONTINUE;
        }
        json_decref(j_user);
      }
      json_decref(j_session);
    } else {
      j_session = config->glewlwyd_config->glewlwyd_callback_check_session_valid(config->glewlwyd_config, request, NULL);
      if (check_result_value(j_session, G_OK)) {
        response->shared_data = json_pack("{ss}", "username", json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")));
        ret = U_CALLBACK_CONTINUE;
      }
      json_decref(j_session);
    }
    return ret;
  }
}

static int callback_oidc_authorization(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  const char * response_type = u_map_get(get_map(request), "response_type");
  int result = U_CALLBACK_CONTINUE;
  char * redirect_url, * state_param = NULL, ** resp_type_array = NULL, * authorization_code = NULL, * access_token = NULL, * id_token = NULL, * expires_in_str = NULL, * query_parameters = NULL;
  json_t * j_auth_result = validate_endpoint_auth(request, response, user_data, 0);
  time_t now;
  int ret, implicit_flow = 1, auth_type = GLEWLWYD_AUTHORIZATION_TYPE_NONE_STORE;
  struct _u_map map_query;

  // state_param kept for error results
  state_param = get_state_param(u_map_get(get_map(request), "state"));

  if (check_result_value(j_auth_result, G_OK)) {
    time(&now);
    ret = G_OK;

    if (split_string(response_type, " ", &resp_type_array)) {
      if (u_map_init(&map_query) == U_OK) {
        if (u_map_get(get_map(request), "state") != NULL) {
          u_map_put(&map_query, "state", u_map_get(get_map(request), "state"));
        }

        if (string_array_size(resp_type_array) == 1 && string_array_has_value((const char **)resp_type_array, "token")) {
          response->status = 302;
          redirect_url = msprintf("%s#error=unsupported_response_type%s", u_map_get(get_map(request), "redirect_uri"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
          ret = G_ERROR_PARAM;
        } else if (string_array_size(resp_type_array) == 1 && string_array_has_value((const char **)resp_type_array, "code")) {
          implicit_flow = 0;
        }

        if (string_array_has_value((const char **)resp_type_array, "code")) {
          auth_type |= GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE_STORE;
        }

        if (string_array_has_value((const char **)resp_type_array, "token")) {
          auth_type |= GLEWLWYD_AUTHORIZATION_TYPE_TOKEN_STORE;
        }

        if (string_array_has_value((const char **)resp_type_array, "id_token")) {
          auth_type |= GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN_STORE;
        }

        if (ret == G_OK && string_array_has_value((const char **)resp_type_array, "code")) {
          if (is_authorization_type_enabled((struct _oidc_config *)user_data, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE) && u_map_get(get_map(request), "redirect_uri") != NULL) {
            // Generates authorization code
            if ((authorization_code = generate_authorization_code(config,
                                                                  json_string_value(json_object_get(json_object_get(json_object_get(j_auth_result, "session"), "user"), "username")), 
                                                                  u_map_get(get_map(request), "client_id"), 
                                                                  json_string_value(json_object_get(json_object_get(j_auth_result, "session"), "scope_filtered")), 
                                                                  u_map_get(get_map(request), "redirect_uri"), 
                                                                  json_string_value(json_object_get(j_auth_result, "issued_for")),
                                                                  u_map_get_case(request->map_header, "user-agent"), 
                                                                  u_map_get(get_map(request), "nonce"), 
                                                                  json_object_get(json_object_get(j_auth_result, "session"), "amr"),
                                                                  auth_type)) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_auth_code_grant - Error generate_authorization_code");
              response->status = 302;
              redirect_url = msprintf("%s%sserver_error", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"));
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
              ret = G_ERROR;
            } else {
              u_map_put(&map_query, "code", authorization_code);
            }
          } else {
            if (u_map_get(get_map(request), "redirect_uri") != NULL) {
              response->status = 302;
              redirect_url = msprintf("%s#error=unsupported_response_type%s", u_map_get(get_map(request), "redirect_uri"), state_param);
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
            } else {
              response->status = 403;
            }
            ret = G_ERROR_PARAM;
          }
        }

        if (ret == G_OK && string_array_has_value((const char **)resp_type_array, "token")) {
          if (is_authorization_type_enabled((struct _oidc_config *)user_data, GLEWLWYD_AUTHORIZATION_TYPE_TOKEN) && u_map_get(get_map(request), "redirect_uri") != NULL) {
            if ((access_token = generate_access_token(config, 
                                                      json_string_value(json_object_get(json_object_get(json_object_get(j_auth_result, "session"), "user"), "username")), 
                                                      json_object_get(json_object_get(j_auth_result, "session"), "user"), 
                                                      json_string_value(json_object_get(json_object_get(j_auth_result, "session"), "scope_filtered")), 
                                                      now)) != NULL) {
              if (serialize_access_token(config, 
                                         auth_type, 
                                         0, 
                                         json_string_value(json_object_get(json_object_get(json_object_get(j_auth_result, "session"), "user"), "username")), 
                                         u_map_get(get_map(request), "client_id"), 
                                         json_string_value(json_object_get(json_object_get(j_auth_result, "session"), "scope_filtered")), 
                                         now, 
                                         json_string_value(json_object_get(j_auth_result, "issued_for")),
                                         u_map_get_case(request->map_header, "user-agent")) != G_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_implicit_grant - Error serialize_access_token");
                response->status = 302;
                redirect_url = msprintf("%s%sserver_error", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"));
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
                ret = G_ERROR;
              } else {
                expires_in_str = msprintf("%" JSON_INTEGER_FORMAT, config->access_token_duration);
                u_map_put(&map_query, "access_token", access_token);
                u_map_put(&map_query, "token_type", "bearer");
                u_map_put(&map_query, "expires_in", expires_in_str);
                u_map_put(&map_query, "scope", json_string_value(json_object_get(json_object_get(j_auth_result, "session"), "scope_filtered")));
                o_free(expires_in_str);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_implicit_grant - Error generate_access_token");
              response->status = 302;
              redirect_url = msprintf("%s%sserver_error", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"));
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
              ret = G_ERROR;
            }
          } else {
            if (u_map_get(get_map(request), "redirect_uri") != NULL) {
              response->status = 302;
              redirect_url = msprintf("%s#error=unsupported_response_type%s", u_map_get(get_map(request), "redirect_uri"), state_param);
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
            } else {
              response->status = 403;
            }
            ret = G_ERROR_PARAM;
          }
        }

        if (ret == G_OK && string_array_has_value((const char **)resp_type_array, "id_token")) {
          if (is_authorization_type_enabled((struct _oidc_config *)user_data, GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN) && u_map_get(get_map(request), "redirect_uri") != NULL) {
            if ((id_token = generate_id_token(config, 
                                              json_string_value(json_object_get(json_object_get(json_object_get(j_auth_result, "session"), "user"), "username")), 
                                              json_object_get(json_object_get(j_auth_result, "session"), "user"), 
                                              json_object_get(j_auth_result, "client"), 
                                              now, 
                                              config->glewlwyd_config->glewlwyd_callback_get_session_age(config->glewlwyd_config, 
                                                                                                         request, 
                                                                                                         json_string_value(json_object_get(json_object_get(j_auth_result, "session"), "scope_filtered"))), 
                                              u_map_get(get_map(request), "nonce"), 
                                              json_object_get(json_object_get(j_auth_result, "session"), "amr"),
                                              NULL)) != NULL) {
              if (serialize_id_token(config, 
                                     GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, 
                                     id_token, 
                                     json_string_value(json_object_get(json_object_get(json_object_get(j_auth_result, "session"), "user"), "username")), 
                                     u_map_get(get_map(request), "client_id"), 
                                     now, 
                                     json_string_value(json_object_get(j_auth_result, "issued_for")), 
                                     u_map_get_case(request->map_header, "user-agent")) != G_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error serialize_id_token");
                response->status = 302;
                redirect_url = msprintf("%s%sserver_error", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"));
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
                ret = G_ERROR;
              } else {
                u_map_put(&map_query, "id_token", id_token);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error serialize_access_token");
              response->status = 302;
              redirect_url = msprintf("%s%sserver_error", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"));
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
              ret = G_ERROR;
            }
          } else {
            if (u_map_get(get_map(request), "redirect_uri") != NULL) {
              response->status = 302;
              redirect_url = msprintf("%s%unsupported_response_type", u_map_get(get_map(request), "redirect_uri"), (o_strchr(u_map_get(get_map(request), "redirect_uri"), '?')!=NULL?"&":"?"));
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
              ret = G_ERROR;
            } else {
              response->status = 403;
            }
            ret = G_ERROR_PARAM;
          }
        }

        if (ret == G_OK) {
          response->status = 302;
          query_parameters = generate_query_parameters(&map_query);
          redirect_url = msprintf("%s%c%s", u_map_get(get_map(request), "redirect_uri"), get_url_separator(u_map_get(get_map(request), "redirect_uri"), implicit_flow), query_parameters);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
          o_free(query_parameters);
        }
        o_free(authorization_code);
        o_free(access_token);
        o_free(id_token);
        u_map_clean(&map_query);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_authorization - Error u_map_init");
        if (u_map_get(get_map(request), "redirect_uri") != NULL) {
          response->status = 302;
          redirect_url = msprintf("%s#error=server_error%s", u_map_get(get_map(request), "redirect_uri"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        } else {
          response->status = 403;
        }
      }
      free_string_array(resp_type_array);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_authorization - Error split_string");
      if (u_map_get(get_map(request), "redirect_uri") != NULL) {
        response->status = 302;
        redirect_url = msprintf("%s#error=server_error%s", u_map_get(get_map(request), "redirect_uri"), state_param);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      } else {
        response->status = 403;
      }
    }
  } else if (!check_result_value(j_auth_result, G_ERROR_PARAM) && !check_result_value(j_auth_result, G_ERROR_UNAUTHORIZED)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_authorization - Error validate_endpoint_auth");
  }
  json_decref(j_auth_result);
  o_free(state_param);

  return result;
}

static int callback_oidc_token(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  const char * grant_type = u_map_get(request->map_post_body, "grant_type");
  int result = U_CALLBACK_CONTINUE;

  if (0 == o_strcmp("authorization_code", grant_type)) {
    if (is_authorization_type_enabled(config, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE)) {
      result = check_auth_type_access_token_request(request, response, user_data);
    } else {
      response->status = 403;
    }
  } else if (0 == o_strcmp("refresh_token", grant_type)) {
    result = get_access_token_from_refresh(request, response, user_data);
  } else if (0 == o_strcmp("delete_token", grant_type)) {
    result = delete_refresh_token(request, response, user_data);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Unknown grant_type '%s'", grant_type);
    response->status = 400;
  }
  return result;
}

static int callback_oidc_get_profile(const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  json_t * j_profile = config->glewlwyd_config->glewlwyd_plugin_callback_get_user_profile(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "username")));
  
  if (check_result_value(j_profile, G_OK)) {
    json_object_del(json_object_get(j_profile, "user"), "scope");
    json_object_del(json_object_get(j_profile, "user"), "enabled");
    json_object_del(json_object_get(j_profile, "user"), "source");
    json_object_del(json_object_get(j_profile, "user"), "last_login");
    ulfius_set_json_body_response(response, 200, json_object_get(j_profile, "user"));
  } else {
    response->status = 404;
  }
  json_decref(j_profile);
  return U_CALLBACK_CONTINUE;
}

static int callback_oidc_refresh_token_list_get(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  size_t offset = 0, limit = GLEWLWYD_DEFAULT_LIMIT_SIZE;
  long int l_converted = 0;
  char * endptr = NULL, * sort = NULL;
  json_t * j_refresh_list;
  
  if (u_map_get(request->map_url, "offset") != NULL) {
    l_converted = strtol(u_map_get(request->map_url, "offset"), &endptr, 10);
    if (!(*endptr) && l_converted > 0) {
      offset = (size_t)l_converted;
    }
  }
  if (u_map_get(request->map_url, "limit") != NULL) {
    l_converted = strtol(u_map_get(request->map_url, "limit"), &endptr, 10);
    if (!(*endptr) && l_converted > 0) {
      limit = (size_t)l_converted;
    }
  }
  if (0 == o_strcmp(u_map_get(request->map_url, "sort"), "authorization_type") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "client_id") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "issued_at") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "last_seen") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "expires_at") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "issued_for") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "user_agent") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "enabled") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "rolling_expiration")) {
    sort = msprintf("gpor_%s%s", u_map_get(request->map_url, "sort"), (u_map_get_case(request->map_url, "desc")!=NULL?" DESC":" ASC"));
  }
  j_refresh_list = refresh_token_list_get(config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), u_map_get(request->map_url, "pattern"), offset, limit, sort);
  if (check_result_value(j_refresh_list, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_refresh_list, "refresh_token"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_refresh_token_list_get - Error refresh_token_list_get");
    response->status = 500;
  }
  o_free(sort);
  json_decref(j_refresh_list);
  return U_CALLBACK_CONTINUE;
}

static int callback_oidc_disable_refresh_token(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  int res;
  
  if ((res = refresh_token_disable(config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), u_map_get(request->map_url, "token_hash"))) == G_ERROR_NOT_FOUND) {
    response->status = 404;
  } else if (res == G_ERROR_PARAM) {
    response->status = 400;
  } else if (res != G_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_disable_refresh_token - Error refresh_token_disable");
    response->status = 500;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_oidc_clean(const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  UNUSED(user_data);
  if (response->shared_data != NULL) {
    json_decref((json_t *)response->shared_data);
  }
  return U_CALLBACK_COMPLETE;
}

static int jwt_autocheck(struct _oidc_config * config) {
  time_t now;
  char * token;
  jwt_t * jwt = NULL;
  int ret;
  
  time(&now);
  token = generate_access_token(config, GLEWLWYD_CHECK_JWT_USERNAME, NULL, GLEWLWYD_CHECK_JWT_SCOPE, now);
  if (token != NULL) {
    if (o_strcmp("sha", json_string_value(json_object_get(config->j_params, "jwt-type"))) == 0) {
      if (jwt_decode(&jwt, token, (const unsigned char *)json_string_value(json_object_get(config->j_params, "key")), json_string_length(json_object_get(config->j_params, "key")))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc jwt_autocheck - oidc - Error jwt_decode");
        ret = G_ERROR_PARAM;
      } else if (jwt_get_alg(jwt) != jwt_get_alg(config->jwt_key)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc jwt_autocheck - oidc - Error algorithm don't match");
        ret = G_ERROR_PARAM;
      } else {
        ret = G_OK;
      }
      jwt_free(jwt);
    } else {
      if (jwt_decode(&jwt, token, (const unsigned char *)json_string_value(json_object_get(config->j_params, "cert")), json_string_length(json_object_get(config->j_params, "cert")))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc jwt_autocheck - oidc - Error jwt_decode");
        ret = G_ERROR_PARAM;
      } else if (jwt_get_alg(jwt) != jwt_get_alg(config->jwt_key)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc jwt_autocheck - oidc - Error algorithm don't match");
        ret = G_ERROR_PARAM;
      } else {
        ret = G_OK;
      }
      jwt_free(jwt);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc jwt_autocheck - oidc - Error generate_access_token");
    ret = G_ERROR;
  }
  o_free(token);
  return ret;
}

static json_t * check_parameters (json_t * j_params) {
  json_t * j_element = NULL, * j_return, * j_error = json_array();
  size_t index = 0;
  int ret = G_OK;
  
  if (j_error != NULL) {
    if (j_params == NULL) {
      json_array_append_new(j_error, json_string("parameters invalid"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "jwt-type") == NULL || !json_is_string(json_object_get(j_params, "jwt-type"))) {
      json_array_append_new(j_error, json_string("jwt-type must be a string and have one of the following values: 'rsa', 'ecdsa', 'sha'"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "iss") == NULL || !json_is_string(json_object_get(j_params, "iss"))) {
      json_array_append_new(j_error, json_string("iss is mandatory must be a non empty string"));
      ret = G_ERROR_PARAM;
    }
    if (0 != o_strcmp("rsa", json_string_value(json_object_get(j_params, "jwt-type"))) &&
               0 != o_strcmp("ecdsa", json_string_value(json_object_get(j_params, "jwt-type"))) &&
               0 != o_strcmp("sha", json_string_value(json_object_get(j_params, "jwt-type")))) {
      json_array_append_new(j_error, json_string("jwt-type must be a string and have one of the following values: 'rsa', 'ecdsa', 'sha'"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "jwt-key-size") == NULL || !json_is_string(json_object_get(j_params, "jwt-key-size"))) {
      json_array_append_new(j_error, json_string("jwt-key-size must be a string and have one of the following values: '256', '384', '512'"));
      ret = G_ERROR_PARAM;
    }
    if (0 != o_strcmp("256", json_string_value(json_object_get(j_params, "jwt-key-size"))) &&
               0 != o_strcmp("384", json_string_value(json_object_get(j_params, "jwt-key-size"))) &&
               0 != o_strcmp("512", json_string_value(json_object_get(j_params, "jwt-key-size")))) {
      json_array_append_new(j_error, json_string("jwt-key-size must be a string and have one of the following values: '256', '384', '512'"));
      ret = G_ERROR_PARAM;
    }
    if ((0 == o_strcmp("rsa", json_string_value(json_object_get(j_params, "jwt-type"))) ||
                0 == o_strcmp("ecdsa", json_string_value(json_object_get(j_params, "jwt-type")))) && 
               (json_object_get(j_params, "key") == NULL || json_object_get(j_params, "cert") == NULL ||
               !json_is_string(json_object_get(j_params, "key")) || !json_is_string(json_object_get(j_params, "cert")) || !json_string_length(json_object_get(j_params, "key")) || !json_string_length(json_object_get(j_params, "cert")))) {
      json_array_append_new(j_error, json_string("Properties 'cert' and 'key' are mandatory and must be strings"));
      ret = G_ERROR_PARAM;
    }
    if (0 == o_strcmp("sha", json_string_value(json_object_get(j_params, "jwt-type"))) &&
              (json_object_get(j_params, "key") == NULL || !json_is_string(json_object_get(j_params, "key")) || !json_string_length(json_object_get(j_params, "key")))) {
      json_array_append_new(j_error, json_string("Property 'key' is mandatory and must be a string"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "access-token-duration") == NULL || !json_is_integer(json_object_get(j_params, "access-token-duration")) || json_integer_value(json_object_get(j_params, "access-token-duration")) <= 0) {
      json_array_append_new(j_error, json_string("Property 'access-token-duration' is optional and must be a non null positive integer"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "refresh-token-duration") == NULL || !json_is_integer(json_object_get(j_params, "refresh-token-duration")) || json_integer_value(json_object_get(j_params, "refresh-token-duration")) <= 0) {
      json_array_append_new(j_error, json_string("Property 'access-token-duration' is optional and must be a non null positive integer"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "refresh-token-rolling") != NULL && !json_is_boolean(json_object_get(j_params, "refresh-token-rolling"))) {
      json_array_append_new(j_error, json_string("Property 'refresh-token-rolling' is optional and must be a non null positive integer"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-code-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-code-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-code-enabled' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-token-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-token-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-token-enabled' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-id-token-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-id-token-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-id-token-enabled' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-refresh-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-refresh-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-refresh-enabled' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "scope") != NULL) {
      if (!json_is_array(json_object_get(j_params, "scope"))) {
        json_array_append_new(j_error, json_string("Property 'scope' is optional and must be an array"));
        ret = G_ERROR_PARAM;
      } else {
        json_array_foreach(json_object_get(j_params, "scope"), index, j_element) {
          if (!json_is_object(j_element)) {
            json_array_append_new(j_error, json_string("'scope' element must be a JSON object"));
            ret = G_ERROR_PARAM;
          } else {
            if (json_object_get(j_element, "name") == NULL || !json_is_string(json_object_get(j_element, "name")) || !json_string_length(json_object_get(j_element, "name"))) {
              json_array_append_new(j_error, json_string("'scope' element must have a property 'name' of type string and non empty"));
              ret = G_ERROR_PARAM;
            } else if (json_object_get(j_element, "refresh-token-rolling") != NULL && !json_is_boolean(json_object_get(j_element, "refresh-token-rolling"))) {
              json_array_append_new(j_error, json_string("'scope' element can have a property 'refresh-token-rolling' of type boolean"));
              ret = G_ERROR_PARAM;
            } else if (json_object_get(j_element, "refresh-token-duration") != NULL && (!json_is_integer(json_object_get(j_element, "refresh-token-duration")) || json_integer_value(json_object_get(j_element, "refresh-token-duration")) <= 0)) {
              json_array_append_new(j_error, json_string("'scope' element can have a property 'refresh-token-duration' of type integer and non null positive value"));
              ret = G_ERROR_PARAM;
            }
          }
        }
      }
    } else if (json_object_get(j_params, "additional-parameters") != NULL) {
      if (!json_is_array(json_object_get(j_params, "additional-parameters"))) {
        json_array_append_new(j_error, json_string("Property 'additional-parameters' is optional and must be an array"));
        ret = G_ERROR_PARAM;
      } else {
        json_array_foreach(json_object_get(j_params, "additional-parameters"), index, j_element) {
          if (!json_is_object(j_element)) {
            json_array_append_new(j_error, json_string("'additional-parameters' element must be a JSON object"));
            ret = G_ERROR_PARAM;
          } else {
            if (json_object_get(j_element, "user-parameter") == NULL || !json_is_string(json_object_get(j_element, "user-parameter")) || !json_string_length(json_object_get(j_element, "user-parameter"))) {
              json_array_append_new(j_error, json_string("'additional-parameters' element must have a property 'user-parameter' of type string and non empty"));
              ret = G_ERROR_PARAM;
            } else if (json_object_get(j_element, "token-parameter") == NULL || !json_is_string(json_object_get(j_element, "token-parameter")) || !json_string_length(json_object_get(j_element, "token-parameter"))) {
              json_array_append_new(j_error, json_string("'additional-parameters' element must have a property 'token-parameter' of type string and non empty, forbidden values are: 'username', 'salt', 'type', 'iat', 'expires_in', 'scope'"));
              ret = G_ERROR_PARAM;
            } else if (0 == o_strcmp(json_string_value(json_object_get(j_element, "token-parameter")), "username") || 
                       0 == o_strcmp(json_string_value(json_object_get(j_element, "token-parameter")), "salt") || 
                       0 == o_strcmp(json_string_value(json_object_get(j_element, "token-parameter")), "type") || 
                       0 == o_strcmp(json_string_value(json_object_get(j_element, "token-parameter")), "iat") || 
                       0 == o_strcmp(json_string_value(json_object_get(j_element, "token-parameter")), "expires_in") || 
                       0 == o_strcmp(json_string_value(json_object_get(j_element, "token-parameter")), "scope")) {
              json_array_append_new(j_error, json_string("'additional-parameters' element must have a property 'token-parameter' of type string and non empty, forbidden values are: 'username', 'salt', 'type', 'iat', 'expires_in', 'scope'"));
              ret = G_ERROR_PARAM;
            }
          }
        }
      }
    }
    if (json_array_size(j_error) && ret == G_ERROR_PARAM) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
    } else {
      j_return = json_pack("{si}", "result", ret);
    }
    json_decref(j_error);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "check_parameters oidc - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

json_t * plugin_module_load(struct config_plugin * config) {
  UNUSED(config);
  return json_pack("{si ss ss ss s{ s{sssos[sss]} s{sssos[sss]} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ss so s{ssso} s{ssso} }}}",
                   "result",
                   G_OK,
                   
                   "name",
                   "oidc",
                   
                   "display_name",
                   "Glewlwyd OpenID Connect Plugin",
                   
                   "description",
                   "Plugin for Glewlwyd OpenID Connect workflow",
                   
                   "parameters",
                     "jwt-type",
                       "type",
                       "list",
                       "mandatory",
                       json_true(),
                       "values",
                         "rsa",
                         "ecdsa",
                         "sha",
                         
                     "jwt-key-size",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       "values",
                         "256",
                         "384",
                         "512",
                         
                     "key",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       
                     "cert",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       
                     "access-token-duration",
                       "type",
                       "number",
                       "mandatory",
                       json_true(),
                       
                     "refresh-token-duration",
                       "type",
                       "number",
                       "mandatory",
                       json_true(),
                       
                     "code-token-duration",
                       "type",
                       "number",
                       "mandatory",
                       json_true(),
                       
                     "refresh-token-rolling",
                       "type",
                       "boolean",
                       "default",
                       json_false(),
                       
                     "auth-type-code-enabled",
                       "type",
                       "boolean",
                       "mandatory",
                       json_true(),
                       
                     "auth-type-implicit-enabled",
                       "type",
                       "boolean",
                       "mandatory",
                       json_true(),
                       
                     "auth-type-password-enabled",
                       "type",
                       "boolean",
                       "mandatory",
                       json_true(),
                       
                     "auth-type-client-enabled",
                       "type",
                       "boolean",
                       "mandatory",
                       json_true(),
                       
                     "auth-type-refresh-enabled",
                       "type",
                       "boolean",
                       "mandatory",
                       json_true(),
                       
                     "scope",
                       "type",
                       "array",
                       "mandatory",
                       json_false(),
                       "format",
                         "type",
                         "string",
                         "mandatory",
                         json_true(),
                       "rolling-refresh",
                         "type",
                         "boolean",
                         "mandatory",
                         json_false());
}

int plugin_module_unload(struct config_plugin * config) {
  UNUSED(config);
  return G_OK;
}

json_t * plugin_module_init(struct config_plugin * config, const char * name, json_t * j_parameters, void ** cls) {
  const unsigned char * key;
  jwt_alg_t alg = 0;
  pthread_mutexattr_t mutexattr;
  json_t * j_return, * j_result;
  
  y_log_message(Y_LOG_LEVEL_INFO, "Init plugin Glewlwyd OpenID Connect");
  *cls = o_malloc(sizeof(struct _oidc_config));
  if (*cls != NULL) {
    pthread_mutexattr_init ( &mutexattr );
    pthread_mutexattr_settype( &mutexattr, PTHREAD_MUTEX_RECURSIVE );
    if (pthread_mutex_init(&((struct _oidc_config *)*cls)->insert_lock, &mutexattr) != 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc plugin_module_init - Error initializing insert_lock");
      o_free(*cls);
      *cls = NULL;
      j_return = json_pack("{si}", "result", G_ERROR);
    } else {
      ((struct _oidc_config *)*cls)->name = name;
      ((struct _oidc_config *)*cls)->jwt_key = NULL;
      ((struct _oidc_config *)*cls)->j_params = json_incref(j_parameters);
      json_object_set_new(((struct _oidc_config *)*cls)->j_params, "name", json_string(name));
      ((struct _oidc_config *)*cls)->glewlwyd_config = config;
      ((struct _oidc_config *)*cls)->glewlwyd_resource_config = o_malloc(sizeof(struct _glewlwyd_resource_config));
      if (((struct _oidc_config *)*cls)->glewlwyd_resource_config != NULL) {
        ((struct _oidc_config *)*cls)->glewlwyd_resource_config->method = G_METHOD_HEADER;
        ((struct _oidc_config *)*cls)->glewlwyd_resource_config->oauth_scope = NULL;
        ((struct _oidc_config *)*cls)->glewlwyd_resource_config->realm = NULL;
        j_result = check_parameters(((struct _oidc_config *)*cls)->j_params);
        if (check_result_value(j_result, G_OK)) {
          ((struct _oidc_config *)*cls)->access_token_duration = json_integer_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "access-token-duration"));
          if (!((struct _oidc_config *)*cls)->access_token_duration) {
            ((struct _oidc_config *)*cls)->access_token_duration = GLEWLWYD_ACCESS_TOKEN_EXP_DEFAULT;
          }
          ((struct _oidc_config *)*cls)->refresh_token_duration = json_integer_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "refresh-token-duration"));
          if (!((struct _oidc_config *)*cls)->refresh_token_duration) {
            ((struct _oidc_config *)*cls)->refresh_token_duration = GLEWLWYD_REFRESH_TOKEN_EXP_DEFAULT;
          }
          ((struct _oidc_config *)*cls)->code_duration = json_integer_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "code-duration"));
          if (!((struct _oidc_config *)*cls)->code_duration) {
            ((struct _oidc_config *)*cls)->code_duration = GLEWLWYD_CODE_EXP_DEFAULT;
          }
          if (json_object_get(((struct _oidc_config *)*cls)->j_params, "refresh-token-rolling") != NULL) {
            ((struct _oidc_config *)*cls)->refresh_token_rolling = json_object_get(((struct _oidc_config *)*cls)->j_params, "refresh-token-rolling")==json_true()?1:0;
          } else {
            ((struct _oidc_config *)*cls)->refresh_token_rolling = 0;
          }
          ((struct _oidc_config *)*cls)->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE] = json_object_get(((struct _oidc_config *)*cls)->j_params, "auth-type-code-enabled")==json_true()?1:0;
          ((struct _oidc_config *)*cls)->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_TOKEN] = json_object_get(((struct _oidc_config *)*cls)->j_params, "auth-type-token-enabled")==json_true()?1:0;
          ((struct _oidc_config *)*cls)->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN] = json_object_get(((struct _oidc_config *)*cls)->j_params, "auth-type-id-token-enabled")==json_true()?1:0;
          ((struct _oidc_config *)*cls)->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN] = json_object_get(((struct _oidc_config *)*cls)->j_params, "auth-type-refresh-enabled")==json_true()?1:0;
          if (!jwt_new(&((struct _oidc_config *)*cls)->jwt_key)) {
            if (0 == o_strcmp("rsa", json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "jwt-type")))) {
              key = (const unsigned char *)json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "key"));
              if (0 == o_strcmp("256", json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "jwt-key-size")))) {
                ((struct _oidc_config *)*cls)->jwt_key_size = 256;
                alg = JWT_ALG_RS256;
              } else if (0 == o_strcmp("384", json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "jwt-key-size")))) {
                ((struct _oidc_config *)*cls)->jwt_key_size = 384;
                alg = JWT_ALG_RS384;
              } else { // 512
                ((struct _oidc_config *)*cls)->jwt_key_size = 512;
                alg = JWT_ALG_RS512;
              }
            } else if (0 == o_strcmp("ecdsa", json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "jwt-type")))) {
              key = (const unsigned char *)json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "key"));
              if (0 == o_strcmp("256", json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "jwt-key-size")))) {
                ((struct _oidc_config *)*cls)->jwt_key_size = 256;
                alg = JWT_ALG_ES256;
              } else if (0 == o_strcmp("384", json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "jwt-key-size")))) {
                ((struct _oidc_config *)*cls)->jwt_key_size = 384;
                alg = JWT_ALG_ES384;
              } else { // 512
                ((struct _oidc_config *)*cls)->jwt_key_size = 512;
                alg = JWT_ALG_ES512;
              }
            } else { // SHA
              key = (const unsigned char *)json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "key"));
              if (0 == o_strcmp("256", json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "jwt-key-size")))) {
                ((struct _oidc_config *)*cls)->jwt_key_size = 256;
                alg = JWT_ALG_HS256;
              } else if (0 == o_strcmp("384", json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "jwt-key-size")))) {
                ((struct _oidc_config *)*cls)->jwt_key_size = 384;
                alg = JWT_ALG_HS384;
              } else { // 512
                ((struct _oidc_config *)*cls)->jwt_key_size = 256;
                alg = JWT_ALG_HS512;
              }
            }
            if (jwt_set_alg(((struct _oidc_config *)*cls)->jwt_key, alg, key, o_strlen((const char *)key))) {
              json_decref(((struct _oidc_config *)*cls)->j_params);
              jwt_free(((struct _oidc_config *)*cls)->jwt_key);
              o_free(*cls);
              *cls = NULL;
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error jwt_set_alg");
              j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
            } else {
              if (jwt_autocheck(((struct _oidc_config *)*cls)) != G_OK) {
                json_decref(((struct _oidc_config *)*cls)->j_params);
                jwt_free(((struct _oidc_config *)*cls)->jwt_key);
                o_free(*cls);
                *cls = NULL;
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error jwt_autocheck");
                j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "Error jwt_autocheck");
              } else {
                if (0 == o_strcmp("sha", json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "jwt-type")))) {
                  ((struct _oidc_config *)*cls)->glewlwyd_resource_config->jwt_decode_key = o_strdup(json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "key")));
                } else {
                  ((struct _oidc_config *)*cls)->glewlwyd_resource_config->jwt_decode_key = o_strdup(json_string_value(json_object_get(((struct _oidc_config *)*cls)->j_params, "cert")));
                }
                ((struct _oidc_config *)*cls)->glewlwyd_resource_config->jwt_alg = alg;
                // Add endpoints
                y_log_message(Y_LOG_LEVEL_INFO, "Add endpoints with plugin prefix %s", name);
                if (config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_authorization, (void*)*cls) != G_OK || 
                   config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_authorization, (void*)*cls) || 
                   config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "token/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_token, (void*)*cls) || 
                   config->glewlwyd_callback_add_plugin_endpoint(config, "*", name, "profile/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_glewlwyd_session_or_token, (void*)*cls) || 
                   config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_get_profile, (void*)*cls) || 
                   config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "profile/token/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_refresh_token_list_get, (void*)*cls) || 
                   config->glewlwyd_callback_add_plugin_endpoint(config, "DELETE", name, "profile/token/:token_hash", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_disable_refresh_token, (void*)*cls) || 
                   config->glewlwyd_callback_add_plugin_endpoint(config, "*", name, "profile/*", GLEWLWYD_CALLBACK_PRIORITY_CLOSE, &callback_oidc_clean, NULL)) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - oidc - Error adding endpoints");
                  j_return = json_pack("{si}", "result", G_ERROR);
                } else {
                  j_return = json_pack("{si}", "result", G_OK);
                }
              }
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error allocating resources for jwt_key");
            json_decref(((struct _oidc_config *)*cls)->j_params);
            o_free(*cls);
            *cls = NULL;
            j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
          }
        } else if (check_result_value(j_result, G_ERROR_PARAM)) {
          o_free(*cls);
          *cls = NULL;
          j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", json_object_get(j_result, "error"));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error check_parameters");
          o_free(*cls);
          *cls = NULL;
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc plugin_module_init - Error initializing glewlwyd_resource_config");
        o_free(*cls);
        *cls = NULL;
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    }
    pthread_mutexattr_destroy(&mutexattr);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error allocating resources for cls");
    o_free(*cls);
    *cls = NULL;
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

int plugin_module_close(struct config_plugin * config, const char * name, void * cls) {
  if (cls != NULL) {
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "auth/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "token/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "*", name, "profile/*");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "profile/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "profile/token/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "DELETE", name, "profile/token/:token_hash");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "*", name, "profile/*");
    pthread_mutex_destroy(&((struct _oidc_config *)cls)->insert_lock);
    jwt_free(((struct _oidc_config *)cls)->jwt_key);
    json_decref(((struct _oidc_config *)cls)->j_params);
    o_free(((struct _oidc_config *)cls)->glewlwyd_resource_config->jwt_decode_key);
    o_free(((struct _oidc_config *)cls)->glewlwyd_resource_config);
    o_free(cls);
  }
  return G_OK;
}

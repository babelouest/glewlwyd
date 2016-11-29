/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * 
 * token services
 *
 * Copyright 2016 Nicolas Mora <mail@babelouest.org>
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

#include <uuid/uuid.h>

#include "glewlwyd.h"

/**
 * Serialize in the database a print of a refresh_token
 */
int serialize_refresh_token(struct config_elements * config, const char * username, const uint auth_type, const char * ip_source, const char * refresh_token, const char * scope_list, time_t now) {
  json_t * j_query, * j_result;
  int res, to_return;
  char * token_hash, * last_seen_value, * expired_at_value, * scope, * scope_escape, * scope_clause, * save_scope_list, * saveptr;
  json_int_t grt_id;
  
  token_hash = str2md5(refresh_token, strlen(refresh_token));
  last_seen_value = msprintf(config->conn->type==HOEL_DB_TYPE_MARIADB?"FROM_UNIXTIME(%d)":"%d", now);
  expired_at_value = msprintf(config->conn->type==HOEL_DB_TYPE_MARIADB?"FROM_UNIXTIME(%d)":"%d", (now+config->refresh_token_expiration));
  
  if (token_hash != NULL && last_seen_value != NULL && expired_at_value != NULL) {
    j_query = json_pack("{sss{sssisssss{ss}s{ss}}}",
              "table",
              GLEWLWYD_TABLE_REFRESH_TOKEN,
              "values",
                "grt_hash",
                token_hash,
                "grt_authorization_type",
                auth_type,
                "grt_username",
                username,
                "grt_ip_source",
                ip_source,
                "grt_last_seen",
                  "raw",
                  last_seen_value,
                "grt_expired_at",
                  "raw",
                  expired_at_value);
    free(last_seen_value);
    free(expired_at_value);
    
    if (j_query != NULL) {
      res = h_insert(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (config->use_scope) {
          j_query = json_pack("{sss[s]s{ss}}",
                              "table",
                              GLEWLWYD_TABLE_REFRESH_TOKEN,
                              "columns",
                                "grt_id",
                              "where",
                                "grt_hash",
                                token_hash);
          res = h_select(config->conn, j_query, &j_result, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            grt_id = json_integer_value(json_object_get(json_array_get(j_result, 0), "grt_id"));
            json_decref(j_result);
            j_query = json_pack("{sss[]}",
                                "table",
                                GLEWLWYD_TABLE_REFRESH_TOKEN_SCOPE,
                                "values");
            save_scope_list = nstrdup(scope_list);
            scope = strtok_r(save_scope_list, " ", &saveptr);
            while (scope != NULL) {
              scope_escape = h_escape_string(config->conn, scope);
              scope_clause = msprintf("(SELECT `gs_id` FROM `%s` WHERE `gs_name` = '%s')", GLEWLWYD_TABLE_SCOPE, scope_escape);
              json_array_append_new(json_object_get(j_query, "values"), json_pack("{sIss}", "grt_id", grt_id, "gs_id", scope_clause));
              free(scope_clause);
              free(scope_escape);
              scope = strtok_r(NULL, " ", &saveptr);
            }
            free(save_scope_list);
            
            if (json_array_size(json_object_get(j_query, "values")) > 0) {
              res = h_insert(config->conn, j_query, NULL);
              json_decref(j_query);
              if (res == H_OK) {
                to_return = G_OK;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - Error executing query insert scope");
                to_return = G_ERROR_DB;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - Error no scope given");
              to_return = G_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - Error executing query select");
            to_return = G_ERROR_DB;
          }
        } else {
          to_return = G_OK;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - Error executing query insert");
        to_return = G_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - Error allocating resources for j_query");
      to_return = G_ERROR;
    }
    free(token_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - Error allocating resources for token_hash or last_seen_value or expired_at_value");
    free(last_seen_value);
    free(expired_at_value);
    free(token_hash);
    to_return = G_ERROR;
  }
  return to_return;
}

/**
 * Serialize in the database a print of an access_token
 */
int serialize_access_token(struct config_elements * config, const uint auth_type, const char * ip_source, const char * refresh_token, const char * scope_list) {
  json_t * j_query;
  int res, ret;
  char * refresh_token_hash = NULL, 
       * refresh_token_hash_escaped = NULL, * grt_id_clause = NULL;
  
  if (refresh_token != NULL) {
    refresh_token_hash = str2md5(refresh_token, strlen(refresh_token));
    refresh_token_hash_escaped = h_escape_string(config->conn, refresh_token_hash);
    
    j_query = json_pack("{sss{s{ss}}s{ss}}",
              "table",
              GLEWLWYD_TABLE_REFRESH_TOKEN,
              "set",
                "grt_last_seen",
                  "raw",
                  "NOW()",
              "where",
                "grt_hash",
                refresh_token_hash_escaped);
    if (j_query != NULL) {
      res = h_update(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        grt_id_clause = msprintf("(SELECT `grt_id` FROM `g_refresh_token` WHERE `grt_hash` = '%s')", refresh_token_hash_escaped);
        j_query = json_pack("{sss{sisss{ss}}}",
                  "table",
                  GLEWLWYD_TABLE_ACCESS_TOKEN,
                  "values",
                    "gat_authorization_type",
                    auth_type,
                    "gat_ip_source",
                    ip_source,
                    "grt_id",
                     "raw",
                     grt_id_clause
        );
        res = h_insert(config->conn, j_query, NULL);
        json_decref(j_query);
        free(grt_id_clause);
        if (res == H_OK) {
          ret = G_OK;
        } else {
          ret = G_ERROR_DB;
        }
      } else {
        ret = G_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "serialize_access_token - Error allocating resources for j_query");
      ret = G_ERROR;
    }
    free(refresh_token_hash);
    free(refresh_token_hash_escaped);
  } else {
    j_query = json_pack("{sss{siss}}",
              "table",
              GLEWLWYD_TABLE_ACCESS_TOKEN,
              "values",
                "gat_authorization_type",
                auth_type,
                "gat_ip_source",
                ip_source
    );
    res = h_insert(config->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      ret = G_OK;
    } else {
      ret = G_ERROR_DB;
    }
  }
  return ret;
}

/**
 * Generates a refresh_token from the specified parameters that are considered valid
 */
char * generate_refresh_token(struct config_elements * config, const char * username, const uint auth_type, const char * ip_source, const char * scope_list, time_t now) {
  jwt_t * jwt;
  char * token = NULL;
  
  jwt = jwt_dup(config->jwt);
  if (jwt != NULL) {
    // Build jwt payload
    jwt_add_grant(jwt, "username", username);
    jwt_add_grant(jwt, "type", "refresh_token");
    jwt_add_grant_int(jwt, "iat", now);
    jwt_add_grant_int(jwt, "expires_in", config->access_token_expiration);
    if (config->use_scope && scope_list != NULL) {
      jwt_add_grant(jwt, "scope", scope_list);
    }
    token = jwt_encode_str(jwt);
    if (token != NULL) {
      if (serialize_refresh_token(config, username, auth_type, ip_source, token, scope_list, now) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_refresh_token - Error serializing token");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_refresh_token - generating token");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_refresh_token - Error cloning jwt");
  }
  jwt_free(jwt);
  return token;
}

/**
 * Generates a session_token from the specified parameters that are considered valid
 */
char * generate_session_token(struct config_elements * config, const char * username, const char * ip_source, time_t now) {
  jwt_t * jwt;
  char * token = NULL;
  
  jwt = jwt_dup(config->jwt);
  if (jwt != NULL) {
    // Build jwt payload
    jwt_add_grant(jwt, "username", username);
    jwt_add_grant(jwt, "type", "session_token");
    jwt_add_grant_int(jwt, "iat", now);
    jwt_add_grant_int(jwt, "expires_in", config->session_expiration);
    token = jwt_encode_str(jwt);
    if (token == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_session_token - generating token");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_session_token - Error cloning jwt");
  }
  jwt_free(jwt);
  return token;
}

/**
 * Generates a access_token from the specified parameters that are considered valid
 */
char * generate_access_token(struct config_elements * config, const char * refresh_token, const char * username, const uint auth_type, const char * ip_source, const char * scope_list, time_t now) {
  jwt_t * jwt;
  char * token = NULL;
  
  jwt = jwt_dup(config->jwt);
  if (jwt != NULL) {
    // Build jwt payload
    jwt_add_grant(jwt, "username", username);
    jwt_add_grant(jwt, "type", "access_token");
    jwt_add_grant_int(jwt, "iat", now);
    jwt_add_grant_int(jwt, "expires_in", config->access_token_expiration);
    if (config->use_scope && scope_list != NULL) {
      jwt_add_grant(jwt, "scope", scope_list);
    }
    token = jwt_encode_str(jwt);
    if (token != NULL) {
      if (serialize_access_token(config, auth_type, ip_source, refresh_token, scope_list) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_access_token - Error serializing token");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_access_token - Error generating token");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_access_token - Error cloning jwt");
  }
  jwt_free(jwt);
  return token;
}

/**
 * Generates a client_access_token from the specified parameters that are considered valid
 */
char * generate_client_access_token(struct config_elements * config, const char * client_id, const char * ip_source, time_t now) {
  jwt_t * jwt;
  char * token = NULL;
  
  jwt = jwt_dup(config->jwt);
  if (jwt != NULL) {
    // Build jwt payload
    jwt_add_grant(jwt, "client_id", client_id);
    jwt_add_grant(jwt, "type", "client_token");
    jwt_add_grant_int(jwt, "iat", now);
    jwt_add_grant_int(jwt, "expires_in", config->access_token_expiration);
    token = jwt_encode_str(jwt);
    if (token != NULL) {
      if (serialize_access_token(config, GLEWLWYD_AUHORIZATION_TYPE_CLIENT_CREDENTIALS, ip_source, NULL, NULL) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_client_access_token - Error serializing token");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_client_access_token - Error generating token");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_client_access_token - Error cloning jwt");
  }
  jwt_free(jwt);
  return token;
}

/**
 * Generates a authorization code from the specified parameters that are considered valid
 */
char * generate_authorization_code(struct config_elements * config, const char * username, const char * client_id, const char * scope_list, const char * redirect_uri, const char * ip_source) {
  uuid_t uuid;
  char * code_value = malloc(37*sizeof(char)), * code_hash, * clause_client_id, * clause_redirect_uri, * clause_scope, * escape;
  char * save_scope_list, * scope, * saveptr;
  json_t * j_query, * j_result;
  int res;
  json_int_t gco_id;
  
  if (username != NULL && client_id != NULL && redirect_uri != NULL && ip_source != NULL) {
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, code_value);
    code_hash = str2md5(code_value, strlen(code_value));
    
    escape = h_escape_string(config->conn, client_id);
    clause_client_id = msprintf("(SELECT `gc_id` FROM `%s` WHERE `gc_client_id` = '%s')", GLEWLWYD_TABLE_CLIENT, escape);
    free(escape);
    
    escape = h_escape_string(config->conn, redirect_uri);
    clause_redirect_uri = msprintf("(SELECT `gru_id` FROM `%s` WHERE `gru_uri` = '%s')", GLEWLWYD_TABLE_REDIRECT_URI, escape);
    free(escape);
    
    j_query = json_pack("{sss{sssssss{ss}s{ss}}}",
                        "table",
                        GLEWLWYD_TABLE_CODE,
                        "values",
                          "gco_code_hash",
                          code_hash,
                          "gco_ip_source",
                          ip_source,
                          "gco_username",
                          username,
                          "gc_id",
                            "raw",
                            clause_client_id,
                          "gru_id",
                            "raw",
                            clause_redirect_uri);
    free(clause_client_id);
    free(clause_redirect_uri);
    res = h_insert(config->conn, j_query, NULL);
    json_decref(j_query);
    
    if (res == H_OK) {
      j_query = json_pack("{sss[s]s{ss}}",
                          "table",
                          GLEWLWYD_TABLE_CODE,
                          "columns",
                            "gco_id",
                          "where",
                            "gco_code_hash",
                            code_hash);
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      
      if (res == H_OK) {
        gco_id = json_integer_value(json_object_get(json_array_get(j_result, 0), "gco_id"));
        json_decref(j_result);
        j_query = json_pack("{sss[]}",
                            "table",
                            GLEWLWYD_TABLE_CODE_SCOPE,
                            "values");
        save_scope_list = nstrdup(scope_list);
        scope = strtok_r(save_scope_list, " ", &saveptr);
        while (scope != NULL) {
          escape = h_escape_string(config->conn, scope);
          clause_scope = msprintf("(SELECT `gs_id` FROM `%s` WHERE `gs_name` = '%s')", GLEWLWYD_TABLE_SCOPE, escape);
          json_array_append_new(json_object_get(j_query, "values"), json_pack("{sIs{ss}}", "gco_id", gco_id, "gs_id", "raw", clause_scope));
          free(clause_scope);
          free(escape);
          scope = strtok_r(NULL, " ", &saveptr);
        }
        
        if (json_array_size(json_object_get(j_query, "values")) > 0) {
          res = h_insert(config->conn, j_query, NULL);
          json_decref(j_query);
          if (res != H_OK) {
            free(code_value);
            code_value = NULL;
            y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - Error insert into %s", GLEWLWYD_TABLE_CODE_SCOPE);
          }
        }
        free(save_scope_list);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - Error getting id from %s", GLEWLWYD_TABLE_CODE);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - Error insert into %s", GLEWLWYD_TABLE_CODE);
    }
    free(code_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - Error input arameters");
  }
  return code_value;
}

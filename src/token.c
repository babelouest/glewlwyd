/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * Provides Json Web Tokens (jwt)
 * 
 * Token services
 *
 * Copyright 2016-2017 Nicolas Mora <mail@babelouest.org>
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
#include <string.h>

#include "glewlwyd.h"

/**
 * Serialize in the database a print of a refresh_token
 */
int serialize_refresh_token(struct config_elements * config, const char * client_id, const char * username, const uint auth_type, const char * ip_source, const char * refresh_token, const char * scope_list, time_t now) {
  json_t * j_query, * j_result;
  int res, to_return;
  char * token_hash, * last_seen_value, * expired_at_value, * scope, * scope_escape, * scope_clause, * save_scope_list, * saveptr = NULL;
  json_int_t grt_id;
  
  token_hash = generate_hash(config, config->hash_algorithm, refresh_token);
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
    o_free(last_seen_value);
    o_free(expired_at_value);
    
    if (j_query != NULL) {
      if (client_id != NULL) {
        json_object_set_new(json_object_get(j_query, "values"), "gc_client_id", json_string(client_id));
      }
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
            save_scope_list = o_strdup(scope_list);
            scope = strtok_r(save_scope_list, " ", &saveptr);
            while (scope != NULL) {
              scope_escape = h_escape_string(config->conn, scope);
              scope_clause = msprintf("(SELECT `gs_id` FROM `%s` WHERE `gs_name` = '%s')", GLEWLWYD_TABLE_SCOPE, scope_escape);
              json_array_append_new(json_object_get(j_query, "values"), json_pack("{sIs{ss}}", "grt_id", grt_id, "gs_id", "raw", scope_clause));
              o_free(scope_clause);
              o_free(scope_escape);
              scope = strtok_r(NULL, " ", &saveptr);
            }
            o_free(save_scope_list);
            
            if (json_array_size(json_object_get(j_query, "values")) > 0) {
              res = h_insert(config->conn, j_query, NULL);
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
            json_decref(j_query);
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
    o_free(token_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - Error allocating resources for token_hash or last_seen_value or expired_at_value");
    o_free(last_seen_value);
    o_free(expired_at_value);
    o_free(token_hash);
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
    refresh_token_hash = generate_hash(config, config->hash_algorithm, refresh_token);
    refresh_token_hash_escaped = h_escape_string(config->conn, refresh_token_hash);
    
    j_query = json_pack("{sss{s{ss}}s{ss}}",
              "table",
              GLEWLWYD_TABLE_REFRESH_TOKEN,
              "set",
                "grt_last_seen",
                  "raw",
                  (config->conn->type==HOEL_DB_TYPE_MARIADB?"NOW()":"strftime('%s','now')"),
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
        o_free(grt_id_clause);
        if (res == H_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "serialize_access_token - Error executing j_query (insert 1)");
          ret = G_ERROR_DB;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "serialize_access_token - Error executing j_query (update)");
        ret = G_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "serialize_access_token - Error allocating resources for j_query");
      ret = G_ERROR;
    }
    o_free(refresh_token_hash);
    o_free(refresh_token_hash_escaped);
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
      y_log_message(Y_LOG_LEVEL_ERROR, "serialize_access_token - Error executing j_query (insert 2)");
      ret = G_ERROR_DB;
    }
  }
  return ret;
}

/**
 * Generates a refresh_token from the specified parameters that are considered valid
 */
char * generate_refresh_token(struct config_elements * config, const char * client_id, const char * username, const uint auth_type, const char * ip_source, const char * scope_list, time_t now) {
  jwt_t * jwt;
  char * token = NULL;
  char salt[GLEWLWYD_SALT_LENGTH + 1] = {0};
  
  jwt = jwt_dup(config->jwt);
  if (jwt != NULL) {
    // Build jwt payload
    rand_string(salt, GLEWLWYD_SALT_LENGTH);
    jwt_add_grant(jwt, "salt", salt);
    jwt_add_grant(jwt, "username", username);
    jwt_add_grant(jwt, "type", "refresh_token");
    jwt_add_grant_int(jwt, "iat", now);
    jwt_add_grant_int(jwt, "expires_in", config->access_token_expiration);
    if (config->use_scope && scope_list != NULL) {
      jwt_add_grant(jwt, "scope", scope_list);
    }
    if (client_id != NULL) {
      jwt_add_grant(jwt, "client_id", client_id);
    }
    token = jwt_encode_str(jwt);
    if (token != NULL) {
      if (serialize_refresh_token(config, client_id, username, auth_type, ip_source, token, scope_list, now) != G_OK) {
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
  char salt[GLEWLWYD_SALT_LENGTH + 1] = {0};
  
  jwt = jwt_dup(config->jwt);
  if (jwt != NULL) {
    // Build jwt payload
    rand_string(salt, GLEWLWYD_SALT_LENGTH);
    jwt_add_grant(jwt, "salt", salt);
    jwt_add_grant(jwt, "username", username);
    jwt_add_grant(jwt, "type", "session_token");
    jwt_add_grant_int(jwt, "iat", now);
    jwt_add_grant_int(jwt, "expires_in", config->session_expiration);
    token = jwt_encode_str(jwt);
    if (token == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_session_token - generating token");
    } else {
      if (serialize_session_token(config, username, ip_source, token, now) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_session_token - Error serializing session_token");
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_session_token - Error cloning jwt");
  }
  jwt_free(jwt);
  return token;
}

/**
 * Serialize in the database a print of a session_token
 */
int serialize_session_token(struct config_elements * config, const char * username, const char * ip_source, const char * session_token, time_t now) {
  json_t * j_query;
  int res;
  char * session_hash = generate_hash(config, config->hash_algorithm, session_token), * last_seen_value, * expired_at_value;
  
  if (session_token != NULL) {
    last_seen_value = msprintf(config->conn->type==HOEL_DB_TYPE_MARIADB?"FROM_UNIXTIME(%d)":"%d", now);
    expired_at_value = msprintf(config->conn->type==HOEL_DB_TYPE_MARIADB?"FROM_UNIXTIME(%d)":"%d", (now+config->session_expiration));
    j_query = json_pack("{sss{sssss{ss}s{ss}s{ss}ss}}",
                        "table",
                        GLEWLWYD_TABLE_SESSION,
                        "values",
                          "gss_hash",
                          session_hash,
                          "gss_username",
                          username,
                          "gss_issued_at",
                            "raw",
                            last_seen_value,
                          "gss_last_seen",
                            "raw",
                            last_seen_value,
                          "gss_expired_at",
                            "raw",
                            expired_at_value,
                          "gss_ip_source",
                          ip_source);
    o_free(session_hash);
    o_free(last_seen_value);
    o_free(expired_at_value);
    res = h_insert(config->conn, j_query, NULL);
    json_decref(j_query);
    return (res==H_OK?G_OK:G_ERROR_DB);
  } else {
    return G_ERROR_PARAM;
  }
}

/**
 * Generates a access_token from the specified parameters that are considered valid
 */
char * generate_access_token(struct config_elements * config, const char * refresh_token, const char * username, const uint auth_type, const char * ip_source, const char * scope_list, time_t now) {
  jwt_t * jwt;
  char * token = NULL;
  char salt[GLEWLWYD_SALT_LENGTH + 1] = {0};
  
  jwt = jwt_dup(config->jwt);
  if (jwt != NULL) {
    // Build jwt payload
    rand_string(salt, GLEWLWYD_SALT_LENGTH);
    jwt_add_grant(jwt, "salt", salt);
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
char * generate_client_access_token(struct config_elements * config, const char * client_id, const char * ip_source, const char * scope_list, time_t now) {
  jwt_t * jwt;
  char * token = NULL;
  char salt[GLEWLWYD_SALT_LENGTH + 1] = {0};
  
  jwt = jwt_dup(config->jwt);
  if (jwt != NULL) {
    // Build jwt payload
    rand_string(salt, GLEWLWYD_SALT_LENGTH);
    jwt_add_grant(jwt, "salt", salt);
    jwt_add_grant(jwt, "client_id", client_id);
    jwt_add_grant(jwt, "type", "client_token");
    if (config->use_scope && scope_list != NULL) {
      jwt_add_grant(jwt, "scope", scope_list);
    }
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
  char * code_value = o_malloc(37*sizeof(char)), * code_hash, * clause_scope, * escape;
  char * save_scope_list, * scope, * saveptr = NULL;
  json_t * j_query, * j_result;
  int res;
  json_int_t gco_id;
  
  if (username != NULL && client_id != NULL && redirect_uri != NULL && ip_source != NULL) {
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, code_value);
    code_hash = generate_hash(config, config->hash_algorithm, code_value);
    
    escape = h_escape_string(config->conn, redirect_uri);
    
    j_query = json_pack("{sss{ssssssssss}}",
                        "table",
                        GLEWLWYD_TABLE_CODE,
                        "values",
                          "gco_code_hash",
                          code_hash,
                          "gco_ip_source",
                          ip_source,
                          "gco_username",
                          username,
                          "gc_client_id",
                          client_id,
                          "gco_redirect_uri",
                          escape);
    res = h_insert(config->conn, j_query, NULL);
    o_free(escape);
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
				if (config->use_scope) {
					gco_id = json_integer_value(json_object_get(json_array_get(j_result, 0), "gco_id"));
					json_decref(j_result);
					j_query = json_pack("{sss[]}",
															"table",
															GLEWLWYD_TABLE_CODE_SCOPE,
															"values");
					save_scope_list = o_strdup(scope_list);
					scope = strtok_r(save_scope_list, " ", &saveptr);
					while (scope != NULL) {
						escape = h_escape_string(config->conn, scope);
						clause_scope = msprintf("(SELECT `gs_id` FROM `%s` WHERE `gs_name` = '%s')", GLEWLWYD_TABLE_SCOPE, escape);
						json_array_append_new(json_object_get(j_query, "values"), json_pack("{sIs{ss}}", "gco_id", gco_id, "gs_id", "raw", clause_scope));
						o_free(clause_scope);
						o_free(escape);
						scope = strtok_r(NULL, " ", &saveptr);
					}
					
					if (json_array_size(json_object_get(j_query, "values")) > 0) {
						res = h_insert(config->conn, j_query, NULL);
						json_decref(j_query);
						if (res != H_OK) {
							o_free(code_value);
							code_value = NULL;
							y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - Error insert into %s", GLEWLWYD_TABLE_CODE_SCOPE);
						}
					}
					o_free(save_scope_list);
				} else {
					json_decref(j_result);
				}
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - Error getting id from %s", GLEWLWYD_TABLE_CODE);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - Error insert into %s", GLEWLWYD_TABLE_CODE);
    }
    o_free(code_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - Error input arameters");
  }
  return code_value;
}

/**
 * Validates if a session token is valid
 */
json_t * session_check(struct config_elements * config, const char * session_value) {
  json_t * j_query, * j_result, * j_return, * j_grants = NULL, * j_user;
  char * session_hash, * clause_expired_at, * grants = NULL;
  const char * type;
  int res;
  jwt_t * jwt = NULL;
  time_t now;
  long expiration;
  
  if (session_value != NULL) {
    if (!jwt_decode(&jwt, session_value, (const unsigned char *)config->jwt_decode_key, strlen(config->jwt_decode_key)) && jwt_get_alg(jwt) == jwt_get_alg(config->jwt)) {
      time(&now);
      expiration = jwt_get_grant_int(jwt, "iat") + jwt_get_grant_int(jwt, "expires_in");
      type = jwt_get_grant(jwt, "type");
      if (now < expiration && 0 == o_strcmp(type, "session_token")) {
        session_hash = generate_hash(config, config->hash_algorithm, session_value);
        if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
          clause_expired_at = o_strdup("> NOW()");
        } else {
          clause_expired_at = o_strdup("> (strftime('%s','now'))");
        }
        j_query = json_pack("{sss[s]s{sssis{ssss}}}",
                          "table",
                          GLEWLWYD_TABLE_SESSION,
                          "columns",
                            "gss_id",
                          "where",
                            "gss_hash",
                            session_hash,
                            "gss_enabled",
                            1,
                            "gss_expired_at",
                              "operator",
                              "raw",
                              "value",
                              clause_expired_at);
        o_free(clause_expired_at);
        res = h_select(config->conn, j_query, &j_result, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          if (json_array_size(j_result) > 0) {
            j_query = json_pack("{sss{s{ss}}s{ss}}",
                                "table",
                                GLEWLWYD_TABLE_SESSION,
                                "set",
                                  "gss_last_seen",
                                    "raw",
                                    (config->conn->type==HOEL_DB_TYPE_MARIADB?"NOW()":"(strftime('%s','now'))"),
                                "where",
                                  "gss_hash",
                                  session_hash);
            res = h_update(config->conn, j_query, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              grants = jwt_get_grants_json(jwt, NULL);
              j_grants = json_loads(grants, JSON_DECODE_ANY, NULL);
              o_free(grants);
              if (j_grants != NULL) {
                j_user = get_user(config, jwt_get_grant(jwt, "username"), NULL);
                if (check_result_value(j_user, G_OK)) {
                  if (json_object_get(json_object_get(j_user, "user"), "enabled") == json_true()) {
                    j_return = json_pack("{siso}", "result", G_OK, "grants", j_grants);
                  } else {
                    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
                  }
                } else {
                  j_return = json_pack("{si}", "result", G_ERROR);
                }
                json_decref(j_user);
              } else {
                j_return = json_pack("{si}", "result", G_ERROR);
              }
            } else {
              j_return = json_pack("{si}", "result", G_ERROR_DB);
            }
          } else {
            j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          }
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        o_free(session_hash);
        json_decref(j_result);
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
    jwt_free(jwt);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

/**
 * Validates if an access_token is valid and contains a scope profile
 */
json_t * access_token_check_scope_profile(struct config_elements * config, const char * header_value) {
  json_t * j_return, * j_grants;
  jwt_t * jwt = NULL;
  time_t now;
  long expiration;
  char  * grants;
  const char * type, * token_value;
  int scope_found = 0, count, i;
  char ** scope_list;
  
  if (header_value != NULL) {
    if (strstr(header_value, GLEWLWYD_PREFIX_BEARER) == header_value) {
      token_value = header_value + strlen(GLEWLWYD_PREFIX_BEARER);
      if (!jwt_decode(&jwt, token_value, (const unsigned char *)config->jwt_decode_key, strlen(config->jwt_decode_key)) && jwt_get_alg(jwt) == jwt_get_alg(config->jwt)) {
        time(&now);
        expiration = jwt_get_grant_int(jwt, "iat") + jwt_get_grant_int(jwt, "expires_in");
        type = jwt_get_grant(jwt, "type");
        if (now < expiration && 0 == o_strcmp(type, "access_token")) {
          grants = jwt_get_grants_json(jwt, NULL);
          j_grants = json_loads(grants, JSON_DECODE_ANY, NULL);
          if (j_grants != NULL) {
            count = split_string(json_string_value(json_object_get(j_grants, "scope")), " ", &scope_list);
            for (i=0; count > 0 && scope_list[i] != NULL; i++) {
              if (strcmp(scope_list[i], config->profile_scope) == 0) {
                scope_found = 1;
                break;
              }
            }
            free_string_array(scope_list);
            if (scope_found) {
              j_return = json_pack("{siso}", "result", G_OK, "grants", j_grants);
            } else {
              j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "access_token_check - Error encoding token grants '%s'", grants);
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          o_free(grants);
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
      jwt_free(jwt);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  return j_return;
}

/**
 * Validates if an access_token is valid and contains a scope admin
 */
json_t * access_token_check_scope_admin(struct config_elements * config, const char * header_value) {
  json_t * j_return, * j_grants;
  jwt_t * jwt = NULL;
  time_t now;
  long expiration;
  char  * grants;
  const char * type, * token_value;
  int scope_found = 0, count, i;
  char ** scope_list;
  
  if (header_value != NULL) {
    if (strstr(header_value, GLEWLWYD_PREFIX_BEARER) == header_value) {
      token_value = header_value + strlen(GLEWLWYD_PREFIX_BEARER);
      if (!jwt_decode(&jwt, token_value, (const unsigned char *)config->jwt_decode_key, strlen(config->jwt_decode_key)) && jwt_get_alg(jwt) == jwt_get_alg(config->jwt)) {
        time(&now);
        expiration = jwt_get_grant_int(jwt, "iat") + jwt_get_grant_int(jwt, "expires_in");
        type = jwt_get_grant(jwt, "type");
        if (now < expiration && 0 == o_strcmp(type, "access_token")) {
          grants = jwt_get_grants_json(jwt, NULL);
          j_grants = json_loads(grants, JSON_DECODE_ANY, NULL);
          if (j_grants != NULL) {
            count = split_string(json_string_value(json_object_get(j_grants, "scope")), " ", &scope_list);
            for (i=0; count > 0 && scope_list[i] != NULL; i++) {
              if (strcmp(scope_list[i], config->admin_scope) == 0) {
                scope_found = 1;
                break;
              }
            }
            free_string_array(scope_list);
            if (scope_found) {
              j_return = json_pack("{siso}", "result", G_OK, "grants", j_grants);
            } else {
              j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "access_token_check - Error encoding token grants '%s'", grants);
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          o_free(grants);
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
      jwt_free(jwt);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  return j_return;
}

/**
 * Validates if a session or an access_token is valid
 */
json_t * session_or_access_token_check(struct config_elements * config, const char * session_value, const char * header_value) {
  json_t * j_valid = session_check(config, session_value);
  
  if (check_result_value(j_valid, G_OK)) {
    return j_valid;
  } else {
    json_decref(j_valid);
    return access_token_check_scope_profile(config, header_value);
  }
}

/**
 * Invalidates a session
 */
int session_delete(struct config_elements * config, const char * session_value) {
  json_t * j_query;
  char * session_hash;
  int res;
  
  session_hash = generate_hash(config, config->hash_algorithm, session_value);
  if (session_hash != NULL) {
    j_query = json_pack("{sss{si}s{ss}}",
                        "table",
                        GLEWLWYD_TABLE_SESSION,
                        "set",
                          "gss_enabled",
                          0,
                        "where",
                        "gss_hash",
                        session_hash);
    res = h_update(config->conn, j_query, NULL);
    json_decref(j_query);
    o_free(session_hash);
    return (res==H_OK?G_OK:G_ERROR_DB);
  } else {
    return G_ERROR_PARAM;
  }
}

/**
 * Generates a reset password token, invalidate all other reset password tokens for the same user
 */
char * generate_user_reset_password_token(struct config_elements * config, const char * username, const char * ip_source) {
  json_t * j_query;
  int res;
  char * token = o_malloc(37*sizeof(char)), * token_hash;
  uuid_t uuid;
  
  if (token != NULL) {
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, token);
    token_hash = generate_hash(config, config->hash_algorithm, token);
    if (token_hash != NULL) {
      // Disabling all other reset tokens for the user, just in case
      j_query = json_pack("{sss{si}s{ss}}",
                          "table",
                          GLEWLWYD_TABLE_RESET_PASSWORD,
                          "set",
                            "grp_enabled",
                            0,
                          "where",
                            "grp_username",
                            username);
      res = h_update(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        j_query = json_pack("{sss{ssssss}}",
                            "table",
                            GLEWLWYD_TABLE_RESET_PASSWORD,
                            "values",
                              "grp_username",
                              username,
                              "grp_token",
                              token_hash,
                              "grp_ip_source",
                              ip_source);
        res = h_insert(config->conn, j_query, NULL);
        json_decref(j_query);
        if (res != H_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_user_reset_password_token - Error executing j_query insert");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_user_reset_password_token - Error executing j_query update");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_user_reset_password_token - Error allocating resources for token_hash");
      o_free(token);
      token = NULL;
    }
    o_free(token_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_user_reset_password_token - Error allocating resources for token");
  }
  return token;
}

/**
 * Return the list of refresh_token for the specified user
 */
json_t * get_refresh_token_list(struct config_elements * config, const char * username, int valid, long int offset, long int limit) {
  json_t * j_query, * j_result, * j_return, * j_element;
  size_t index;
  int res;
  
  j_query = json_pack("{sss[sssssss]s{ss}sisiss}",
                      "table",
                      GLEWLWYD_TABLE_REFRESH_TOKEN,
                      "columns",
                        "grt_hash AS token_hash",
                        "grt_authorization_type",
                        config->conn->type==HOEL_DB_TYPE_MARIADB?"UNIX_TIMESTAMP(grt_issued_at) AS issued_at":"grt_issued_at AS issued_at",
                        config->conn->type==HOEL_DB_TYPE_MARIADB?"UNIX_TIMESTAMP(grt_last_seen) AS last_seen":"grt_last_seen AS last_seen",
                        config->conn->type==HOEL_DB_TYPE_MARIADB?"UNIX_TIMESTAMP(grt_expired_at) AS expired_at":"grt_expired_at AS expired_at",
                        "grt_ip_source AS ip_source",
                        "grt_enabled",
                      "where",
                        "grt_username",
                        username,
                      "offset",
                      offset,
                      "limit",
                      limit,
                      "order_by",
                      "issued_at desc");
  if (valid > -1) {
    json_object_set_new(json_object_get(j_query, "where"), "grt_enabled", json_integer(valid));
  }
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      if (json_integer_value(json_object_get(j_element, "grt_enabled")) == 1) {
        json_object_set_new(j_element, "enabled", json_true());
      } else {
        json_object_set_new(j_element, "enabled", json_false());
      }
      json_object_del(j_element, "grt_enabled");
      
      switch(json_integer_value(json_object_get(j_element, "grt_authorization_type"))) {
        case GLEWLWYD_AUHORIZATION_TYPE_AUTHORIZATION_CODE:
          json_object_set_new(j_element, "authorization_type", json_string("authorization_code"));
          break;
        case GLEWLWYD_AUHORIZATION_TYPE_CODE:
          json_object_set_new(j_element, "authorization_type", json_string("code"));
          break;
        case GLEWLWYD_AUHORIZATION_TYPE_IMPLICIT:
          json_object_set_new(j_element, "authorization_type", json_string("implicit"));
          break;
        case GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS:
          json_object_set_new(j_element, "authorization_type", json_string("password"));
          break;
        case GLEWLWYD_AUHORIZATION_TYPE_CLIENT_CREDENTIALS:
          json_object_set_new(j_element, "authorization_type", json_string("celient_credentials"));
          break;
        case GLEWLWYD_AUHORIZATION_TYPE_REFRESH_TOKEN:
          json_object_set_new(j_element, "authorization_type", json_string("refresh"));
          break;
      }
      json_object_del(j_element, "grt_authorization_type");
    }
    j_return = json_pack("{siso}", "result", G_OK, "token", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_refresh_token_list - Error getting token list");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

/**
 * Revoke a refresh_token
 */
int revoke_token(struct config_elements * config, const char * username, const char * token_hash) {
  json_t * j_query, * j_result;
  int res, to_return;
  
  if (username != NULL && token_hash != NULL) {
    j_query = json_pack("{sss[s]s{sssssi}}",
                        "table",
                        GLEWLWYD_TABLE_REFRESH_TOKEN,
                        "columns",
                          "grt_id",
                        "where",
                          "grt_username",
                          username,
                          "grt_hash",
                          token_hash,
                          "grt_enabled",
                          1);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result) > 0) {
        j_query = json_pack("{sss{si}s{sI}}",
                            "table",
                            GLEWLWYD_TABLE_REFRESH_TOKEN,
                            "set",
                              "grt_enabled",
                              0,
                            "where",
                              "grt_id",
                              json_integer_value(json_object_get(json_array_get(j_result, 0), "grt_id")));
        res = h_update(config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          to_return = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "revoke_token - Error revoking token");
          to_return = G_ERROR_DB;
        }
      } else {
        to_return = G_ERROR_NOT_FOUND;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "revoke_token - Error getting token");
      to_return = G_ERROR_DB;
    }
    json_decref(j_result);
  } else {
    to_return = G_ERROR_PARAM;
  }
  
  return to_return;
}

/**
 * Return the list of sessions for the specified user
 */
json_t * get_session_list(struct config_elements * config, const char * username, int valid, long int offset, long int limit) {
  json_t * j_query, * j_result, * j_return, * j_element;
  size_t index;
  int res;
  
  j_query = json_pack("{sss[ssssss]s{ss}sisiss}",
                      "table",
                      GLEWLWYD_TABLE_SESSION,
                      "columns",
                        "gss_hash AS session_hash",
                        config->conn->type==HOEL_DB_TYPE_MARIADB?"UNIX_TIMESTAMP(gss_issued_at) AS issued_at":"gss_issued_at AS issued_at",
                        config->conn->type==HOEL_DB_TYPE_MARIADB?"UNIX_TIMESTAMP(gss_last_seen) AS last_seen":"gss_last_seen AS last_seen",
                        config->conn->type==HOEL_DB_TYPE_MARIADB?"UNIX_TIMESTAMP(gss_expired_at) AS expired_at":"gss_expired_at AS expired_at",
                        "gss_ip_source AS ip_source",
                        "gss_enabled",
                      "where",
                        "gss_username",
                        username,
                      "offset",
                      offset,
                      "limit",
                      limit,
                      "order_by",
                      "issued_at desc");
  if (valid > -1) {
    json_object_set_new(json_object_get(j_query, "where"), "gss_enabled", json_integer(valid));
  }
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      if (json_integer_value(json_object_get(j_element, "gss_enabled")) == 1) {
        json_object_set_new(j_element, "enabled", json_true());
      } else {
        json_object_set_new(j_element, "enabled", json_false());
      }
      json_object_del(j_element, "gss_enabled");
    }
    j_return = json_pack("{siso}", "result", G_OK, "session", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_refresh_token_list - Error getting session list");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

/**
 * Get a specific session
 */
int get_session(struct config_elements * config, const char * username, const char * session_hash) {
  json_t * j_query, * j_result;
  int res, to_return;
  
  j_query = json_pack("{sss[s]s{sssssi}}",
                      "table",
                      GLEWLWYD_TABLE_SESSION,
                      "columns",
                        "gss_id",
                      "where",
                        "gss_username",
                        username,
                        "gss_hash",
                        session_hash,
                        "gss_enabled",
                        1);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result) > 0) {
      to_return = G_OK;
    } else {
      to_return = G_ERROR_NOT_FOUND;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_session - Error getting session");
    to_return = G_ERROR_DB;
  }
  json_decref(j_result);
  
  return to_return;
}

/**
 * Revokes a session
 */
int revoke_session(struct config_elements * config, const char * username, const char * session_hash) {
  json_t * j_query, * j_result;
  int res, to_return;
  
  if (username != NULL && session_hash != NULL) {
    j_query = json_pack("{sss[s]s{sssssi}}",
                        "table",
                        GLEWLWYD_TABLE_SESSION,
                        "columns",
                          "gss_id",
                        "where",
                          "gss_username",
                          username,
                          "gss_hash",
                          session_hash,
                          "gss_enabled",
                          1);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result) > 0) {
        j_query = json_pack("{sss{si}s{sI}}",
                            "table",
                            GLEWLWYD_TABLE_SESSION,
                            "set",
                              "gss_enabled",
                              0,
                            "where",
                              "gss_id",
                              json_integer_value(json_object_get(json_array_get(j_result, 0), "gss_id")));
        res = h_update(config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          to_return = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "revoke_session - Error revoking session");
          to_return = G_ERROR_DB;
        }
      } else {
        to_return = G_ERROR_NOT_FOUND;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "revoke_session - Error getting session");
      to_return = G_ERROR_DB;
    }
    json_decref(j_result);
  } else {
    to_return = G_ERROR_PARAM;
  }
  
  return to_return;
}

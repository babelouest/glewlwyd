/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * 
 * main functions definitions
 *
 * Copyright 2016 Nicolas Mora <mail@babelouest.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation;
 * version 3 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
 
#include <ldap.h>
#include <openssl/md5.h>

#include "glewlwyd.h"

int serialize_refresh_token(struct config_elements * config, const char * username, const uint auth_type, const char * ip_source, const char * refresh_token, time_t now) {
  json_t * j_query;
  int res;
  char * token_hash, * last_seen_value, * expired_at_value;
  
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
    free(token_hash);
    
    if (j_query != NULL) {
      res = h_insert(config->conn, j_query, NULL);
      json_decref(j_query);
      return (res==H_OK?G_OK:G_ERROR_DB);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - Error allocating resources for j_query");
      return G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - Error allocating resources for token_hash or last_seen_value or expired_at_value");
    free(last_seen_value);
    free(expired_at_value);
    free(token_hash);
    return G_ERROR;
  }
}

int serialize_access_token(struct config_elements * config, const uint auth_type, const char * ip_source, const char * refresh_token) {
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
                    "grt_authorization_type",
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
                "grt_authorization_type",
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
 * Authentication check
 * 
 */
json_t * auth_check(struct config_elements * config, const char * username, const char * password, const char * scope_list) {
  json_t * j_res = NULL;
  
  if (username != NULL && password != NULL) {
    if (config->has_auth_ldap) {
      j_res = auth_check_credentials_ldap(config, username, password, scope_list);
    }
    if (config->has_auth_database && (j_res == NULL || json_integer_value(json_object_get(j_res, "result")) != G_OK)) {
      json_decref(j_res);
      j_res = auth_check_credentials_database(config, username, password, scope_list);
    }
  } else {
    j_res = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_res;
}

char * generate_refresh_token(struct config_elements * config, const char * username, const uint auth_type, const char * ip_source, const char * scope_list, time_t now) {
  jwt_t * jwt;
  char * token = NULL;
  
  jwt = jwt_dup(config->jwt);
  if (jwt != NULL) {
    // Build jwt payload
    jwt_add_grant(jwt, "username", username);
    jwt_add_grant_int(jwt, "iat", now);
    jwt_add_grant_int(jwt, "expires_in", config->access_token_expiration);
    if (config->use_scope && scope_list != NULL) {
      jwt_add_grant(jwt, "scope", scope_list);
    }
    token = jwt_encode_str(jwt);
    if (token != NULL) {
      if (serialize_refresh_token(config, username, auth_type, ip_source, token, now) != G_OK) {
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

char * generate_session_token(struct config_elements * config, const char * username, const char * ip_source, const char * scope_list, time_t now) {
  jwt_t * jwt;
  char * token = NULL;
  
  jwt = jwt_dup(config->jwt);
  if (jwt != NULL) {
    // Build jwt payload
    jwt_add_grant(jwt, "username", username);
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

char * generate_access_token(struct config_elements * config, const char * refresh_token, const char * username, const uint auth_type, const char * ip_source, const char * scope_list, time_t now) {
  jwt_t * jwt;
  char * token = NULL;
  
  jwt = jwt_dup(config->jwt);
  if (jwt != NULL) {
    // Build jwt payload
    jwt_add_grant(jwt, "username", username);
    jwt_add_grant_int(jwt, "iat", now);
    jwt_add_grant_int(jwt, "expires_in", config->access_token_expiration);
    if (config->use_scope && scope_list != NULL) {
      jwt_add_grant(jwt, "scope", scope_list);
    }
    token = jwt_encode_str(jwt);
    if (token != NULL) {
      if (serialize_access_token(config, auth_type, ip_source, refresh_token) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_access_token - Error serializing token");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_access_token - generating token");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_access_token - Error cloning jwt");
  }
  jwt_free(jwt);
  return token;
}

json_t * auth_check_scope_database(struct config_elements * config, const char * username, const char * scope_list) {
  json_t * j_query, * j_result, * scope_list_allowed, * j_value;
  int res;
  char * scope, * scope_escaped, * saveptr, * scope_list_escaped = strdup(""), * scope_list_save = nstrdup(scope_list), * login_escaped = h_escape_string(config->conn, username), * scope_list_join;
  char * where_clause, * tmp;
  size_t index;
  
  if (scope_list_save != NULL && login_escaped != NULL && scope_list_escaped != NULL) {
    scope = strtok_r(scope_list_save, " ", &saveptr);
    while (scope != NULL) {
      scope_escaped = h_escape_string(config->conn, scope);
      if (nstrlen(scope_list_escaped) > 0) {
        tmp = msprintf("%s,'%s'", scope_list_escaped, scope_escaped);
        free(scope_list_escaped);
        scope_list_escaped = tmp;
      } else {
        free(scope_list_escaped);
        scope_list_escaped = msprintf("'%s'", scope_escaped);
      }
      free(scope_escaped);
      scope = strtok_r(NULL, " ", &saveptr);
    }
    free(scope_list_save);
    where_clause = msprintf("IN (SELECT gs_id FROM %s WHERE gu_id = (SELECT gu_id FROM %s WHERE gu_login='%s') AND gs_id IN (SELECT gs_id FROM %s WHERE gs_name in (%s)))", GLEWLWYD_TABLE_USER_SCOPE, GLEWLWYD_TABLE_USER, login_escaped, GLEWLWYD_TABLE_SCOPE, scope_list_escaped);
    j_query = json_pack("{sss[s]s{s{ssss}}}",
              "table",
              GLEWLWYD_TABLE_SCOPE,
              "columns",
                "gs_name",
              "where",
                "gs_id",
                  "operator",
                  "raw",
                  "value",
                  where_clause);
    free(scope_list_escaped);
    free(login_escaped);
    free(where_clause);
    if (j_query != NULL) {
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result) > 0) {
          scope_list_join = strdup("");
          json_array_foreach(j_result, index, j_value) {
            if (nstrlen(scope_list_join) > 0) {
              tmp = msprintf("%s %s", scope_list_join, json_string_value(json_object_get(j_value, "gs_name")));
              free(scope_list_join);
              scope_list_join = tmp;
            } else {
              free(scope_list_join);
              scope_list_join = strdup(json_string_value(json_object_get(j_value, "gs_name")));
            }
          }
          scope_list_allowed = json_pack("{siss}", "result", G_OK, "scope", scope_list_join);
          free(scope_list_join);
        } else {
          scope_list_allowed = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Error executing sql query");
        scope_list_allowed = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error allocating resources for j_query");
      scope_list_allowed = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error allocating resources for scope_list_save or login_escaped or scope_list_escaped");
    scope_list_allowed = json_pack("{si}", "result", G_ERROR);
  }
  return scope_list_allowed;
}

/**
 * Check if the username and password specified are valid as a database user
 * On success, return a json array with all scope values available
 */
json_t * auth_check_credentials_database(struct config_elements * config, const char * username, const char * password, const char * scope_list) {
  json_t * j_query, * j_result;
  char * escaped, * str_password;
  int res, res_size;
  
  if (nstrlen(username) <= 0 || nstrlen(password) <= 0) {
    return json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  } else {
    escaped = h_escape_string(config->conn, password);
    if (config->conn->type == HOEL_DB_TYPE_SQLITE) {
      // TODO Add SHA1 or MD5 hashing function
      str_password = msprintf("= '%s'", password);
    } else {
      str_password = msprintf("= PASSWORD('%s')", escaped);
    }
    free(escaped);
    j_query = json_pack("{sss{sss{ssss}si}}",
                        "table",
                        GLEWLWYD_TABLE_USER,
                        "where",
                          "gu_login",
                          username,
                          "gu_password",
                            "operator",
                            "raw",
                            "value",
                            str_password,
                          "gu_enabled",
                          1);
    
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    free(str_password);
    if (res == H_OK) {
      res_size = json_array_size(j_result);
      json_decref(j_result);
      if (res_size == 0) {
        return json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      } else if (res_size == 1) {
        if (config->use_scope) {
          return auth_check_scope_database(config, username, scope_list);
        } else {
          return json_pack("{si}", "result", G_OK);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Error in database while getting credentials (obviously)");
        return json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error in database while executing query");
      return json_pack("{si}", "result", G_ERROR_DB);
    }
  }
}

/**
 * Check if the username and password specified are valid as a LDAP user
 */
json_t * auth_check_credentials_ldap(struct config_elements * config, const char * username, const char * password, const char * scope_list) {
  LDAP * ldap;
  LDAPMessage * answer, * entry;
  
  int  result, result_login;
  int  ldap_version   = LDAP_VERSION3;
  int  scope          = LDAP_SCOPE_SUBTREE;
  char * filter       = NULL;
  char * attrs[]      = {"memberOf", NULL, NULL};
  int  attrsonly      = 0;
  char * user_dn      = NULL;
  json_t * res        = NULL;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred;
  struct berval *servcred;

  cred.bv_val = config->auth_ldap->bind_passwd;
  cred.bv_len = strlen(config->auth_ldap->bind_passwd);

  if (ldap_initialize(&ldap, config->auth_ldap->uri) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error initializing ldap");
    res = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error setting ldap protocol version");
    res = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if ((result = ldap_sasl_bind_s(ldap, config->auth_ldap->bind_dn, ldap_mech, &cred, NULL, NULL, &servcred)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error binding to ldap server mode %s: %s", ldap_mech, ldap_err2string(result));
    res = json_pack("{si}", "result", G_ERROR_PARAM);
  } else {
    // Connection successful, doing ldap search
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter, config->auth_ldap->login_property, username);
    
    if (config->use_scope) {
      attrs[1] = config->auth_ldap->scope_property;
    }
    if (filter != NULL && (result = ldap_search_ext_s(ldap, config->auth_ldap->base_search, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search: %s", ldap_err2string(result));
      res = json_pack("{si}", "result", G_ERROR_PARAM);
    } else if (ldap_count_entries(ldap, answer) == 0) {
      // No result found for username
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap, no entry for this username");
      res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    } else {
      // ldap found some results, getting the first one
      entry = ldap_first_entry(ldap, answer);
      
      if (entry == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "ldap search: error getting first result");
        res = json_pack("{si}", "result", G_ERROR);
      } else {
        if (config->use_scope) {
          struct berval ** values = ldap_get_values_len(ldap, entry, config->auth_ldap->scope_property);
          char * new_scope_list = strdup("");
          int i;
          
          for (i=0; i < ldap_count_values_len(values); i++) {
            char * str_value = malloc(values[i]->bv_len + 1);
            char * scope_list_dup = strdup(scope_list);
            char * token, * save_ptr = NULL;
            
            snprintf(str_value, values[i]->bv_len + 1, "%s", values[i]->bv_val);
            token = strtok_r(scope_list_dup, " ", &save_ptr);
            while (token != NULL) {
              if (0 == strcmp(token, str_value)) {
                if (strlen(new_scope_list) > 0) {
                  char * tmp = msprintf("%s %s", new_scope_list, token);
                  free(new_scope_list);
                  new_scope_list = tmp;
                } else {
                  free(new_scope_list);
                  new_scope_list = strdup(token);
                }
              }
              token = strtok_r(NULL, " ", &save_ptr);
            }
            free(scope_list_dup);
            free(str_value);
          }
          ldap_value_free_len(values);
          if (nstrlen(new_scope_list) > 0) {
            // Testing the first result to username with the given password
            user_dn = ldap_get_dn(ldap, entry);
            cred.bv_val = (char *)password;
            cred.bv_len = strlen(password);
            result_login = ldap_sasl_bind_s(ldap, user_dn, ldap_mech, &cred, NULL, NULL, &servcred);
            ldap_memfree(user_dn);
            if (result_login == LDAP_SUCCESS) {
              res = json_pack("{siss}", "result", G_OK, "scope", new_scope_list);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap, bind error");
              res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
            }
          } else {
            // User hasn't all of part of the scope requested, sending unauthorized answer
            y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap, scope incorrect");
            res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          }
        } else {
          // Testing the first result to username with the given password
          user_dn = ldap_get_dn(ldap, entry);
          cred.bv_val = (char *)password;
          cred.bv_len = strlen(password);
          result_login = ldap_sasl_bind_s(ldap, user_dn, ldap_mech, &cred, NULL, NULL, &servcred);
          ldap_memfree(user_dn);
          if (result_login == LDAP_SUCCESS) {
            res = json_pack("{si}", "result", G_OK);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap, bind error");
            res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          }
        }
      }
    }
    free(filter);
    ldap_msgfree(answer);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  return res;
}

int is_authorization_type_enabled(struct config_elements * config, uint authorization_type) {
  json_t * j_query, * j_result;
  int res, to_return;
  
  j_query = json_pack("{sss{sisi}}",
            "table",
            GLEWLWYD_TABLE_AUTHORIZATION_TYPE,
            "where",
            "got_code",
            authorization_type,
            "got_enabled",
            1);
  if (j_query != NULL) {
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result) > 0) {
        to_return = G_OK;
      } else {
        to_return = G_ERROR_UNAUTHORIZED;
      }
      json_decref(j_result);
      return to_return;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_authorization_type_enabled - Error executing j_query");
      return G_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_authorization_type_enabled - Error allocating resources for j_query");
    return G_ERROR_MEMORY;
  }
}

int client_check(struct config_elements * config, const uint auth_type, const char * client_id, const char * redirect_uri) {
  json_t * j_result;
  int res, to_return;
  char * redirect_uri_escaped, * client_id_escaped, * query;
  
  if (client_id != NULL && redirect_uri != NULL) {
    // I don't want to build a huge j_query since there are 4 tables involved so I'll build my own sql query
    redirect_uri_escaped = h_escape_string(config->conn, redirect_uri);
    client_id_escaped = h_escape_string(config->conn, client_id);
    query = msprintf("SELECT `%s`.`gc_id` FROM `%s`, `%s`, `%s` WHERE `%s`.`gc_id`=`%s`.`gc_id` AND `%s`.`gc_id`=`%s`.`gc_id`\
                      AND `%s`.`gc_enabled`=1 AND `%s`.`gru_enabled`=1 AND `%s`.`gru_uri`='%s' AND `%s`.`gc_client_id`='%s' \
                      AND `%s`.`got_id`=(SELECT `got_id` FROM `%s` WHERE `got_code`=%d);", 
            GLEWLWYD_TABLE_CLIENT,
            
            GLEWLWYD_TABLE_CLIENT,
            GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE,
            GLEWLWYD_TABLE_REDIRECT_URI,
              
            GLEWLWYD_TABLE_CLIENT,
            GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE,
            
            GLEWLWYD_TABLE_CLIENT,
            GLEWLWYD_TABLE_REDIRECT_URI,
            
            GLEWLWYD_TABLE_CLIENT,
            
            GLEWLWYD_TABLE_REDIRECT_URI,
            
            GLEWLWYD_TABLE_REDIRECT_URI,
            redirect_uri_escaped,
            
            GLEWLWYD_TABLE_CLIENT,
            client_id_escaped,
            
            GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE,
            GLEWLWYD_TABLE_AUTHORIZATION_TYPE,
            auth_type);
    res = h_execute_query_json(config->conn, query, &j_result);
    free(query);
    free(redirect_uri_escaped);
    free(client_id_escaped);
    if (res == H_OK) {
      if (json_array_size(j_result) > 0) {
        to_return = G_OK;
      } else {
        to_return = G_ERROR_UNAUTHORIZED;
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_check - Error executing query");
      to_return = G_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error params, client_id is %s, redirect_uri is %s", client_id, redirect_uri);
    to_return = G_ERROR_PARAM;
  }
  return to_return;
}

/**
 *
 * Session is checked by validating the cookie named after config->session_key
 * The cookie value is a jwt itself
 *
 */
json_t * session_check(struct config_elements * config, const struct _u_request * request) {
  json_t * j_result;
  const char * session_value = u_map_get(request->map_cookie, config->session_key);
  jwt_t * jwt;
  long expiration;
  time_t now;
  
  y_log_message(Y_LOG_LEVEL_DEBUG, "session is %s", session_value);
  if (session_value != NULL) {
    if (!jwt_decode(&jwt, session_value, (const unsigned char *)config->jwt_decode_key, strlen(config->jwt_decode_key)) && jwt_get_alg(jwt) == jwt_get_alg(config->jwt)) {
      time(&now);
      expiration = jwt_get_grant_int(jwt, "iat") + jwt_get_grant_int(jwt, "expires_in");
      y_log_message(Y_LOG_LEVEL_DEBUG, "now is %ld, expires is %ld", now, expiration);
      if (now < expiration) {
        j_result = json_pack("{si}", "result", G_OK);
      } else {
        j_result = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "session invalid");
      j_result = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
    jwt_free(jwt);
  } else {
    j_result = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  
  return j_result;
}

json_t * auth_check_scope(struct config_elements * config, const char * username, const char * scope_list) {
  json_t * j_res = NULL;
  
  if (config->has_auth_ldap) {
    j_res = auth_check_scope_ldap(config, username, scope_list);
  }
  if (config->has_auth_database && (j_res == NULL || check_result_value(j_res, G_OK))) {
    json_decref(j_res);
    j_res = auth_check_scope_database(config, username, scope_list);
  }
  return j_res;
}

json_t * auth_check_scope_ldap(struct config_elements * config, const char * username, const char * scope_list) {
  LDAP * ldap;
  LDAPMessage * answer, * entry;
  
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  int  scope          = LDAP_SCOPE_SUBTREE;
  char * filter       = NULL;
  char * attrs[]      = {"memberOf", NULL, NULL};
  int  attrsonly      = 0;
  json_t * res        = NULL;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred;
  struct berval *servcred;

  cred.bv_val = config->auth_ldap->bind_passwd;
  cred.bv_len = strlen(config->auth_ldap->bind_passwd);

  if (ldap_initialize(&ldap, config->auth_ldap->uri) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error initializing ldap");
    res = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error setting ldap protocol version");
    res = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if ((result = ldap_sasl_bind_s(ldap, config->auth_ldap->bind_dn, ldap_mech, &cred, NULL, NULL, &servcred)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error binding to ldap server mode %s: %s", ldap_mech, ldap_err2string(result));
    res = json_pack("{si}", "result", G_ERROR_PARAM);
  } else {
    // Connection successful, doing ldap search
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter, config->auth_ldap->login_property, username);
    
    if (config->use_scope) {
      attrs[1] = config->auth_ldap->scope_property;
    }
    if (filter != NULL && (result = ldap_search_ext_s(ldap, config->auth_ldap->base_search, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search: %s", ldap_err2string(result));
      res = json_pack("{si}", "result", G_ERROR_PARAM);
    } else if (ldap_count_entries(ldap, answer) == 0) {
      // No result found for username
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap, no entry for this username");
      res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    } else {
      // ldap found some results, getting the first one
      entry = ldap_first_entry(ldap, answer);
      
      if (entry == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "ldap search: error getting first result");
        res = json_pack("{si}", "result", G_ERROR);
      } else {
        struct berval ** values = ldap_get_values_len(ldap, entry, config->auth_ldap->scope_property);
        char * new_scope_list = strdup("");
        int i;
        
        for (i=0; i < ldap_count_values_len(values); i++) {
          char * str_value = malloc(values[i]->bv_len + 1);
          char * scope_list_dup = strdup(scope_list);
          char * token, * save_ptr = NULL;
          
          snprintf(str_value, values[i]->bv_len + 1, "%s", values[i]->bv_val);
          token = strtok_r(scope_list_dup, " ", &save_ptr);
          while (token != NULL) {
            if (0 == strcmp(token, str_value)) {
              if (strlen(new_scope_list) > 0) {
                char * tmp = msprintf("%s %s", new_scope_list, token);
                free(new_scope_list);
                new_scope_list = tmp;
              } else {
                free(new_scope_list);
                new_scope_list = strdup(token);
              }
            }
            token = strtok_r(NULL, " ", &save_ptr);
          }
          free(scope_list_dup);
          free(str_value);
        }
        ldap_value_free_len(values);
        if (nstrlen(new_scope_list) > 0) {
          res = json_pack("{siss}", "result", G_OK, "scope", new_scope_list);
        } else {
          // User hasn't all of part of the scope requested, sending unauthorized answer
          y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap, scope incorrect");
          res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
      }
    }
    free(filter);
    ldap_msgfree(answer);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  return res;
}

int auth_check_client_user_scope(struct config_elements * config, const char * client_id, const char * username, const char * scope_list) {
  json_t * j_query, * j_result;
  int res, nb_scope = 0;
  char * scope, * escaped_scope, * escaped_scope_list = NULL, * save_scope_list, * saveptr, * tmp;
  char * client_id_escaped, * client_clause, * scope_clause;
  
  save_scope_list = strdup(scope_list);
  scope = strtok_r(save_scope_list, ",", &saveptr);
  while (scope != NULL) {
    nb_scope++;
    escaped_scope = h_escape_string(config->conn, scope);
    if (escaped_scope_list == NULL)  {
      escaped_scope_list = msprintf("'%s'", escaped_scope);
    } else {
      tmp = msprintf("%s,'%s'", escaped_scope_list, escaped_scope);
      free(escaped_scope_list);
      escaped_scope_list = tmp;
    }
    free(escaped_scope);
    scope = strtok_r(NULL, ",", &saveptr);
  }
  free(save_scope_list);
  
  client_id_escaped = h_escape_string(config->conn, client_id);
  client_clause = msprintf("= (SELECT `gc_id` FROM `%s` WHERE `gc_client_id`='%s')", GLEWLWYD_TABLE_CLIENT, client_id_escaped);
  scope_clause = msprintf("IN (SELECT `gs_id` FROM `%s` WHERE `gs_name` IN (%s))", GLEWLWYD_TABLE_SCOPE, escaped_scope_list);
  j_query = json_pack("{sss[s]s{sss{ssss}s{ssss}}}"
            "table",
            GLEWLWYD_TABLE_CLIENT_USER_SCOPE,
            "columns",
              "gcus_id",
            "where",
              "gcus_username",
              "username",
              "gc_id",
                "operator",
                "raw",
                "value",
                client_clause,
              "gs_id",
                "operator",
                "raw",
                "value",
                scope_clause
            );
  free(client_id_escaped);
  free(client_clause);
  free(scope_clause);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    nb_scope -= json_array_size(j_result);
    json_decref(j_result);
    return (nb_scope==0?G_OK:G_ERROR_UNAUTHORIZED);
  } else {
    return G_ERROR_DB;
  }
}

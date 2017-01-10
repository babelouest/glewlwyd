/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * Provides Json Web Tokens (jwt)
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
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
 
#include <ldap.h>
#include <openssl/md5.h>

#include "glewlwyd.h"

/**
 *
 * Check if the authorization type is enabled in the configuration
 *
 */
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

/**
 *
 * Grant access of scope to client_id for username
 *
 */
int grant_client_user_scope_access(struct config_elements * config, const char * client_id, const char * username, const char * scope_list) {
  json_t * j_query, * j_result;
  char * save_scope_list = nstrdup(scope_list), * scope, * saveptr;
  char * where_clause_scope, * scope_escaped;
  int res, to_return = G_OK;
  
  if (client_id != NULL && username != NULL && save_scope_list != NULL && strlen(save_scope_list) > 0) {
    scope = strtok_r(save_scope_list, " ", &saveptr);
    while (scope != NULL) {
      // Check if this user hasn't granted access to this client for this scope
      scope_escaped = h_escape_string(config->conn, scope);
      where_clause_scope = msprintf("= (SELECT `gs_id` FROM `%s` WHERE `gs_name`='%s')", GLEWLWYD_TABLE_SCOPE, scope_escaped);
      j_query = json_pack("{sss[s]s{sssss{ssss}}}",
                          "table",
                          GLEWLWYD_TABLE_CLIENT_USER_SCOPE,
                          "columns",
                            "gcus_id",
                          "where",
                            "gc_client_id",
                            client_id,
                            "gco_username",
                            username,
                            "gs_id",
                              "operator",
                              "raw",
                              "value",
                              where_clause_scope);
      free(where_clause_scope);
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result) == 0) {
          // Add grant to this scope
          where_clause_scope = msprintf("(SELECT `gs_id` FROM `%s` WHERE `gs_name`='%s')", GLEWLWYD_TABLE_SCOPE, scope_escaped);
          j_query = json_pack("{sss{sssss{ss}}}",
                              "table",
                              GLEWLWYD_TABLE_CLIENT_USER_SCOPE,
                              "values",
                                "gc_client_id",
                                client_id,
                                "gco_username",
                                username,
                                "gs_id",
                                  "raw",
                                  where_clause_scope);
          free(where_clause_scope);
          res = h_insert(config->conn, j_query, NULL);
          json_decref(j_query);
          if (res != H_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "grant_client_user_scope_access - Error adding scope %s to client_id %s for user %s", scope, client_id, username);
            to_return = G_ERROR_DB;
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "grant_client_user_scope_access - Error getting grant for scope %s to client_id %s for user %s", scope, client_id, username);
        to_return = G_ERROR_DB;
      }
      free(scope_escaped);
      json_decref(j_result);
      scope = strtok_r(NULL, " ", &saveptr);
    }
  } else {
    // Error input parameters
    y_log_message(Y_LOG_LEVEL_ERROR, "grant_client_user_scope_access - Error input parameters");
    to_return = G_ERROR_PARAM;
  }
  free(save_scope_list);
  
  return to_return;
}

/**
 *
 * Remove access of scope to client_id for username
 *
 */
int delete_client_user_scope_access(struct config_elements * config, const char * client_id, const char * username, const char * scope_list) {
  json_t * j_query, * j_result;
  char * save_scope_list = nstrdup(scope_list), * scope, * saveptr;
  char * where_clause_scope, * scope_escaped;
  int res, to_return = G_OK;
  
  if (client_id != NULL && username != NULL && save_scope_list != NULL && strlen(save_scope_list) > 0) {
    scope = strtok_r(save_scope_list, " ", &saveptr);
    while (scope != NULL) {
      // Check if this user hasn't granted access to this client for this scope
      scope_escaped = h_escape_string(config->conn, scope);
      where_clause_scope = msprintf("= (SELECT `gs_id` FROM `%s` WHERE `gs_name`='%s')", GLEWLWYD_TABLE_SCOPE, scope_escaped);
      j_query = json_pack("{sss[s]s{sssss{ssss}}}",
                          "table",
                          GLEWLWYD_TABLE_CLIENT_USER_SCOPE,
                          "columns",
                            "gcus_id",
                          "where",
                            "gc_client_id",
                            client_id,
                            "gco_username",
                            username,
                            "gs_id",
                              "operator",
                              "raw",
                              "value",
                              where_clause_scope);
      free(where_clause_scope);
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result) == 0) {
          // Add grant to this scope
          where_clause_scope = msprintf("(SELECT `gs_id` FROM `%s` WHERE `gs_name`='%s')", GLEWLWYD_TABLE_SCOPE, scope_escaped);
          j_query = json_pack("{sss{sssss{ss}}}",
                              "table",
                              GLEWLWYD_TABLE_CLIENT_USER_SCOPE,
                              "where",
                                "gc_client_id",
                                client_id,
                                "gco_username",
                                username,
                                "gs_id",
                                  "raw",
                                  where_clause_scope);
          free(where_clause_scope);
          res = h_delete(config->conn, j_query, NULL);
          json_decref(j_query);
          if (res != H_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "delete_client_user_scope_access - Error adding scope %s to client_id %s for user %s", scope, client_id, username);
            to_return = G_ERROR_DB;
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "delete_client_user_scope_access - Error getting grant for scope %s to client_id %s for user %s", scope, client_id, username);
        to_return = G_ERROR_DB;
      }
      free(scope_escaped);
      json_decref(j_result);
      scope = strtok_r(NULL, " ", &saveptr);
    }
  } else {
    // Error input parameters
    y_log_message(Y_LOG_LEVEL_ERROR, "delete_client_user_scope_access - Error input parameters");
    to_return = G_ERROR_PARAM;
  }
  free(save_scope_list);
  
  return to_return;
}

/**
 *
 * Check if code is valid
 * If so, return username, client_id and (if needed) scope list that was used to create that code
 *
 */
json_t * validate_authorization_code(struct config_elements * config, const char * authorization_code, const char * client_id, const char * redirect_uri, const char * ip_source) {
  json_t * j_query, * j_result, * j_scope, * j_element, * j_return;
  size_t index;
  int res;
  json_int_t gco_id;
  char * code_hash, * escape, * escape_ip_source, * clause_redirect_uri, * col_gco_date, * clause_gco_date, * clause_scope, * scope_list = NULL, * tmp;
  
  if (authorization_code != NULL && client_id != NULL) {
    code_hash = generate_hash(config, config->hash_algorithm, authorization_code);
    escape_ip_source = h_escape_string(config->conn, ip_source);
    escape = h_escape_string(config->conn, redirect_uri);
    clause_redirect_uri = msprintf("= (SELECT `gru_id` FROM `%s` WHERE `gru_uri`='%s')", GLEWLWYD_TABLE_REDIRECT_URI, escape);
    free(escape);
    
    // TODO: code expiration time in config file
    if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
      col_gco_date = nstrdup("UNIX_TIMESTAMP(`gco_date`)");
      clause_gco_date = nstrdup("> (UNIX_TIMESTAMP(NOW()) - 600)");
    } else {
      col_gco_date = nstrdup("gco_date");
      clause_gco_date = nstrdup("> (strftime('%s','now') - 600)");
    }
    
    j_query = json_pack("{sss[ss]s{si ss ss s{ssss} ss s{ssss}}}",
                        "table",
                        GLEWLWYD_TABLE_CODE,
                        "columns",
                          "gco_id",
                          "gco_username",
                        "where",
                          "gco_enabled",
                          1,
                          "gco_code_hash",
                          code_hash,
                          "gco_ip_source",
                          escape_ip_source,
                          "gru_id",
                            "operator",
                            "raw",
                            "value",
                            clause_redirect_uri,
                          "gc_client_id",
                          client_id,
                          col_gco_date,
                            "operator",
                            "raw",
                            "value",
                            clause_gco_date);
    free(clause_gco_date);
    free(col_gco_date);
    free(clause_redirect_uri);
    free(escape_ip_source);
    free(code_hash);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result) > 0) {
        // Get scope_list (if any)
        if (config->use_scope) {
          gco_id = json_integer_value(json_object_get(json_array_get(j_result, 0), "gco_id"));
          clause_scope = msprintf("IN (SELECT `gs_id` FROM `%s` WHERE `gco_id`=%" JSON_INTEGER_FORMAT ")", GLEWLWYD_TABLE_CODE_SCOPE, gco_id);
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
                                  clause_scope);
          free(clause_scope);
          res = h_select(config->conn, j_query, &j_scope, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            json_array_foreach(j_scope, index, j_element) {
              if (scope_list == NULL) {
                scope_list = nstrdup(json_string_value(json_object_get(j_element, "gs_name")));
              } else {
                tmp = msprintf("%s %s", scope_list, json_string_value(json_object_get(j_element, "gs_name")));
                free(scope_list);
                scope_list = tmp;
              }
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "validate_authorization_code - Error executing query scope");
            j_return = json_pack("{siss}", "result", G_ERROR_DB, "error", "server_error");
          }
          json_decref(j_scope);
          
          if (scope_list != NULL) {
            j_return = json_pack("{sisssssI}", "result", G_OK, "scope", scope_list, "username", json_string_value(json_object_get(json_array_get(j_result, 0), "gco_username")), "gco_id", json_integer_value((json_object_get(json_array_get(j_result, 0), "gco_id"))));
          } else {
            j_return = json_pack("{siss}", "result", G_ERROR_UNAUTHORIZED, "error", "invalid_scope");
          }
          free(scope_list);
        } else {
          j_return = json_pack("{sisssI}", "result", G_OK, "username", json_string_value(json_object_get(json_array_get(j_result, 0), "gco_username")), "gco_id", json_integer_value((json_object_get(json_array_get(j_result, 0), "gco_id"))));
        }
      } else {
        j_return = json_pack("{siss}", "result", G_ERROR_UNAUTHORIZED, "error", "access_denied");
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "validate_authorization_code - Error executng query code");
      j_return = json_pack("{siss}", "result", G_ERROR_DB, "error", "server_error");
    }
  } else {
    j_return = json_pack("{siss}", "result", G_ERROR_UNAUTHORIZED, "error", "unauthorized_client");
  }
  return j_return;
}

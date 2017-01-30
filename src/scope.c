/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * Provides Json Web Tokens (jwt)
 * 
 * scope CRUD services
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

#include <string.h>
#include "glewlwyd.h"

/**
 * Get the list of all scopes
 */
json_t * get_scope_list(struct config_elements * config) {
  json_t * j_query, * j_result, * j_return;
  int res;
  
  j_query = json_pack("{sss[ss]}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "columns",
                        "gs_name AS name",
                        "gs_description AS description");
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_return = json_pack("{siso}", "result", G_OK, "scope", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_scope_list error getting scope list");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

/**
 * Get a specific scope
 */
json_t * get_scope(struct config_elements * config, const char * scope) {
  json_t * j_query, * j_result, * j_return;
  int res;
  
  j_query = json_pack("{sss[ss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "columns",
                        "gs_name AS name",
                        "gs_description AS description",
                      "where",
                        "gs_name",
                        scope);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result) > 0) {
      j_return = json_pack("{siso}", "result", G_OK, "scope", json_copy(json_array_get(j_result, 0)));
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_scope error getting scoipe list");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

/**
 * Check if the scope has valid parameters
 */
json_t * is_scope_valid(struct config_elements * config, json_t * j_scope, int add) {
  json_t * j_return = json_array(), * j_query, * j_result;
  int res;
  
  if (j_return != NULL) {
    if (json_is_object(j_scope)) {
      if (add) {
        if (json_is_string(json_object_get(j_scope, "name"))) {
          j_query = json_pack("{sss{ss}}",
                              "table",
                              GLEWLWYD_TABLE_SCOPE,
                              "where",
                                "gs_name",
                                json_string_value(json_object_get(j_scope, "name")));
          res = h_select(config->conn, j_query, &j_result, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            if (json_array_size(j_result) > 0) {
              json_array_append_new(j_return, json_pack("{ss}", "name", "scope name alread exist"));
            }
            json_decref(j_result);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "is_scope_valid - Error executing j_query");
          }
        }
        
        if (!json_is_string(json_object_get(j_scope, "name")) || json_string_length(json_object_get(j_scope, "name")) == 0 || json_string_length(json_object_get(j_scope, "name")) > 128 || strchr(json_string_value(json_object_get(j_scope, "name")), ' ') != NULL) {
          json_array_append_new(j_return, json_pack("{ss}", "name", "scope name must be a non empty string of maximum 128 characters, without space characters"));
        }
        if (json_object_get(j_scope, "description") != NULL && (!json_is_string(json_object_get(j_scope, "description")) || json_string_length(json_object_get(j_scope, "description")) > 512)) {
          json_array_append_new(j_return, json_pack("{ss}", "description", "scope description is optional and must be a string of maximum 512 characters"));
        }
      } else {
        if (json_object_get(j_scope, "description") == NULL || !json_is_string(json_object_get(j_scope, "description")) || json_string_length(json_object_get(j_scope, "description")) > 512) {
          json_array_append_new(j_return, json_pack("{ss}", "description", "scope description is mandatory and must be a string of maximum 512 characters"));
        }
      }
    } else {
      json_array_append_new(j_return, json_pack("{ss}", "scope", "scope must be a json object"));
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_scope_valid - Error allocating resources for j_result");
  }
  return j_return;
}

/**
 * Add a new scope
 */
int add_scope(struct config_elements * config, json_t * j_scope) {
  json_t * j_query;
  int res;
  
  j_query = json_pack("{sss{ss}}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "values",
                        "gs_name",
                        json_string_value(json_object_get(j_scope, "name")));
  if (json_object_get(j_scope, "description") != NULL) {
    json_object_set_new(json_object_get(j_query, "values"), "gs_description", json_copy(json_object_get(j_scope, "description")));
  }
  
  res = h_insert(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_scope - Error executing j_query");
    return G_ERROR_DB;
  }
}

/**
 * Updates an exising scope
 */
int set_scope(struct config_elements * config, const char * scope, json_t * j_scope) {
  json_t * j_query;
  int res;
  
  j_query = json_pack("{sss{ss}s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "set",
                        "gs_description",
                        json_object_get(j_scope, "description")!=NULL?json_string_value(json_object_get(j_scope, "description")):"",
                      "where",
                        "gs_name",
                        scope);
  
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_scope - Error executing j_query");
    return G_ERROR_DB;
  }
}

/**
 * Delete an existing scope
 */
int delete_scope(struct config_elements * config, const char * scope) {
  json_t * j_query;
  int res;
  
  j_query = json_pack("{sss{ss}}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "where",
                        "gs_name",
                        scope);
  
  res = h_delete(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_scope - Error executing j_query");
    return G_ERROR_DB;
  }
}

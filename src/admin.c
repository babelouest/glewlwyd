/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * Provides Json Web Tokens (jwt)
 * 
 * admin services
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

#include "glewlwyd.h"

/**
 *
 * Get a list of authorization_type or a specific one
 *
 */
json_t * get_authorization_type(struct config_elements * config, const char * authorization_type) {
  json_t * j_query, * j_result, * j_return, * j_element;
  int res;
  size_t index;
  
  j_query = json_pack("{sss[sss]}",
                      "table",
                      GLEWLWYD_TABLE_AUTHORIZATION_TYPE,
                      "columns",
                        "got_name AS name",
                        "got_description AS description",
                        "got_enabled");
  if (authorization_type != NULL) {
    json_object_set_new(j_query, "where", json_pack("{ss}", "got_name", authorization_type));
  }
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (authorization_type != NULL && json_array_size(j_result) == 0) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else {
      json_array_foreach(j_result, index, j_element) {
        json_object_set_new(j_element, "enabled", json_integer_value(json_object_get(j_element, "got_enabled"))==1?json_true():json_false());
        json_object_del(j_element, "got_enabled");
      }
      j_return = json_pack("{siso}", "result", G_OK, "authorization", json_copy(j_result));
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_authorization_type_list - Error getting authorization type list");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  json_decref(j_result);
  return j_return;
}

/**
 *
 * Check if authorization_type has valid parameters
 *
 */
json_t * is_authorization_type_valid(struct config_elements * config, json_t * j_authorization_type) {
  json_t * j_result = json_array();
  
  if (j_result != NULL) {
    if (j_authorization_type == NULL || !json_is_object(j_authorization_type)) {
      json_array_append_new(j_result, json_pack("{ss}", "authorization_type", "structure must be a json object"));
    } else {
      
      if (json_object_get(j_authorization_type, "description") != NULL && (!json_is_string(json_object_get(j_authorization_type, "description")) || json_string_length(json_object_get(j_authorization_type, "description")) > 512)) {
        json_array_append_new(j_result, json_pack("{ss}", "description", "description must be a string up to 512 characters"));
      }
      
      if (json_object_get(j_authorization_type, "enabled") != NULL && !json_is_boolean(json_object_get(j_authorization_type, "enabled"))) {
        json_array_append_new(j_result, json_pack("{ss}", "enabled", "enabled must be a boolean"));
      }
      
      if (json_object_get(j_authorization_type, "description") == NULL && json_object_get(j_authorization_type, "enabled") == NULL) {
        json_array_append_new(j_result, json_pack("{ss}", "authorization_type", "You must modify at least one value"));
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_authorization_type_valid - Error allocating resources for j_result");
  }
  return j_result;
}

/**
 *
 * Update an authorization_type
 *
 */
int set_authorization_type(struct config_elements * config, const char * authorization_type, json_t * j_authorization_type) {
  json_t * j_query;
  int res;
  
  j_query = json_pack("{sss{}s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_AUTHORIZATION_TYPE,
                      "set",
                      "where",
                        "got_name",
                        authorization_type);
  if (json_object_get(j_authorization_type, "description") != NULL) {
    json_object_set_new(json_object_get(j_query, "set"), "got_description", json_copy(json_object_get(j_authorization_type, "description")));
  }
  
  if (json_object_get(j_authorization_type, "enabled") != NULL) {
    json_object_set_new(json_object_get(j_query, "set"), "got_enabled", json_object_get(j_authorization_type, "enabled")==json_true()?json_integer(1):json_integer(0));
  }
  
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  
  if (res==H_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_authorization_type - Error executing j_query");
    return G_ERROR_DB;
  }
}

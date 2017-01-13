/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * Provides Json Web Tokens (jwt)
 * 
 * Resource CRUD
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
 * Get the list of all resources
 */
json_t * get_resource_list(struct config_elements * config) {
  json_t * j_query, * j_result, * j_return;
  int res;
  
  j_query = json_pack("{sss[sss]}",
                      "table",
                      GLEWLWYD_TABLE_RESOURCE,
                      "columns",
                        "gr_name AS name",
                        "gr_description AS description",
                        "gr_uri AS uri");
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_return = json_pack("{siso}", "result", G_OK, "resource", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_resource_list error getting resource list");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

/**
 * Get a specifric resource
 */
json_t * get_resource(struct config_elements * config, const char * resource) {
  json_t * j_query, * j_result, * j_return;
  int res;
  
  j_query = json_pack("{sss[sss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_RESOURCE,
                      "columns",
                        "gr_name AS name",
                        "gr_description AS description",
                        "gr_uri AS uri",
                      "where",
                        "gr_name",
                        resource);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result) > 0) {
      j_return = json_pack("{siso}", "result", G_OK, "resource", json_copy(json_array_get(j_result, 0)));
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_resource error getting scoipe list");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

/**
 * Check if the resource parameters are valid
 */
json_t * is_resource_valid(struct config_elements * config, json_t * j_resource, int add) {
  json_t * j_return = json_array(), * j_query, * j_result;
  int res;
  
  if (j_return != NULL) {
    if (json_is_object(j_resource)) {
      if (add) {
        if (json_is_string(json_object_get(j_resource, "name"))) {
          j_query = json_pack("{sss{ss}}",
                              "table",
                              GLEWLWYD_TABLE_RESOURCE,
                              "where",
                                "gr_name",
                                json_string_value(json_object_get(j_resource, "name")));
          res = h_select(config->conn, j_query, &j_result, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            if (json_array_size(j_result) > 0) {
              json_array_append_new(j_return, json_pack("{ss}", "name", "resource name alread exist"));
            }
            json_decref(j_result);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "is_resource_valid - Error executing j_query");
          }
        }
        
        if (!json_is_string(json_object_get(j_resource, "name")) || json_string_length(json_object_get(j_resource, "name")) == 0 || json_string_length(json_object_get(j_resource, "name")) > 128 || strchr(json_string_value(json_object_get(j_resource, "name")), ' ') != NULL) {
          json_array_append_new(j_return, json_pack("{ss}", "name", "resource name must be a non empty string of maximum 128 characters, without space characters"));
        }
      }
      if (json_object_get(j_resource, "description") != NULL && (!json_is_string(json_object_get(j_resource, "description")) || json_string_length(json_object_get(j_resource, "description")) > 512)) {
        json_array_append_new(j_return, json_pack("{ss}", "description", "resource description is optional and must be a string of maximum 512 characters"));
      }
      if (json_object_get(j_resource, "uri") == NULL || ((!json_is_string(json_object_get(j_resource, "uri")) || json_string_length(json_object_get(j_resource, "uri")) > 512))) {
        json_array_append_new(j_return, json_pack("{ss}", "uri", "resource uri is mandatory and must be a string of maximum 512 characters"));
      }
    } else {
      json_array_append_new(j_return, json_pack("{ss}", "resource", "resource must be a json object"));
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_resource_valid - Error allocating resources for j_result");
  }
  return j_return;
}

/**
 * Add a new resource
 */
int add_resource(struct config_elements * config, json_t * j_resource) {
  json_t * j_query;
  int res;
  
  j_query = json_pack("{sss{ssss}}",
                      "table",
                      GLEWLWYD_TABLE_RESOURCE,
                      "values",
                        "gr_name",
                        json_string_value(json_object_get(j_resource, "name")),
                        "gr_uri",
                        json_string_value(json_object_get(j_resource, "uri")));
  if (json_object_get(j_resource, "description") != NULL) {
    json_object_set_new(json_object_get(j_query, "values"), "gr_description", json_copy(json_object_get(j_resource, "description")));
  }
  
  res = h_insert(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_resource - Error executing j_query");
    return G_ERROR_DB;
  }
}

/**
 * Updates an existing resource
 */
int set_resource(struct config_elements * config, const char * resource, json_t * j_resource) {
  json_t * j_query;
  int res;
  
  j_query = json_pack("{sss{ss}s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_RESOURCE,
                      "set",
                        "gr_uri",
                        json_string_value(json_object_get(j_resource, "uri")),
                      "where",
                        "gr_name",
                        resource);
  if (json_object_get(j_resource, "description") != NULL) {
    json_object_set_new(json_object_get(j_query, "set"), "gr_description", json_copy(json_object_get(j_resource, "description")));
  }
  
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_resource - Error executing j_query");
    return G_ERROR_DB;
  }
}

/**
 * Deletes an existing resource
 */
int delete_resource(struct config_elements * config, const char * resource) {
  json_t * j_query;
  int res;
  
  j_query = json_pack("{sss{ss}}",
                      "table",
                      GLEWLWYD_TABLE_RESOURCE,
                      "where",
                        "gr_name",
                        resource);
  
  res = h_delete(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_resource - Error executing j_query");
    return G_ERROR_DB;
  }
}

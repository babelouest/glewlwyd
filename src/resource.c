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
  json_t * j_query, * j_result, * j_return, * j_element, * j_scope, * j_scope_entry;
  size_t index;
  int res, i_scope;
  char * scope_clause;
  
  j_query = json_pack("{sss[ssss]}",
                      "table",
                      GLEWLWYD_TABLE_RESOURCE,
                      "columns",
                        "gr_id",
                        "gr_name AS name",
                        "gr_description AS description",
                        "gr_uri AS uri");
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      if (config->use_scope) {
        scope_clause = msprintf("IN (SELECT `gs_id` FROM %s WHERE `gr_id`='%" JSON_INTEGER_FORMAT "')", GLEWLWYD_TABLE_RESOURCE_SCOPE, json_integer_value(json_object_get(j_element, "gr_id")));
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
                                scope_clause);
        o_free(scope_clause);
        res = h_select(config->conn, j_query, &j_scope, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          json_object_set_new(j_element, "scope", json_array());
          json_array_foreach(j_scope, i_scope, j_scope_entry) {
            json_array_append(json_object_get(j_element, "scope"), json_object_get(j_scope_entry, "gs_name"));
          }
          json_decref(j_scope);
        }
      }
      json_object_del(j_element, "gr_id");
    }
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
  json_t * j_query, * j_result, * j_return, * j_scope, * j_scope_entry;
  int res, i_scope;
  char * scope_clause;
  
  j_query = json_pack("{sss[ssss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_RESOURCE,
                      "columns",
                        "gr_id",
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
      if (config->use_scope) {
        scope_clause = msprintf("IN (SELECT `gs_id` FROM %s WHERE `gr_id`='%" JSON_INTEGER_FORMAT "')", GLEWLWYD_TABLE_RESOURCE_SCOPE, json_integer_value(json_object_get(json_array_get(j_result, 0), "gr_id")));
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
                                scope_clause);
        o_free(scope_clause);
        res = h_select(config->conn, j_query, &j_scope, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          json_object_set_new(json_array_get(j_result, 0), "scope", json_array());
          json_array_foreach(j_scope, i_scope, j_scope_entry) {
            json_array_append(json_object_get(json_array_get(j_result, 0), "scope"), json_object_get(j_scope_entry, "gs_name"));
          }
          json_decref(j_scope);
        }
      }
      json_object_del(json_array_get(j_result, 0), "gr_id");
      j_return = json_pack("{sisO}", "result", G_OK, "resource", json_array_get(j_result, 0));
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
  json_t * j_return = json_array(), * j_query, * j_result, * j_scope;
  int res;
  size_t index;
  
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
      if (config->use_scope) {
        if (json_object_get(j_resource, "scope") == NULL || !json_is_array(json_object_get(j_resource, "scope"))) {
          json_array_append_new(j_return, json_pack("{ss}", "scope", "scope is a mandatory array of scope names"));
        } else {
          json_array_foreach(json_object_get(j_resource, "scope"), index, j_scope) {
            if (!json_is_string(j_scope)) {
              json_array_append_new(j_return, json_pack("{ss}", "scope", "scope name must be a string"));
            } else {
              j_result = get_scope(config, json_string_value(j_scope));
              if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
                char * message = msprintf("scope name '%s' not found", json_string_value(j_scope));
                json_array_append_new(j_return, json_pack("{ss}", "scope", message));
                o_free(message);
              } else if (!check_result_value(j_result, G_OK)) {
                y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error while checking scope name '%s'", json_string_value(j_scope));
              }
              json_decref(j_result);
            }
          }
        }
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
  json_t * j_query, * j_scope;
  int res, to_return;
  char * clause_scope, * escaped;
  char * clause_login;
  size_t index;
  
  j_query = json_pack("{sss{ssssss}}",
                      "table",
                      GLEWLWYD_TABLE_RESOURCE,
                      "values",
                        "gr_name",
                        json_string_value(json_object_get(j_resource, "name")),
                        "gr_description",
                        json_object_get(j_resource, "description")!=NULL?json_string_value(json_object_get(j_resource, "description")):"",
                        "gr_uri",
                        json_object_get(j_resource, "uri")!=NULL?json_string_value(json_object_get(j_resource, "uri")):"");
  if (json_object_get(j_resource, "description") != NULL) {
    json_object_set(json_object_get(j_query, "values"), "gr_description", json_object_get(j_resource, "description"));
  }
  
  res = h_insert(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    to_return = G_OK;
    if (json_object_get(j_resource, "scope") != NULL && config->use_scope) {
      escaped = h_escape_string(config->conn, json_string_value(json_object_get(j_resource, "name")));
      clause_login = msprintf("(SELECT `gr_id` FROM `%s` WHERE `gr_name`='%s')", GLEWLWYD_TABLE_RESOURCE, escaped);
      o_free(escaped);
      j_query = json_pack("{sss[]}",
                          "table",
                          GLEWLWYD_TABLE_RESOURCE_SCOPE,
                          "values");
      json_array_foreach(json_object_get(j_resource, "scope"), index, j_scope) {
        escaped = h_escape_string(config->conn, json_string_value(j_scope));
        clause_scope = msprintf("(SELECT `gs_id` FROM `%s` WHERE `gs_name`='%s')", GLEWLWYD_TABLE_SCOPE, escaped);
        o_free(escaped);
        json_array_append_new(json_object_get(j_query, "values"), json_pack("{s{ss}s{ss}}", "gr_id", "raw", clause_login, "gs_id", "raw", clause_scope));
        o_free(clause_scope);
      }
      if (json_array_size(json_object_get(j_query, "values")) > 0) {
        if (h_insert(config->conn, j_query, NULL) != H_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "add_client_database - Error adding scope");
          to_return = G_ERROR_DB;
        }
      }
      o_free(clause_login);
      json_decref(j_query);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_resource - Error executing j_query");
    to_return = G_ERROR_DB;
  }
  return to_return;
}

/**
 * Updates an existing resource
 */
int set_resource(struct config_elements * config, const char * resource, json_t * j_resource) {
  json_t * j_query, * j_scope;
  int res, to_return;
  char * clause_scope, * escaped;
  size_t index;
  char * clause_login;
  
  j_query = json_pack("{sss{ssss}s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_RESOURCE,
                      "set",
                        "gr_uri",
                        json_string_value(json_object_get(j_resource, "uri")),
                        "gr_description",
                        json_object_get(j_resource, "description")!=NULL?json_string_value(json_object_get(j_resource, "description")):"",
                      "where",
                        "gr_name",
                        resource);
  if (json_object_get(j_resource, "description") != NULL) {
    json_object_set(json_object_get(j_query, "set"), "gr_description", json_object_get(j_resource, "description"));
  }
  
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    to_return =  G_OK;
    if (json_object_get(j_resource, "scope") != NULL && config->use_scope) {
      escaped = h_escape_string(config->conn, resource);
      clause_login = msprintf("= (SELECT `gr_id` FROM `%s` WHERE `gr_name`='%s')", GLEWLWYD_TABLE_RESOURCE, escaped);
      o_free(escaped);
      j_query = json_pack("{sss{s{ssss}}}",
                          "table",
                          GLEWLWYD_TABLE_RESOURCE_SCOPE,
                          "where",
                            "gr_id",
                              "operator",
                              "raw",
                              "value",
                              clause_login);
      o_free(clause_login);
      res = h_delete(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
          escaped = h_escape_string(config->conn, resource);
          clause_login = msprintf("(SELECT `gr_id` FROM `%s` WHERE `gr_name`='%s')", GLEWLWYD_TABLE_RESOURCE, escaped);
          o_free(escaped);
          j_query = json_pack("{sss[]}",
                              "table",
                              GLEWLWYD_TABLE_RESOURCE_SCOPE,
                              "values");
          json_array_foreach(json_object_get(j_resource, "scope"), index, j_scope) {
            escaped = h_escape_string(config->conn, json_string_value(j_scope));
            clause_scope = msprintf("(SELECT `gs_id` FROM `%s` WHERE `gs_name`='%s')", GLEWLWYD_TABLE_SCOPE, escaped);
            o_free(escaped);
            json_array_append_new(json_object_get(j_query, "values"), json_pack("{s{ss}s{ss}}", "gr_id", "raw", clause_login, "gs_id", "raw", clause_scope));
            o_free(clause_scope);
          }
          o_free(clause_login);
          if (json_array_size(json_object_get(j_query, "values")) > 0) {
            if (h_insert(config->conn, j_query, NULL) != H_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "add_client_database - Error adding scope");
              to_return =  G_ERROR_DB;
            }
          }
          json_decref(j_query);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_client_database - Error deleting old scope");
        to_return =  G_ERROR_DB;
      }
      
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_resource - Error executing j_query");
    to_return =  G_ERROR_DB;
  }
  return to_return;
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

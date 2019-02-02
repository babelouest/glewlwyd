/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * scope management functions definition
 *
 * Copyright 2018 Nicolas Mora <mail@babelouest.org>
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

json_t * get_scope_list(struct config_elements * config) {
  json_t * j_query, * j_result, * j_return;
  int res;

  j_query = json_pack("{sss[sss]}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "columns",
                        "gs_name",
                        "gs_display_name",
                        "gs_description");
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_return = json_pack("{siso}", "result", G_OK, "scope", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_scope_list - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

json_t * get_scope(struct config_elements * config, const char * scope) {
  json_t * j_query, * j_result, * j_return;
  int res;

  j_query = json_pack("{sss[sss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "columns",
                        "gs_name",
                        "gs_display_name",
                        "gs_description",
                      "where",
                        "gs_name",
                        scope);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_return = json_pack("{siso}", "result", G_OK, "scope", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_scope - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

json_t * get_auth_scheme_list_from_scope(struct config_elements * config, const char * scope) {
  const char * str_query_pattern = "SELECT \
    guasg_name AS group_name, \
    guasmi_module AS scheme_type, \
    guasmi_name AS scheme_name \
  FROM \
    `" GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE "`, \
    `" GLEWLWYD_TABLE_USER_AUTH_SCHEME_GROUP "`, \
    `" GLEWLWYD_TABLE_SCOPE "` \
  WHERE \
    `" GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE "`.`guasmi_id` IN (SELECT `guasmi_id` FROM `" GLEWLWYD_TABLE_USER_AUTH_SCHEME_GROUP_AUTH_SCHEME_MODULE_INSTANCE "` WHERE `guasg_id` = `" GLEWLWYD_TABLE_USER_AUTH_SCHEME_GROUP "`.`guasg_id`) AND \
    `" GLEWLWYD_TABLE_USER_AUTH_SCHEME_GROUP "`.`guasg_id` IN (SELECT `guasg_id` FROM `" GLEWLWYD_TABLE_USER_AUTH_SCHEME_GROUP_SCOPE "` WHERE `gs_id` = `" GLEWLWYD_TABLE_SCOPE "`.`gs_id`) AND \
    `" GLEWLWYD_TABLE_SCOPE "`.`gs_name` = '%s' \
  ORDER BY \
    `" GLEWLWYD_TABLE_SCOPE "`.`gs_id`, \
    `" GLEWLWYD_TABLE_USER_AUTH_SCHEME_GROUP "`.`guasg_id`;";
  char * scope_escape = h_escape_string(config->conn, scope), * str_query = NULL;
  json_t * j_return, * j_result = NULL, * j_element;
  int res;
  size_t index;
  
  if (scope_escape != NULL) {
    str_query = msprintf(str_query_pattern, scope_escape);
    if (str_query != NULL) {
      res = h_execute_query_json(config->conn, str_query, &j_result);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          j_return = json_pack("{sis{}}", "result", G_OK, "scheme");
          if (j_return != NULL) {
            json_array_foreach(j_result, index, j_element) {
              if (json_object_get(json_object_get(j_return, "scheme"), json_string_value(json_object_get(j_element, "group_name"))) == NULL) {
                json_object_set_new(json_object_get(j_return, "scheme"), json_string_value(json_object_get(j_element, "group_name")), json_array());
              }
              if (json_object_get(json_object_get(j_return, "scheme"), json_string_value(json_object_get(j_element, "group_name"))) != NULL) {
                json_array_append_new(json_object_get(json_object_get(j_return, "scheme"), json_string_value(json_object_get(j_element, "group_name"))), json_pack("{ssss}", "scheme_type", json_string_value(json_object_get(j_element, "scheme_type")), "scheme_name", json_string_value(json_object_get(j_element, "scheme_name"))));
              }
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_auth_scheme_list_from_scope - Error allocating resources for j_return");
            j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
          }
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_auth_scheme_list_from_scope - Error executing str_query");
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_auth_scheme_list_from_scope - Error allocating resources for str_query");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(str_query);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_auth_scheme_list_from_scope - Error h_escape_string");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

json_t * get_auth_scheme_list_from_scope_list(struct config_elements * config, const char * scope_list) {
  char ** scope_array;
  int i;
  json_t * j_result, * j_scheme_list;

  if (split_string(scope_list, " ", &scope_array) > 0) {
    j_result = json_pack("{sis{}}", "result", G_OK, "scheme");
    if (j_result != NULL) {
      for (i=0; scope_array[i] != NULL; i++) {
        if (json_object_get(json_object_get(j_result, "scheme"), scope_array[i]) == NULL) {
          j_scheme_list = get_auth_scheme_list_from_scope(config, scope_array[i]);
          if (check_result_value(j_scheme_list, G_OK)) {
            json_object_set(json_object_get(j_result, "scheme"), scope_array[i], json_object_get(j_scheme_list, "scheme"));
          }
          json_decref(j_scheme_list);
        }
      }
      if (!json_object_size(json_object_get(j_result, "scheme"))) {
        json_decref(j_result);
        j_result = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_auth_scheme_list_from_scope_list - Error allocating resources for j_result");
      j_result = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_auth_scheme_list_from_scope_list - Error split_string");
    j_result = json_pack("{si}", "result", G_ERROR);
  }
  return j_result;
}

json_t * get_validated_auth_scheme_list_from_scope_list(struct config_elements * config, const char * scope_list, const char * session_id) {
  return get_auth_scheme_list_from_scope_list(config, scope_list);
}

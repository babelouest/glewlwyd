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
  json_t * j_query, * j_result, * j_return, * j_element;
  int res;
  size_t index;

  j_query = json_pack("{sss[ssss]}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "columns",
                        "gs_name AS name",
                        "gs_display_name AS display_name",
                        "gs_description AS description",
                        "gs_requires_password");
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      json_object_set(j_element, "requires_password", json_integer_value(json_object_get(j_element, "gs_requires_password"))?json_true():json_false());
      json_object_del(j_element, "gs_requires_password");
    }
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
  char * query;

  j_query = json_pack("{sss[ssss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "columns",
                        "gs_name AS name",
                        "gs_display_name AS display_name",
                        "gs_description AS description",
                        "gs_requires_password",
                      "where",
                        "gs_name",
                        scope);
  res = h_select(config->conn, j_query, &j_result, &query);
  json_decref(j_query);
  if (res == H_OK) {
    json_object_set(json_array_get(j_result, 0), "password_required", json_integer_value(json_object_get(json_array_get(j_result, 0), "gs_requires_password"))?json_true():json_false());
    json_object_del(json_array_get(j_result, 0), "gs_requires_password");
    j_return = json_pack("{siso}", "result", G_OK, "scope", json_array_get(j_result, 0));
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
    guasmi_name AS scheme_name, \
    guasmi_display_name AS scheme_display_name \
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
                json_array_append_new(json_object_get(json_object_get(j_return, "scheme"), json_string_value(json_object_get(j_element, "group_name"))), json_pack("{ssssss}", "scheme_type", json_string_value(json_object_get(j_element, "scheme_type")), "scheme_name", json_string_value(json_object_get(j_element, "scheme_name")), "scheme_display_name", json_string_value(json_object_get(j_element, "scheme_display_name"))));
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
  char ** scope_array = NULL;
  int i;
  json_t * j_result, * j_scheme_list, * j_scope;

  if (split_string(scope_list, " ", &scope_array) > 0) {
    j_result = json_pack("{sis{}}", "result", G_OK, "scheme");
    if (j_result != NULL) {
      for (i=0; scope_array[i] != NULL; i++) {
        if (json_object_get(json_object_get(j_result, "scheme"), scope_array[i]) == NULL) {
          j_scope = get_scope(config, scope_array[i]);
          if (check_result_value(j_scope, G_OK)) {
            j_scheme_list = get_auth_scheme_list_from_scope(config, scope_array[i]);
            if (check_result_value(j_scheme_list, G_OK)) {
              json_object_set(json_object_get(j_result, "scheme"), scope_array[i], json_pack("{sOsO}", "password_required", json_object_get(json_object_get(j_scope, "scope"), "password_required"), "schemes", json_object_get(j_scheme_list, "scheme")));
            } else if (check_result_value(j_scheme_list, G_ERROR_NOT_FOUND)) {
              json_object_set(json_object_get(j_result, "scheme"), scope_array[i], json_pack("{sOs{}}", "password_required", json_object_get(json_object_get(j_scope, "scope"), "password_required"), "schemes"));
            }
            json_decref(j_scheme_list);
          }
          json_decref(j_scope);
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
  free_string_array(scope_array);
  return j_result;
}

static json_t * get_current_session(struct config_elements * config, const char * session_hash) {
  json_t * j_query, * j_result = NULL, * j_return;
  int res;
  char * expire_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?o_strdup("> NOW()"):o_strdup("> (strftime('%s','now'))");

  j_query = json_pack("{sss[ss]s{sssis{ssss}}sssi}",
                      "table",
                      GLEWLWYD_TABLE_USER_SESSION,
                      "columns",
                        "gus_id",
                        "gus_username AS username",
                      "where",
                        "gus_uuid",
                        session_hash,
                        "gus_enabled",
                        1,
                        "gus_expiration",
                          "operator",
                          "raw",
                          "value",
                          expire_clause,
                      "order_by",
                      "gus_last_login DESC",
                      "limit",
                      1);
  o_free(expire_clause);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result) > 0) {
      j_return = json_pack("{sisO}", "result", G_OK, "session", json_array_get(j_result, 0));
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_current_session - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  json_decref(j_result);
  return j_return;
}

static json_t * get_current_user_from_session(struct config_elements * config, const char * session_id) {
  char * session_hash;
  json_t * j_session, * j_return, * j_user;

  if (session_id != NULL && o_strlen(session_id)) {
    if ((session_hash = generate_hash(config, config->hash_algorithm, session_id)) != NULL) {
      j_session = get_current_session(config, session_hash);
      if (check_result_value(j_session, G_OK)) {
        j_user = get_user(config, json_string_value(json_object_get(json_object_get(j_session, "session"), "username")));
        if (check_result_value(j_user, G_OK)) {
          j_return = json_pack("{sisO}", "result", G_OK, "user", json_object_get(j_user, "user"));
        } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_current_user_from_session - Error get_user");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_current_user_from_session - Error get_current_session");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_session);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_current_user_from_session - Error generate_hash");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(session_hash);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

static int is_scheme_valid_for_session(struct config_elements * config, json_int_t guasmi_id, const char * session_hash) {
  char * expire_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?o_strdup("> NOW()"):o_strdup("> (strftime('%s','now'))");
  json_t * j_query, * j_result = NULL, * j_session = get_current_session(config, session_hash);
  int res, ret = 0;

  if (check_result_value(j_session, G_OK)) {
    j_query = json_pack("{sss[s]s{sOsos{ssss}si}}",
                        "table",
                        GLEWLWYD_TABLE_USER_SESSION_SCHEME,
                        "columns",
                          "guss_id",
                        "where",
                          "gus_id",
                          json_object_get(json_object_get(j_session, "session"), "gus_id"),
                          "guasmi_id",
                          guasmi_id?json_integer(guasmi_id):json_null(),
                          "guss_expiration",
                            "operator",
                            "raw",
                            "value",
                            expire_clause,
                          "guss_enabled",
                          1);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      ret = (json_array_size(j_result)>0);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_password_valid_for_session - Error executing j_query");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_password_valid_for_session - Error get_current_session");
  }
  json_decref(j_session);
  o_free(expire_clause);
  return ret;
}

json_t * get_validated_auth_scheme_list_from_scope_list(struct config_elements * config, const char * scope_list, const char * session_id) {
  char * session_hash = generate_hash(config, config->hash_algorithm, session_id);
  json_t * j_scheme_list = get_auth_scheme_list_from_scope_list(config, scope_list), * j_scope, * j_scheme, * j_group, * j_user = get_current_user_from_session(config, session_id);
  const char * key_scope, * key_group;
  size_t index_scheme;
  struct _user_auth_scheme_module_instance * scheme;
  
  if (check_result_value(j_scheme_list, G_OK)) {
    json_object_foreach(json_object_get(j_scheme_list, "scheme"), key_scope, j_scope) {
      if (check_result_value(j_user, G_OK)) {
          json_object_set(j_scope, "password_authenticated", is_scheme_valid_for_session(config, 0, session_hash)?json_true():json_false());
          if (user_has_scope(json_object_get(j_user, "user"), key_scope)) {
            json_object_set(j_scope, "available", json_true());
            json_object_foreach(json_object_get(j_scope, "schemes"), key_group, j_group) {
              json_array_foreach(j_group, index_scheme, j_scheme) {
                scheme = get_user_auth_scheme_module_instance(config, json_string_value(json_object_get(j_scheme, "scheme_type")), json_string_value(json_object_get(j_scheme, "scheme_name")));
                if (scheme != NULL && scheme->enabled) {
                  json_object_set(j_scheme, "scheme_authenticated", is_scheme_valid_for_session(config, scheme->guasmi_id, session_hash)?json_true():json_false());
                } else if (scheme != NULL && !scheme->enabled) {
                  json_object_set(j_scheme, "scheme_authenticated", json_null());
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "get_validated_auth_scheme_list_from_scope_list - Error get_user_auth_scheme_module_instance");
                }
              }
            }
          } else {
            json_object_set(j_scope, "available", json_false());
            json_object_clear(json_object_get(j_scope, "schemes"));
          }
      } else {
        json_object_del(j_scope, "schemes");
        json_object_del(j_scope, "password_required");
      }
    }
  }
  json_decref(j_user);
  o_free(session_hash);
  return j_scheme_list;
}

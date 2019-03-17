/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * scope management functions definition
 *
 * Copyright 2016-2019 Nicolas Mora <mail@babelouest.org>
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

json_t * get_scope_list(struct config_elements * config, const char * pattern, size_t offset, size_t limit) {
  json_t * j_query, * j_result, * j_return, * j_element, * j_scheme;
  int res;
  size_t index;
  char * pattern_escaped, * pattern_clause;

  j_query = json_pack("{sss[ssss]sisi}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "columns",
                        "gs_name AS name",
                        "gs_display_name AS display_name",
                        "gs_description AS description",
                        "gs_password_required",
                      "limit",
                      limit,
                      "offset",
                      offset);
  if (o_strlen(pattern)) {
    pattern_escaped = h_escape_string(config->conn, pattern);
    pattern_clause = msprintf("IN (SELECT `gs_id` FROM `" GLEWLWYD_TABLE_SCOPE "` WHERE `gs_name` LIKE '%%%s%%' OR `gs_display_name` LIKE '%%%s%%' OR `gs_description` LIKE '%%%s%%')", pattern_escaped, pattern_escaped, pattern_escaped);
    json_object_set_new(j_query, "where", json_pack("{s{ssss}}", "gs_id", "operator", "raw", "value", pattern_clause));
    o_free(pattern_escaped);
    o_free(pattern_clause);
  }
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      json_object_set(j_element, "password_required", json_integer_value(json_object_get(j_element, "gs_password_required"))?json_true():json_false());
      json_object_del(j_element, "gs_password_required");
      j_scheme = get_auth_scheme_list_from_scope(config, json_string_value(json_object_get(j_element, "name")));
      if (check_result_value(j_scheme, G_OK)) {
        json_object_set(j_element, "scheme", json_object_get(j_scheme, "scheme"));
      } else if (check_result_value(j_scheme, G_ERROR_NOT_FOUND)) {
        json_object_set_new(j_element, "scheme", json_object());
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_scope_list - Error get_auth_scheme_list_from_scope for scope %s", json_string_value(json_object_get(j_element, "name")));
      }
      json_decref(j_scheme);
    }
    j_return = json_pack("{siso}", "result", G_OK, "scope", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_scope_list - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

json_t * get_scope(struct config_elements * config, const char * scope) {
  json_t * j_query, * j_result = NULL, * j_return, * j_scheme;
  int res;

  j_query = json_pack("{sss[ssss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "columns",
                        "gs_name AS name",
                        "gs_display_name AS display_name",
                        "gs_description AS description",
                        "gs_password_required",
                      "where",
                        "gs_name",
                        scope);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      json_object_set(json_array_get(j_result, 0), "password_required", json_integer_value(json_object_get(json_array_get(j_result, 0), "gs_password_required"))?json_true():json_false());
      json_object_del(json_array_get(j_result, 0), "gs_password_required");
      j_scheme = get_auth_scheme_list_from_scope(config, scope);
      if (check_result_value(j_scheme, G_OK)) {
        json_object_set(json_array_get(j_result, 0), "scheme", json_object_get(j_scheme, "scheme"));
        j_return = json_pack("{sisO}", "result", G_OK, "scope", json_array_get(j_result, 0));
      } else if (check_result_value(j_scheme, G_ERROR_NOT_FOUND)) {
        json_object_set_new(json_array_get(j_result, 0), "scheme", json_object());
        j_return = json_pack("{sisO}", "result", G_OK, "scope", json_array_get(j_result, 0));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_scope - Error get_auth_scheme_list_from_scope");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_scheme);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_scope - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  json_decref(j_result);
  return j_return;
}

json_t * get_auth_scheme_list_from_scope(struct config_elements * config, const char * scope) {
  const char * str_query_pattern = "SELECT \
`gsg_name` AS group_name, \
`guasmi_module` AS scheme_type, \
`guasmi_name` AS scheme_name, \
`guasmi_display_name` AS scheme_display_name \
FROM \
`" GLEWLWYD_TABLE_SCOPE_GROUP "`, \
`" GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE "`, \
`" GLEWLWYD_TABLE_SCOPE_GROUP_AUTH_SCHEME_MODULE_INSTANCE "` \
WHERE \
`" GLEWLWYD_TABLE_SCOPE_GROUP_AUTH_SCHEME_MODULE_INSTANCE "`.`guasmi_id` = `" GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE "`.`guasmi_id` AND \
`" GLEWLWYD_TABLE_SCOPE_GROUP "`.`gsg_id` = `" GLEWLWYD_TABLE_SCOPE_GROUP_AUTH_SCHEME_MODULE_INSTANCE "`.`gsg_id` AND \
`" GLEWLWYD_TABLE_SCOPE_GROUP_AUTH_SCHEME_MODULE_INSTANCE "`.`gsg_id` IN  \
  (SELECT `gsg_id` FROM `" GLEWLWYD_TABLE_SCOPE_GROUP "` WHERE `gs_id` =  \
    (SELECT `gs_id` FROM `" GLEWLWYD_TABLE_SCOPE "` WHERE `gs_name`='%s')) \
ORDER BY \
`" GLEWLWYD_TABLE_SCOPE_GROUP "`.`gsg_id`;";
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
  o_free(scope_escape);
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
              json_object_set_new(json_object_get(j_result, "scheme"), scope_array[i], json_pack("{sOsO}", "password_required", json_object_get(json_object_get(j_scope, "scope"), "password_required"), "schemes", json_object_get(j_scheme_list, "scheme")));
            } else if (check_result_value(j_scheme_list, G_ERROR_NOT_FOUND)) {
              json_object_set_new(json_object_get(j_result, "scheme"), scope_array[i], json_pack("{sOs{}}", "password_required", json_object_get(json_object_get(j_scope, "scope"), "password_required"), "schemes"));
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

  j_query = json_pack("{sss[ss]s{sssis{ssss}si}sssi}",
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
                        "gus_current",
                        1,
                      "order_by",
                      "gus_current DESC",
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

static json_t * get_current_user_from_session(struct config_elements * config, const char * session_uid) {
  char * session_hash;
  json_t * j_session, * j_return, * j_user;

  if (session_uid != NULL && o_strlen(session_uid)) {
    if ((session_hash = generate_hash(config->hash_algorithm, session_uid)) != NULL) {
      j_session = get_current_session(config, session_hash);
      if (check_result_value(j_session, G_OK)) {
        j_user = get_user(config, json_string_value(json_object_get(json_object_get(j_session, "session"), "username")), NULL);
        if (check_result_value(j_user, G_OK)) {
          j_return = json_pack("{sisO}", "result", G_OK, "user", json_object_get(j_user, "user"));
        } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_current_user_from_session - Error get_user");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_user);
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

static int is_scheme_valid_for_session(struct config_elements * config, json_int_t guasmi_id, json_int_t max_use, const char * session_hash) {
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
    if (max_use > 0) {
      json_object_set_new(json_object_get(j_query, "where"), "guss_use_counter", json_pack("{sssI}", "operator", "<", "value", max_use));
    }
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      ret = (json_array_size(j_result)>0);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_password_valid_for_session - Error executing j_query");
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_password_valid_for_session - Error get_current_session");
  }
  json_decref(j_session);
  o_free(expire_clause);
  return ret;
}

json_t * get_validated_auth_scheme_list_from_scope_list(struct config_elements * config, const char * scope_list, const char * session_uid) {
  char * session_hash = generate_hash(config->hash_algorithm, session_uid);
  json_t * j_scheme_list = get_auth_scheme_list_from_scope_list(config, scope_list), * j_cur_scope, * j_scope, * j_scheme, * j_group, * j_user = get_current_user_from_session(config, session_uid), * j_scheme_remove;
  const char * key_scope, * key_group;
  size_t index_scheme;
  struct _user_auth_scheme_module_instance * scheme;
  
  if (check_result_value(j_scheme_list, G_OK)) {
    json_object_foreach(json_object_get(j_scheme_list, "scheme"), key_scope, j_cur_scope) {
      j_scope = get_scope(config, key_scope);
      if (check_result_value(j_scope, G_OK)) {
        if (check_result_value(j_user, G_OK)) {
          json_object_set(j_cur_scope, "display_name", json_object_get(json_object_get(j_scope, "scope"), "display_name"));
          json_object_set(j_cur_scope, "description", json_object_get(json_object_get(j_scope, "scope"), "description"));
          json_object_set(j_cur_scope, "password_authenticated", is_scheme_valid_for_session(config, 0, 0, session_hash)?json_true():json_false());
          if (user_has_scope(json_object_get(j_user, "user"), key_scope)) {
            json_object_set(j_cur_scope, "available", json_true());
            json_object_foreach(json_object_get(j_cur_scope, "schemes"), key_group, j_group) {
              j_scheme_remove = json_array();
              if (j_scheme_remove != NULL) {
                json_array_foreach(j_group, index_scheme, j_scheme) {
                  scheme = get_user_auth_scheme_module_instance(config, json_string_value(json_object_get(j_scheme, "scheme_name")));
                  if (scheme != NULL) {
                    if (scheme->enabled && scheme->module->user_can_use_scheme(json_string_value(json_object_get(json_object_get(j_user, "user"), "username")), scheme->cls)) {
                      json_object_set(j_scheme, "scheme_authenticated", is_scheme_valid_for_session(config, scheme->guasmi_id, scheme->guasmi_max_use, session_hash)?json_true():json_false());
                    } else {
                      json_array_append_new(j_scheme_remove, json_integer(index_scheme));
                    }
                  } else {
                    json_array_append_new(j_scheme_remove, json_integer(index_scheme));
                    y_log_message(Y_LOG_LEVEL_ERROR, "get_validated_auth_scheme_list_from_scope_list - Error get_user_auth_scheme_module_instance");
                  }
                }
                if (json_array_size(j_scheme_remove) > 0) {
                  index_scheme = json_array_size(j_scheme_remove);
                  do {
                    index_scheme--;
                    json_array_remove(j_group, json_integer_value(json_array_get(j_scheme_remove, index_scheme)));
                  } while (index_scheme != 0);
                }
                json_decref(j_scheme_remove);
                if (!json_array_size(j_group)) {
                  json_object_set(j_cur_scope, "available", json_false());
                  json_object_del(j_cur_scope, "password_required");
                  json_object_del(j_cur_scope, "password_authenticated");
                  json_object_clear(json_object_get(j_cur_scope, "schemes"));
                  break;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_validated_auth_scheme_list_from_scope_list - Error allocating resources for j_scheme_remove");
              }
            }
          } else {
            json_object_set(j_cur_scope, "available", json_false());
            json_object_del(j_cur_scope, "password_required");
            json_object_del(j_cur_scope, "password_authenticated");
            json_object_clear(json_object_get(j_cur_scope, "schemes"));
          }
        } else {
          json_object_del(j_cur_scope, "schemes");
          json_object_del(j_cur_scope, "password_required");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_validated_auth_scheme_list_from_scope_list - Error get_scope");
      }
      json_decref(j_scope);
    }
  }
  json_decref(j_user);
  o_free(session_hash);
  return j_scheme_list;
}

json_t * get_client_user_scope_grant(struct config_elements * config, const char * client_id, const char * username, const char * scope_list) {
  char ** scope_array = NULL;
  json_t * j_query, * j_result = NULL, * j_return, * j_element;
  int res, i;
  char * scope_clause, * scope_name_list = NULL, * scope_escaped, * tmp, * username_escaped, * client_id_escaped;
  size_t index;
  
  if (split_string(scope_list, " ", &scope_array) > 0) {
    for (i=0; scope_array[i] != NULL; i++) {
      scope_escaped = h_escape_string(config->conn, scope_array[i]);
      if (scope_name_list == NULL) {
        scope_name_list = msprintf("'%s'", scope_escaped);
      } else {
        tmp = msprintf("%s,'%s'", scope_name_list, scope_escaped);
        o_free(scope_name_list);
        scope_name_list = tmp;
      }
      o_free(scope_escaped);
    }
    if (scope_name_list != NULL) {
      username_escaped = h_escape_string(config->conn, username);
      client_id_escaped = h_escape_string(config->conn, client_id);
      scope_clause = msprintf("IN (SELECT `gs_id` FROM `" GLEWLWYD_TABLE_CLIENT_USER_SCOPE "` WHERE `gs_id` IN (SELECT `gs_id` FROM `" GLEWLWYD_TABLE_SCOPE "` WHERE `gs_name` IN (%s)) AND `gcus_username`='%s' AND `gcus_client_id`='%s' AND `gcus_enabled`=1)", scope_name_list, username_escaped, client_id_escaped);
      j_query = json_pack("{sss[ssss]s{s{ssss}}}",
                          "table",
                          GLEWLWYD_TABLE_SCOPE,
                          "columns",
                            "gs_name AS name",
                            "gs_display_name AS display_name",
                            "gs_description AS description",
                            "gs_password_required",
                          "where",
                            "gs_id",
                              "operator",
                              "raw",
                              "value",
                              scope_clause);
      o_free(scope_name_list);
      o_free(username_escaped);
      o_free(client_id_escaped);
      o_free(scope_clause);
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        json_array_foreach(j_result, index, j_element) {
          json_object_set(j_element, "password_required", json_integer_value(json_object_get(j_element, "gs_password_required"))?json_true():json_false());
          json_object_del(j_element, "gs_password_required");
        }
        j_return = json_pack("{sisO}", "result", G_OK, "scope", j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client_user_scope_grant - Error executing j_query");
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_client_user_scope_grant - Error scope_name_list");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_client_user_scope_grant - Error split_string");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  free_string_array(scope_array);
  return j_return;
}

json_t * get_granted_scopes_for_client(struct config_elements * config, json_t * j_user, const char * client_id, const char * scope_list) {
  json_t * j_scope_list, * j_element, * j_scope, * j_client, * j_return;
  char ** scope_array;
  int i, found;
  size_t index;

  j_client = get_client(config, client_id, NULL);
  if (check_result_value(j_client, G_OK) && json_object_get(json_object_get(j_client, "client"), "enabled") == json_true()) {
    j_scope_list = get_client_user_scope_grant(config, client_id, json_string_value(json_object_get(j_user, "username")), scope_list);
    if (check_result_value(j_scope_list, G_OK)) {
      if (split_string(scope_list, " ", &scope_array) > 0) {
        for (i=0; scope_array[i] != NULL; i++) {
          found = 0;
          json_array_foreach(json_object_get(j_scope_list, "scope"), index, j_element) {
            if (0 == o_strcmp(json_string_value(json_object_get(j_element, "name")), scope_array[i])) {
              json_object_set(j_element, "granted", json_true());
              found = 1;
            }
          }
          if (!found) {
            json_array_foreach(json_object_get(j_user, "scope"), index, j_element) {
              if (0 == o_strcmp(scope_array[i], json_string_value(j_element))) {
                j_scope = get_scope(config, scope_array[i]);
                if (check_result_value(j_scope, G_OK)) {
                  json_object_set(json_object_get(j_scope, "scope"), "granted", json_false());
                  json_array_append(json_object_get(j_scope_list, "scope"), json_object_get(j_scope, "scope"));
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_user_session_scope_grant - Error get_scope");
                }
                json_decref(j_scope);
              }
            }
          }
        }
        j_return = json_pack("{sis{s{sOsO}sO}}",
                              "result",
                              G_OK,
                              "grant",
                                "client",
                                  "client_id",
                                  json_object_get(json_object_get(j_client, "client"), "client_id"),
                                  "name",
                                  json_object_get(json_object_get(j_client, "client"), "name"),
                                "scope",
                                json_object_get(j_scope_list, "scope"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_user_session_scope_grant - Error split_string");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      free_string_array(scope_array);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_user_session_scope_grant - Error get_client_user_scope_grant");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_scope_list);
  } else if (check_result_value(j_client, G_OK) && json_object_get(json_object_get(j_client, "client"), "enabled") != json_true()) {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (check_result_value(j_client, G_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_user_session_scope_grant - Error get_client");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_client);
  return j_return;
}

int set_granted_scopes_for_client(struct config_elements * config, json_t * j_user, const char * client_id, const char * scope_list) {
  json_t * j_query, * j_element;
  char * scope_clause = NULL, * scope_escaped, ** scope_array = NULL;
  int res, ret = G_OK, i, has_granted;
  size_t index;

  j_query = json_pack("{sss{si}s{ssss}}",
                     "table",
                     GLEWLWYD_TABLE_CLIENT_USER_SCOPE,
                     "set",
                       "gcus_enabled",
                       0,
                     "where",
                       "gcus_username",
                       json_string_value(json_object_get(j_user, "username")),
                       "gcus_client_id",
                       client_id);
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (scope_list != NULL && o_strlen(scope_list)) {
      if (split_string(scope_list, " ", &scope_array) > 0) {
        has_granted = 0;
        for (i=0; scope_array[i] != NULL && ret != G_ERROR_DB; i++) {
          json_array_foreach(json_object_get(j_user, "scope"), index, j_element) {
            if (0 == o_strcmp(scope_array[i], json_string_value(j_element)) && ret != G_ERROR_DB) {
              has_granted = 1;
              scope_escaped = h_escape_string(config->conn, scope_array[i]);
              scope_clause = msprintf("(SELECT `gs_id` FROM `" GLEWLWYD_TABLE_SCOPE "` WHERE `gs_name`='%s')", scope_escaped);
              j_query = json_pack("{sss{s{ss}ssss}}",
                                  "table",
                                  GLEWLWYD_TABLE_CLIENT_USER_SCOPE,
                                  "values",
                                    "gs_id",
                                      "raw",
                                      scope_clause,
                                    "gcus_username",
                                    json_string_value(json_object_get(j_user, "username")),
                                    "gcus_client_id",
                                    client_id);
              o_free(scope_clause);
              res = h_insert(config->conn, j_query, NULL);
              if (res != H_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "set_granted_scopes_for_client - Error executing j_query (2)");
                ret = G_ERROR_DB;
              }
              json_decref(j_query);
              o_free(scope_escaped);
            }
          }
        }
        if (!has_granted) {
          ret = G_ERROR_UNAUTHORIZED;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_granted_scopes_for_client - Error split_string");
      }
      free_string_array(scope_array);
    } else {
      ret = G_OK;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_granted_scopes_for_client - Error executing j_query (1)");
    ret = G_ERROR_DB;
  }
  return ret;
}

json_t * get_scope_list_allowed_for_session(struct config_elements * config, const char * scope_list, const char * session_uid) {
  json_t * j_scheme_list = get_validated_auth_scheme_list_from_scope_list(config, scope_list, session_uid), * j_scope, * j_group, * j_scheme, * j_scope_allowed = NULL;
  int ret, group_allowed, scope_allowed;
  const char * scope, * group;
  size_t index;

  if (check_result_value(j_scheme_list, G_OK)) {
    j_scope_allowed = json_array();
    if (j_scope_allowed != NULL) {
      ret = G_OK;
      // Iterate in each scopes
      json_object_foreach(json_object_get(j_scheme_list, "scheme"), scope, j_scope) {
        scope_allowed = 1;
        if (json_object_get(j_scope, "available") == json_true()) {
          if (json_object_get(j_scope, "password_required") == json_true() && json_object_get(j_scope, "password_authenticated") == json_false()) {
            ret = G_ERROR_UNAUTHORIZED;
            scope_allowed = 0;
          } else {
            json_object_foreach(json_object_get(j_scope, "schemes"), group, j_group) {
              group_allowed = 0;
              json_array_foreach(j_group, index, j_scheme) {
                if (!group_allowed && json_object_get(j_scheme, "scheme_authenticated") == json_true()) {
                  group_allowed = 1;
                }
              }
              if (!group_allowed) {
                ret = G_ERROR_UNAUTHORIZED;
                scope_allowed = 0;
              }
            }
          }
          if (scope_allowed) {
            json_array_append_new(j_scope_allowed, json_string(scope));
          }
        }
      }
      if (ret == G_OK && !json_array_size(j_scope_allowed)) {
        ret = G_ERROR_UNAUTHORIZED;
        json_decref(j_scope_allowed);
        j_scope_allowed = NULL;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_scope_list_allowed_for_session - Error iallocating resources for j_scope_allowed");
      ret = G_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_scope_list_allowed_for_session - Error get_validated_auth_scheme_list_from_scope_list");
    ret = G_ERROR;
  }
  json_decref(j_scheme_list);
  if (ret == G_OK) {
    return json_pack("{sisO}", "result", ret, "scope", j_scope_allowed);
  } else {
    return json_pack("{si}", "result", ret);
  }
}

json_t * is_scope_valid(struct config_elements * config, const char * scope, json_t * j_scope, int add) {
  json_t * j_return, * j_array, * j_group, * j_scheme, * j_module;
  size_t index;
  const char * key;
  char * message;

  if (json_is_object(j_scope)) {
    j_array = json_array();
    if (j_array != NULL) {
      if (add) {
        if (!json_is_string(json_object_get(j_scope, "name")) || !json_string_length(json_object_get(j_scope, "name")) || json_string_length(json_object_get(j_scope, "name")) > 128) {
          json_array_append_new(j_array, json_string("name is mandatory and must be string between 1 and 128 characters"));
        }
      }
      if (json_object_get(j_scope, "display_name") != NULL && (!json_is_string(json_object_get(j_scope, "display_name")) || !json_string_length(json_object_get(j_scope, "display_name")) || json_string_length(json_object_get(j_scope, "display_name")) > 256)) {
        json_array_append_new(j_array, json_string("display_name is optional and must be string between 1 and 256 characters"));
      }
      if (json_object_get(j_scope, "description") != NULL && (!json_is_string(json_object_get(j_scope, "description")) || !json_string_length(json_object_get(j_scope, "description")) || json_string_length(json_object_get(j_scope, "description")) > 512)) {
        json_array_append_new(j_array, json_string("description is optional and must be string between 1 and 512 characters"));
      }
      if (json_object_get(j_scope, "password_required") != NULL && !json_is_boolean(json_object_get(j_scope, "password_required"))) {
        json_array_append_new(j_array, json_string("password_required is optional and must be a boolean"));
      }
      if (json_object_get(j_scope, "scheme") != NULL && !json_is_object(json_object_get(j_scope, "scheme"))) {
        json_array_append_new(j_array, json_string("scheme is optional and must be a JSON object"));
      } else {
        json_object_foreach(json_object_get(j_scope, "scheme"), key, j_group) {
          if (!json_is_array(j_group) || !json_array_size(j_group)) {
            json_array_append_new(j_array, json_string("scheme group must be a non empty JSON array"));
          } else {
            json_array_foreach(j_group, index, j_scheme) {
              if (!json_is_object(j_scheme) || !json_object_size(j_scheme)) {
                json_array_append_new(j_array, json_string("scheme must be a non empty JSON object"));
              } else {
                if (!json_is_string(json_object_get(j_scheme, "scheme_name")) || !json_string_length(json_object_get(j_scheme, "scheme_name"))) {
                  json_array_append_new(j_array, json_string("scheme_name must be a non empty string"));
                } else {
                  j_module = get_user_auth_scheme_module(config, json_string_value(json_object_get(j_scheme, "scheme_name")));
                  if (check_result_value(j_module, G_ERROR_NOT_FOUND)) {
                    message = msprintf("scheme_name '%s' does not exist", json_string_value(json_object_get(j_scheme, "scheme_name")));
                    json_array_append_new(j_array, json_string(message));
                    o_free(message);
                  } else if (!check_result_value(j_module, G_OK)) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "is_scope_valid - Error get_user_auth_scheme_module");
                  }
                  json_decref(j_module);
                }
              }
            }
          }
        }
      }
      if (json_array_size(j_array)) {
        j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_array);
      } else {
        j_return = json_pack("{si}", "result", G_OK);
      }
      json_decref(j_array);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_scope_valid - Error allocating resources for j_array");
      j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
    }
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "Parameter must be a JSON object");
  }
  return j_return;
}

static int add_scope_scheme_groups(struct config_elements * config, const char * scope, json_t * j_scheme) {
  json_t * j_query, * j_scope_group, * j_scope_group_id, * j_scheme_module;
  int res, ret = G_OK;
  char * scope_escaped, * scope_clause, * scheme_escaped, * scheme_module_clause;
  const char * group_name;
  size_t index;

  scope_escaped = h_escape_string(config->conn, scope);
  scope_clause = msprintf("(SELECT `gs_id` FROM `" GLEWLWYD_TABLE_SCOPE "` WHERE `gs_name`='%s')", scope_escaped);

  json_object_foreach(j_scheme, group_name, j_scope_group) {
    j_query = json_pack("{sss{s{ss}ss}}",
                        "table",
                        GLEWLWYD_TABLE_SCOPE_GROUP,
                        "values",
                          "gs_id",
                            "raw",
                            scope_clause,
                          "gsg_name",
                          group_name);
    res = h_insert(config->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      j_scope_group_id = h_last_insert_id(config->conn);
      if (j_scope_group_id != NULL && json_integer_value(j_scope_group_id) > 0) {
        json_array_foreach(j_scope_group, index, j_scheme_module) {
          scheme_escaped = h_escape_string(config->conn, json_string_value(json_object_get(j_scheme_module, "scheme_name")));
          scheme_module_clause = msprintf("(SELECT `guasmi_id` FROM `" GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE "` WHERE `guasmi_name`='%s')", scheme_escaped);
          j_query = json_pack("{sss{sOs{ss}}}",
                              "table",
                              GLEWLWYD_TABLE_SCOPE_GROUP_AUTH_SCHEME_MODULE_INSTANCE,
                              "values",
                                "gsg_id",
                                j_scope_group_id,
                                "guasmi_id",
                                  "raw",
                                  scheme_module_clause);
          o_free(scheme_module_clause);
          o_free(scheme_escaped);
          res = h_insert(config->conn, j_query, NULL);
          json_decref(j_query);
          if (res != H_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "add_scope_scheme_groups - Error executing j_query (2)");
            ret = G_ERROR_DB;
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_scope_scheme_groups - Error h_last_insert_id");
        ret = G_ERROR_DB;
      }
      json_decref(j_scope_group_id);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_scope_scheme_groups - Error executing j_query (1)");
      ret = G_ERROR_DB;
    }
  }
  o_free(scope_escaped);
  o_free(scope_clause);
  return ret;
}

int add_scope(struct config_elements * config, json_t * j_scope) {
  json_t * j_query;
  int res, ret;

  j_query = json_pack("{sss{sOsOsOsi}}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "values",
                        "gs_name",
                        json_object_get(j_scope, "name"),
                        "gs_display_name",
                        json_object_get(j_scope, "display_name")!=NULL?json_object_get(j_scope, "display_name"):json_null(),
                        "gs_description",
                        json_object_get(j_scope, "description")!=NULL?json_object_get(j_scope, "description"):json_null(),
                        "gs_password_required",
                        json_object_get(j_scope, "password_required")==json_false()?0:1);
  res = h_insert(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_object_get(j_scope, "scheme") != NULL && json_object_size(json_object_get(j_scope, "scheme"))) {
      if (add_scope_scheme_groups(config, json_string_value(json_object_get(j_scope, "name")), json_object_get(j_scope, "scheme")) == G_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_scope - Error add_scope_scheme_groups");
        ret = G_ERROR;
      }
    } else {
      ret = G_OK;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_scope - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

int set_scope(struct config_elements * config, const char * scope, json_t * j_scope) {
  json_t * j_query;
  char * scope_escaped, * scope_clause;
  int res, ret;

  scope_escaped = h_escape_string(config->conn, scope);
  scope_clause = msprintf("IN (SELECT `gs_id` FROM `" GLEWLWYD_TABLE_SCOPE "` WHERE `gs_name`='%s')", scope_escaped);
  j_query = json_pack("{sss{s{ssss}}}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE_GROUP,
                      "where",
                        "gs_id",
                          "operator",
                          "raw",
                          "value",
                          scope_clause);
  o_free(scope_clause);
  o_free(scope_escaped);
  res = h_delete(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_query = json_pack("{sss{sOsOsi}s{ss}}",
                        "table",
                        GLEWLWYD_TABLE_SCOPE,
                        "set",
                          "gs_display_name",
                          json_object_get(j_scope, "display_name")!=NULL?json_object_get(j_scope, "display_name"):json_null(),
                          "gs_description",
                          json_object_get(j_scope, "description")!=NULL?json_object_get(j_scope, "description"):json_null(),
                          "gs_password_required",
                          json_object_get(j_scope, "password_required")==json_false()?0:1,
                        "where",
                          "gs_name",
                          scope);
    res = h_update(config->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (add_scope_scheme_groups(config, scope, json_object_get(j_scope, "scheme")) == G_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_scope - Error add_scope_scheme_groups");
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "set_scope - Error executing j_query (2)");
      ret = G_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_scope - Error executing j_query (1)");
    ret = G_ERROR_DB;
  }
  return ret;
}

int delete_scope(struct config_elements * config, const char * scope) {
  json_t * j_query;
  int res, ret;

  j_query = json_pack("{sss{ss}}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "where",
                        "gs_name",
                        scope);
  res = h_delete(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "delete_scope - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

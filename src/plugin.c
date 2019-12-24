/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Definitions for functions used in plugin modules
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

#include <string.h>
#include <ctype.h>
#include "glewlwyd.h"

int glewlwyd_callback_add_plugin_endpoint(struct config_plugin * config, const char * method, const char * name, const char * url, unsigned int priority, int (* callback)(const struct _u_request * request, struct _u_response * response, void * user_data), void * user_data) {
  int ret;
  char * p_url;

  if (config != NULL && config->glewlwyd_config != NULL && config->glewlwyd_config->instance != NULL && method != NULL && name != NULL && url != NULL && callback != NULL && 0 != o_strncasecmp(name, "auth", o_strlen("auth"))) {
    p_url = msprintf("%s/%s", name, url);
    if (p_url != NULL) {
      if ((ret = ulfius_add_endpoint_by_val(config->glewlwyd_config->instance, method, config->glewlwyd_config->api_prefix, p_url, GLEWLWYD_CALLBACK_PRIORITY_PLUGIN + priority, callback, user_data)) != U_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_add_plugin_endpoint - Error %d ulfius_add_endpoint_by_val %s - %s/%s",ret, method, config->glewlwyd_config->api_prefix, p_url);
        ret = G_ERROR;
      } else {
        y_log_message(Y_LOG_LEVEL_INFO, "Add endpoint %s %s/%s", method, config->glewlwyd_config->api_prefix, p_url);
        ret = G_OK;
      }
      o_free(p_url);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_add_plugin_endpoint - Error allocating resources for p_url");
      ret = G_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_add_plugin_endpoint - Error input paramters");
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int glewlwyd_callback_remove_plugin_endpoint(struct config_plugin * config, const char * method, const char * name, const char * url) {
  int ret;
  char * p_url;

  if (config != NULL && config->glewlwyd_config != NULL && config->glewlwyd_config->instance != NULL && method != NULL && name != NULL && url != NULL) {
    p_url = msprintf("%s/%s", name, url);
    if (p_url != NULL) {
      if ((ret = ulfius_remove_endpoint_by_val(config->glewlwyd_config->instance, method, config->glewlwyd_config->api_prefix, p_url)) != U_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_remove_plugin_endpoint - Error %d ulfius_remove_endpoint_by_val %s - %s/%s", ret, method, config->glewlwyd_config->api_prefix, p_url);
        ret = G_ERROR;
      } else {
        y_log_message(Y_LOG_LEVEL_INFO, "Remove endpoint %s %s/%s", method, config->glewlwyd_config->api_prefix, p_url);
        ret = G_OK;
      }
      o_free(p_url);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_remove_plugin_endpoint - Error allocating resources for p_url");
      ret = G_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_remove_plugin_endpoint - Error input paramters");
    ret = G_ERROR_PARAM;
  }
  return ret;
}

json_t * glewlwyd_callback_check_session_valid(struct config_plugin * config, const struct _u_request * request, const char * scope_list) {
  json_t * j_user, * j_return, * j_scope_allowed;
  char * session_uid = NULL;
  
  if (config != NULL && request != NULL) {
    session_uid = get_session_id(config->glewlwyd_config, request);
    j_user = get_current_user_for_session(config->glewlwyd_config, session_uid);
    // Check if session is valid
    if (check_result_value(j_user, G_OK)) {
      if (o_strlen(scope_list)) {
        // For all allowed scope, check that the current session has a valid session
        j_scope_allowed = get_validated_auth_scheme_list_from_scope_list(config->glewlwyd_config, scope_list, session_uid);
        if (check_result_value(j_scope_allowed, G_OK)) {
          j_return = json_pack("{sis{sOsO}}", "result", G_OK, "session", "scope", json_object_get(j_scope_allowed, "scheme"), "user", json_object_get(j_user, "user"));
        } else if (check_result_value(j_scope_allowed, G_ERROR_UNAUTHORIZED) || check_result_value(j_scope_allowed, G_ERROR_NOT_FOUND)) {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_check_session_valid - Error get_validated_auth_scheme_list_from_scope_list");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_scope_allowed);
      } else {
        j_return = json_pack("{sis{sO}}", "result", G_OK, "session", "user", json_object_get(j_user, "user"));
      }
    } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_check_session_valid - Error get_current_user_for_session");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_user);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  o_free(session_uid);
  return j_return;
}

json_t * glewlwyd_callback_check_user_valid(struct config_plugin * config, const char * username, const char * password, const char * scope) {
  json_t * j_user, * j_return, * j_auth, * j_element, * j_scope;
  int check_password, check_scope;
  char ** scope_array = NULL, * scope_list = NULL, * tmp;
  size_t index;

  if (config != NULL && username != NULL) {
    j_user = get_user(config->glewlwyd_config, username, NULL);
    if (check_result_value(j_user, G_OK)) {
      check_password = 1;
      if (password != NULL) {
        j_auth = auth_check_user_credentials(config->glewlwyd_config, username, password);
        if (!check_result_value(j_auth, G_OK)) {
          check_password = 0;
        }
        json_decref(j_auth);
      }
      check_scope = 1;
      if (scope != NULL) {
        if (split_string(scope, " ", &scope_array) > 0) {
          json_array_foreach(json_object_get(json_object_get(j_user, "user"), "scope"), index, j_element) {
            if (string_array_has_value((const char **)scope_array, json_string_value(j_element))) {
              // Check if scope has no scheme but password
              j_scope = get_scope(config->glewlwyd_config, json_string_value(j_element));
              if (check_result_value(j_scope, G_OK)) {
                if (json_object_size(json_object_get(json_object_get(j_scope, "scope"), "scheme")) == 0 && json_object_get(json_object_get(j_scope, "scope"), "password_required") == json_true()) {
                  if (scope_list == NULL) {
                    scope_list = o_strdup(json_string_value(j_element));
                  } else {
                    tmp = msprintf("%s %s", scope_list, json_string_value(j_element));
                    o_free(scope_list);
                    scope_list = tmp;
                  }
                }
              } else if (!check_result_value(j_scope, G_ERROR_NOT_FOUND)) {
                y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_check_user_valid - Error get_scope");
              }
              json_decref(j_scope);
            }
          }
          if (scope_list != NULL) {
            json_object_set_new(json_object_get(j_user, "user"), "scope_list", json_string(scope_list));
          } else {
            check_scope = 0;
          }
          o_free(scope_list);
        } else  {
          y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_check_user_valid - Error split_string");
          check_scope = 0;
        }
        free_string_array(scope_array);
      }
      if (check_password && check_scope) {
        j_return = json_pack("{sisO}", "result", G_OK, "user", json_object_get(j_user, "user"));
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
    } else if (check_result_value(j_user, G_ERROR_NOT_FOUND) || (check_result_value(j_user, G_OK) && json_object_get(json_object_get(j_user, "user"), "enabled") != json_true())) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_check_user_valid - Error get_user");
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    }
    json_decref(j_user);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_check_user_valid - Error input parameters");
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

json_t * glewlwyd_callback_check_client_valid(struct config_plugin * config, const char * client_id, const char * password) {
  json_t * j_return, * j_client, * j_client_credentials;
  int password_checked = 1;

  if (config != NULL && client_id != NULL) {
    j_client = get_client(config->glewlwyd_config, client_id, NULL);
    if (check_result_value(j_client, G_OK) && json_object_get(json_object_get(j_client, "client"), "enabled") == json_true()) {
      if (password != NULL) {
        if (json_string_length(json_object_get(json_object_get(j_client, "client"), "client_secret"))) {
          if (0 != o_strcmp(password, json_string_value(json_object_get(json_object_get(j_client, "client"), "client_secret")))) {
            password_checked = 0;
          }
        } else {
          j_client_credentials = auth_check_client_credentials(config->glewlwyd_config, client_id, password);
          if (!check_result_value(j_client_credentials, G_OK)) {
            password_checked = 0;
          }
          json_decref(j_client_credentials);
        }
      }
      if (password_checked) {
        j_return = json_pack("{sisO}", "result", G_OK, "client", json_object_get(j_client, "client"));
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
    } else if (check_result_value(j_client, G_ERROR_NOT_FOUND) || (check_result_value(j_client, G_OK) && json_object_get(json_object_get(j_client, "client"), "enabled") != json_true())) {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_check_client_valid - Error get_client");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_client);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

json_t * glewlwyd_callback_get_client_granted_scopes(struct config_plugin * config, const char * client_id, const char * username, const char * scope_list) {
  json_t * j_user = get_user(config->glewlwyd_config, username, NULL), * j_grant = NULL;
  if (check_result_value(j_user, G_OK)) {
    j_grant = get_granted_scopes_for_client(config->glewlwyd_config, json_object_get(j_user, "user"), client_id, scope_list);
  } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)){
    j_grant = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_get_client_granted_scopes - Error get_user");
    j_grant = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_user);
  return j_grant;
}

int glewlwyd_callback_trigger_session_used(struct config_plugin * config, const struct _u_request * request, const char * scope_list) {
  json_t * j_session = glewlwyd_callback_check_session_valid(config, request, scope_list), * j_query, * j_scope, * j_scheme_processed, * j_group, * j_scheme;
  char * session_uid = get_session_id(config->glewlwyd_config, request), * session_hash = NULL, * clause_session, * username_escaped, * clause_scheme, * escape_scheme_module, * escape_scheme_name;
  int ret, res, password_processed = 0;
  const char * key_scope, * key_group;
  size_t index;

  if (check_result_value(j_session, G_OK) || session_uid == NULL) {
    if ((session_hash = generate_hash(config->glewlwyd_config->hash_algorithm, session_uid)) != NULL) {
      j_scheme_processed = json_object();
      if (j_scheme_processed != NULL) {
        ret = G_OK;
        username_escaped = h_escape_string_with_quotes(config->glewlwyd_config->conn, json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")));
        clause_session = msprintf("IN (SELECT gus_id FROM " GLEWLWYD_TABLE_USER_SESSION " WHERE gus_session_hash='%s' AND gus_username=%s AND gus_expiration %s AND gus_enabled=1 AND gus_current=1)", session_hash, username_escaped, SWITCH_DB_TYPE(config->glewlwyd_config->conn->type, "> NOW()", "> (strftime('%s','now'))", "> NOW()"));
        json_object_foreach(json_object_get(json_object_get(j_session, "session"), "scope"), key_scope, j_scope) {
          if (!password_processed && json_object_get(j_scope, "password_authenticated") == json_true()) {
            password_processed = 1;
            // Increment guss_use_counter for the password scheme on the specified session
            j_query = json_pack("{sss{s{ss}}s{sOs{ssss}sis{ssss}}}",
                                "table",
                                GLEWLWYD_TABLE_USER_SESSION_SCHEME,
                                "set",
                                  "guss_use_counter",
                                    "raw",
                                    "(guss_use_counter + 1)",
                                "where",
                                  "guasmi_id",
                                  json_null(),
                                  "gus_id",
                                    "operator",
                                    "raw",
                                    "value",
                                    clause_session,
                                  "guss_enabled",
                                  1,
                                  "guss_expiration",
                                    "operator",
                                    "raw",
                                    "value",
                                    SWITCH_DB_TYPE(config->glewlwyd_config->conn->type, "> NOW()", "> (strftime('%s','now'))", "> NOW()"));
            res = h_update(config->glewlwyd_config->conn, j_query, NULL);
            json_decref(j_query);
            if (res != H_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_trigger_session_used - Error h_update for password scheme");
              ret = G_ERROR_DB;
            }
          }
          json_object_foreach(json_object_get(j_scope, "schemes"), key_group, j_group) {
            json_array_foreach(j_group, index, j_scheme) {
              if (json_object_get(j_scheme, "scheme_authenticated") == json_true() && json_object_get(j_scheme_processed, json_string_value(json_object_get(j_scheme, "scheme_name"))) == NULL) {
                json_object_set_new(j_scheme_processed, json_string_value(json_object_get(j_scheme, "scheme_name")), json_object());
                // Increment guss_use_counter for the specified scheme on the specified session
                escape_scheme_module = h_escape_string_with_quotes(config->glewlwyd_config->conn, json_string_value(json_object_get(j_scheme, "scheme_type")));
                escape_scheme_name = h_escape_string_with_quotes(config->glewlwyd_config->conn, json_string_value(json_object_get(j_scheme, "scheme_name")));
                clause_scheme = msprintf("IN (SELECT guasmi_id FROM " GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE " WHERE guasmi_module=%s AND guasmi_name=%s)", escape_scheme_module, escape_scheme_name);
                j_query = json_pack("{sss{s{ss}}s{s{ssss}s{ssss}sis{ssss}}}",
                                    "table",
                                    GLEWLWYD_TABLE_USER_SESSION_SCHEME,
                                    "set",
                                      "guss_use_counter",
                                        "raw",
                                        "(guss_use_counter + 1)",
                                    "where",
                                      "guasmi_id",
                                        "operator",
                                        "raw",
                                        "value",
                                        clause_scheme,
                                      "gus_id",
                                        "operator",
                                        "raw",
                                        "value",
                                        clause_session,
                                      "guss_enabled",
                                      1,
                                      "guss_expiration",
                                        "operator",
                                        "raw",
                                        "value",
                                        SWITCH_DB_TYPE(config->glewlwyd_config->conn->type, "> NOW()", "> (strftime('%s','now'))", "> NOW()"));
                o_free(clause_scheme);
                o_free(escape_scheme_name);
                o_free(escape_scheme_module);
                res = h_update(config->glewlwyd_config->conn, j_query, NULL);
                json_decref(j_query);
                if (res != H_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_trigger_session_used - Error h_update for scheme %s/%s", json_string_value(json_object_get(j_scheme, "scheme_type")), json_string_value(json_object_get(j_scheme, "scheme_name")));
                  ret = G_ERROR_DB;
                }
              }
            }
          }
        }
        o_free(username_escaped);
        o_free(clause_session);
        json_decref(j_scheme_processed);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_trigger_session_used - Error allocating resources for j_scheme_processed");
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_trigger_session_used - Error generate_hash");
      ret = G_ERROR;
    }
    o_free(session_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_trigger_session_used - Error glewlwyd_callback_check_session_valid or session_uid NULL");
    ret = G_ERROR;
  }
  json_decref(j_session);
  o_free(session_uid);
  return ret;
}

time_t glewlwyd_callback_get_session_age(struct config_plugin * config, const struct _u_request * request, const char * scope_list) {
  time_t age = 0;
  char * session_uid = get_session_id(config->glewlwyd_config, request), * session_uid_hash, * query, ** scope_array = NULL, * scope_escaped, * scope_list_clause = NULL;
  json_t * j_result;
  
  if (session_uid != NULL) {
    session_uid_hash = generate_hash(config->glewlwyd_config->hash_algorithm, session_uid);
    if (session_uid_hash != NULL) {
      if (split_string(scope_list, " ", &scope_array)) {
        for (int i=0; scope_array[i] != NULL; i++) {
          scope_escaped = h_escape_string_with_quotes(config->glewlwyd_config->conn, scope_array[i]);
          if (scope_list_clause == NULL) {
            scope_list_clause = msprintf("%s", scope_escaped);
          } else {
            scope_list_clause = mstrcatf(scope_list_clause, ",%s", scope_escaped);
          }
          o_free(scope_escaped);
        }
        if (scope_list_clause != NULL) {
          // Quey to retreive the most recent, enabled and succeeded authentication date for the current session
          query = msprintf("SELECT %s FROM " GLEWLWYD_TABLE_USER_SESSION_SCHEME " WHERE guss_enabled=1 AND gus_id IN (SELECT gus_id FROM " GLEWLWYD_TABLE_USER_SESSION " WHERE gus_session_hash='%s' AND gus_current=1) AND (guasmi_id IS NULL OR guasmi_id IN (SELECT guasmi_id FROM " GLEWLWYD_TABLE_SCOPE_GROUP_AUTH_SCHEME_MODULE_INSTANCE " WHERE gsg_id IN (SELECT gsg_id FROM " GLEWLWYD_TABLE_SCOPE_GROUP " WHERE gs_id IN (SELECT gs_id FROM " GLEWLWYD_TABLE_SCOPE " WHERE gs_name IN (%s))))) ORDER BY guss_last_login DESC LIMIT 1;", (SWITCH_DB_TYPE(config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(guss_last_login) AS guss_last_login", "guss_last_login", "EXTRACT(EPOCH FROM guss_last_login)::integer AS guss_last_login")), session_uid_hash, scope_list_clause);
          if (h_execute_query_json(config->glewlwyd_config->conn, query, &j_result) == H_OK) {
            if (json_array_size(j_result)) {
              age = (time_t)json_integer_value(json_object_get(json_array_get(j_result, 0), "guss_last_login"));
            }
            json_decref(j_result);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_get_session_age - Error executig query");
          }
          o_free(query);
        }
        o_free(scope_list_clause);
        free_string_array(scope_array);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_get_session_age - Error split_string");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_get_session_age - Error generate_hash for session_uid");
    }
    o_free(session_uid_hash);
  }
  o_free(session_uid);
  return age;
}

char * glewlwyd_callback_get_login_url(struct config_plugin * config, const char * client_id, const char * scope_list, const char * callback_url, struct _u_map * additional_parameters) {
  char * encoded_callback_url = NULL, * encoded_client_id = NULL, * encoded_scope_list = NULL, * login_url, * query_additional_parameters = NULL, * value_encoded;
  const char ** keys;
  int i;
  
  if (callback_url != NULL) {
    encoded_callback_url = url_encode(callback_url);
  }
  if (client_id != NULL) {
    encoded_client_id = url_encode(client_id);
  }
  if (scope_list != NULL) {
    encoded_scope_list = url_encode(scope_list);
  }
  if (additional_parameters != NULL) {
    keys = u_map_enum_keys(additional_parameters);
    for (i=0; keys[i]!=NULL; i++) {
      if (u_map_get(additional_parameters, keys[i]) == NULL) {
        query_additional_parameters = mstrcatf(query_additional_parameters, "&%s", keys[i]);
      } else {
        value_encoded = url_encode(u_map_get(additional_parameters, keys[i]));
        query_additional_parameters = mstrcatf(query_additional_parameters, "&%s=%s", keys[i], value_encoded);
        o_free(value_encoded);
      }
    }
  }
  login_url = msprintf("%s/%s?%s%s%s%s%s%s%s",
                       config->glewlwyd_config->external_url,
                       config->glewlwyd_config->login_url,
                       (encoded_client_id!=NULL?"client_id=":""),
                       (encoded_client_id!=NULL?encoded_client_id:""),
                       (encoded_scope_list!=NULL?"&scope=":""),
                       (encoded_scope_list!=NULL?encoded_scope_list:""),
                       (encoded_callback_url!=NULL?"&callback_url=":""),
                       (encoded_callback_url!=NULL?encoded_callback_url:""),
                       (query_additional_parameters!=NULL?query_additional_parameters:""));
  o_free(query_additional_parameters);
  o_free(encoded_callback_url);
  o_free(encoded_client_id);
  o_free(encoded_scope_list);
  return login_url;
}

char * glewlwyd_callback_get_plugin_external_url(struct config_plugin * config, const char * name) {
  return msprintf("%s/%s/%s", config->glewlwyd_config->external_url, config->glewlwyd_config->api_prefix, name);
}

char * glewlwyd_callback_generate_hash(struct config_plugin * config, const char * data) {
  return generate_hash(config->glewlwyd_config->hash_algorithm, data);
}

json_t * glewlwyd_plugin_callback_get_user_list(struct config_plugin * config, const char * pattern, size_t offset, size_t limit) {
  return get_user_list(config->glewlwyd_config, pattern, offset, limit, NULL);
}

json_t * glewlwyd_plugin_callback_get_user(struct config_plugin * config, const char * username) {
  return get_user(config->glewlwyd_config, username, NULL);
}

json_t * glewlwyd_plugin_callback_get_user_profile(struct config_plugin * config, const char * username) {
  return get_user_profile(config->glewlwyd_config, username, NULL);
}

json_t * glewlwyd_plugin_callback_is_user_valid(struct config_plugin * config, const char * username, json_t * j_user, int add) {
  return is_user_valid(config->glewlwyd_config, username, j_user, add, NULL);
}

int glewlwyd_plugin_callback_add_user(struct config_plugin * config, json_t * j_user) {
  return add_user(config->glewlwyd_config, j_user, NULL);
}

int glewlwyd_plugin_callback_set_user(struct config_plugin * config, const char * username, json_t * j_user) {
  json_t * j_cur_user = get_user(config->glewlwyd_config, username, NULL);
  int ret;
  
  if (check_result_value(j_cur_user, G_OK)) {
    ret = set_user(config->glewlwyd_config, username, j_user, json_string_value(json_object_get(json_object_get(j_cur_user, "user"), "source")));
  } else if (check_result_value(j_cur_user, G_ERROR_NOT_FOUND)) {
    ret = U_ERROR_NOT_FOUND;
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "glewlwyd_plugin_callback_set_user - Error get_user");
    ret = G_ERROR;
  }
  json_decref(j_cur_user);
  return ret;
}

int glewlwyd_plugin_callback_user_update_password(struct config_plugin * config, const char * username, const char * password) {
  json_t * j_user = get_user(config->glewlwyd_config, username, NULL);
  int ret;
  
  if (check_result_value(j_user, G_OK)) {
    ret = user_set_password(config->glewlwyd_config, username, password);
  } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
    ret = U_ERROR_NOT_FOUND;
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "glewlwyd_plugin_callback_user_update_password - Error get_user");
    ret = G_ERROR;
  }
  json_decref(j_user);
  return ret;
}

int glewlwyd_plugin_callback_delete_user(struct config_plugin * config, const char * username) {
  json_t * j_user = get_user(config->glewlwyd_config, username, NULL);
  int ret;
  
  if (check_result_value(j_user, G_OK)) {
    ret = delete_user(config->glewlwyd_config, username, json_string_value(json_object_get(json_object_get(j_user, "user"), "source")));
  } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
    ret = U_ERROR_NOT_FOUND;
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "glewlwyd_plugin_callback_set_user - Error get_user");
    ret = G_ERROR;
  }
  json_decref(j_user);
  return ret;
}

json_t * glewlwyd_plugin_callback_get_client_list(struct config_plugin * config, const char * pattern, size_t offset, size_t limit) {
  return get_client_list(config->glewlwyd_config, pattern, offset, limit, NULL);
}

json_t * glewlwyd_plugin_callback_get_client(struct config_plugin * config, const char * client_id) {
  return get_client(config->glewlwyd_config, client_id, NULL);
}

json_t * glewlwyd_plugin_callback_is_client_valid(struct config_plugin * config, const char * client_id, json_t * j_client, int add) {
  return is_client_valid(config->glewlwyd_config, client_id, j_client, add, NULL);
}

int glewlwyd_plugin_callback_add_client(struct config_plugin * config, json_t * j_client) {
  return add_client(config->glewlwyd_config, j_client, NULL);
}

int glewlwyd_plugin_callback_set_client(struct config_plugin * config, const char * client_id, json_t * j_client) {
  return set_client(config->glewlwyd_config, client_id, j_client, NULL);
}

int glewlwyd_plugin_callback_delete_client(struct config_plugin * config, const char * client_id) {
  return delete_client(config->glewlwyd_config, client_id, NULL);
}

json_t * glewlwyd_plugin_callback_scheme_register(struct config_plugin * config, const char * mod_name, const struct _u_request * http_request, const char * username, json_t * j_scheme_data) {
  json_t * j_return;
  struct _user_auth_scheme_module_instance * scheme_instance = get_user_auth_scheme_module_instance(config->glewlwyd_config, mod_name);
  if (scheme_instance != NULL && scheme_instance->enabled) {
    j_return = scheme_instance->module->user_auth_scheme_module_register(config->glewlwyd_config->config_m, http_request, username, j_scheme_data, scheme_instance->cls);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

json_t * glewlwyd_plugin_callback_scheme_register_get(struct config_plugin * config, const char * mod_name, const struct _u_request * http_request, const char * username) {
  json_t * j_return;
  struct _user_auth_scheme_module_instance * scheme_instance = get_user_auth_scheme_module_instance(config->glewlwyd_config, mod_name);
  if (scheme_instance != NULL && scheme_instance->enabled) {
    j_return = scheme_instance->module->user_auth_scheme_module_register_get(config->glewlwyd_config->config_m, http_request, username, scheme_instance->cls);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

int glewlwyd_plugin_callback_scheme_can_use(struct config_plugin * config, const char * mod_name, const char * username) {
  int ret;
  struct _user_auth_scheme_module_instance * scheme_instance = get_user_auth_scheme_module_instance(config->glewlwyd_config, mod_name);
  if (scheme_instance != NULL && scheme_instance->enabled) {
    ret = scheme_instance->module->user_auth_scheme_module_can_use(config->glewlwyd_config->config_m, username, scheme_instance->cls);
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int glewlwyd_plugin_callback_scheme_deregister(struct config_plugin * config, const char * mod_name, const char * username) {
  int ret;
  struct _user_auth_scheme_module_instance * scheme_instance = get_user_auth_scheme_module_instance(config->glewlwyd_config, mod_name);
  if (scheme_instance != NULL && scheme_instance->enabled) {
    ret = scheme_instance->module->user_auth_scheme_module_deregister(config->glewlwyd_config->config_m, username, scheme_instance->cls);
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

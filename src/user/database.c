/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Database user module
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
#include <jansson.h>
#include <yder.h>
#include <orcania.h>
#include <hoel.h>
#include "../glewlwyd-common.h"

#define G_TABLE_USER_PROPERTY "g_user_property"
#define G_TABLE_USER_SCOPE_USER "g_user_scope_user"
#define G_TABLE_USER_SCOPE "g_user_scope"
#define G_TABLE_USER "g_user"

#define G_TYPE_STRING 0
#define G_TYPE_NUMBER 0
#define G_TYPE_BOOLEAN 0

struct mod_parameters {
  int use_glewlwyd_connection;
  struct _h_connection * conn;
  json_t * j_params;
};

static char * get_pattern_clause(struct mod_parameters * param, const char * pattern) {
  char * escape_pattern = h_escape_string(param->conn, pattern), * clause = NULL;
  
  if (escape_pattern != NULL) {
    clause = msprintf("IN (SELECT `gu_id` from `" G_TABLE_USER "` WHERE `gu_username` LIKE '%s' OR `gu_display_name` LIKE '%s' OR `gu_email` LIKE '%s')", escape_pattern, escape_pattern, escape_pattern);
  }
  o_free(escape_pattern);
  return clause;
}

static int append_user_properties(struct mod_parameters * param, json_t * j_user, int profile) {
  json_t * j_query, * j_result, * j_element, * j_param_config;
  int res, ret;
  size_t index;
  
  j_query = json_pack("{sss[sssss]s{sO}}",
                      "table",
                      G_TABLE_USER_PROPERTY,
                      "columns",
                        "gup_name AS name",
                        "gup_value_tiny AS value_tiny",
                        "gup_value_small AS value_small",
                        "gup_value_medium AS value_medium",
                        "gup_value_long AS value_long",
                      "where",
                        "gu_id",
                        json_object_get(j_user, "gu_id"));
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      j_param_config = json_object_get(json_object_get(param->j_params, "data-format"), json_string_value(json_object_get(j_element, "name")));
      if ((!profile && json_object_get(j_param_config, "read") != json_false()) || (profile && json_object_get(j_param_config, "profile-read") != json_false())) {
        if (json_object_get(j_element, "value_tiny") != json_null()) {
          if (json_object_get(j_param_config, "multiple") == json_true()) {
            if (json_object_get(j_user, json_string_value(json_object_get(j_element, "name"))) == NULL) {
              json_object_set_new(j_user, json_string_value(json_object_get(j_element, "name")), json_array());
            }
            json_array_append(json_object_get(j_user, json_string_value(json_object_get(j_element, "name"))), json_object_get(j_element, "value_tiny"));
          } else {
            json_object_set(j_user, json_string_value(json_object_get(j_element, "name")), json_object_get(j_element, "value_tiny"));
          }
        } else if (json_object_get(j_element, "value_small") != json_null()) {
          if (json_object_get(j_param_config, "multiple") == json_true()) {
            if (json_object_get(j_user, json_string_value(json_object_get(j_element, "name"))) == NULL) {
              json_object_set_new(j_user, json_string_value(json_object_get(j_element, "name")), json_array());
            }
            json_array_append(json_object_get(j_user, json_string_value(json_object_get(j_element, "name"))), json_object_get(j_element, "value_small"));
          } else {
            json_object_set(j_user, json_string_value(json_object_get(j_element, "name")), json_object_get(j_element, "value_small"));
          }
        } else if (json_object_get(j_element, "value_medium") != json_null()) {
          if (json_object_get(j_param_config, "multiple") == json_true()) {
            if (json_object_get(j_user, json_string_value(json_object_get(j_element, "name"))) == NULL) {
              json_object_set_new(j_user, json_string_value(json_object_get(j_element, "name")), json_array());
            }
            json_array_append(json_object_get(j_user, json_string_value(json_object_get(j_element, "name"))), json_object_get(j_element, "value_medium"));
          } else {
            json_object_set(j_user, json_string_value(json_object_get(j_element, "name")), json_object_get(j_element, "value_medium"));
          }
        } else if (json_object_get(j_element, "value_long") != json_null()) {
          if (json_object_get(j_param_config, "multiple") == json_true()) {
            if (json_object_get(j_user, json_string_value(json_object_get(j_element, "name"))) == NULL) {
              json_object_set_new(j_user, json_string_value(json_object_get(j_element, "name")), json_array());
            }
            json_array_append(json_object_get(j_user, json_string_value(json_object_get(j_element, "name"))), json_object_get(j_element, "value_long"));
          } else {
            json_object_set(j_user, json_string_value(json_object_get(j_element, "name")), json_object_get(j_element, "value_long"));
          }
        } else {
          if (json_object_get(j_param_config, "multiple") == json_true()) {
            if (json_object_get(j_user, json_string_value(json_object_get(j_element, "name"))) == NULL) {
              json_object_set_new(j_user, json_string_value(json_object_get(j_element, "name")), json_array());
            }
            json_array_append(json_object_get(j_user, json_string_value(json_object_get(j_element, "name"))), json_null());
          } else {
            json_object_set(j_user, json_string_value(json_object_get(j_element, "name")), json_null());
          }
        }
      }
    }
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "append_user_properties database - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static char * database_user_get(const char * username, int * result, void * cls, int profile) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query, * j_result;
  int res;
  char * str_result = NULL;
  
  j_query = json_pack("{sss[sssss]s{ss}}",
                      "table",
                      G_TABLE_USER,
                      "columns",
                        "gu_id",
                        "gu_username AS username",
                        "gu_name AS name",
                        "gu_email AS email",
                        "gu_enabled",
                      "where",
                        "gu_username",
                        username);
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      json_object_set(json_array_get(j_result, 0), "enabled", (json_integer_value(json_object_get(json_array_get(j_result, 0), "gu_enabled"))?json_true():json_false()));
      if (append_user_properties(param, json_array_get(j_result, 0), profile) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_count_total database - Error append_user_properties");
      }
      json_object_del(json_array_get(j_result, 0), "gu_enabled");
      json_object_del(json_array_get(j_result, 0), "gu_id");
      str_result = json_dumps(j_result, JSON_COMPACT);
      *result = G_OK;
    } else {
      *result = G_ERROR_NOT_FOUND;
    }
    json_decref(j_result);
  } else {
    *result = G_ERROR_DB;
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_count_total database - Error executing j_query");
  }
  return str_result;
}

int user_module_load(struct config_module * config, char ** name, char ** display_name, char ** description, char ** parameters) {
  int ret = G_OK;
  if (name != NULL && parameters != NULL && display_name != NULL && description != NULL) {
    *name = o_strdup("database");
    *display_name = o_strdup("Database backend user");
    *description = o_strdup("Module to store users in the database");
    *parameters = o_strdup("{"
                             "\"use-glewlwyd-connection\":{\"type\":\"boolean\",\"default\":true},"
                             "\"type\":{\"type\":\"list\",\"values\":[\"sqlite\",\"mariadb\",\"postgre\"],\"mandatory\":false},"
                             "\"sqlite-path\":{\"type\":\"string\",\"mandatory\":false},"
                             "\"mariadb-host\":{\"type\":\"string\",\"mandatory\":false},"
                             "\"mariadb-user\":{\"type\":\"string\",\"mandatory\":false},"
                             "\"mariadb-password\":{\"type\":\"string\",\"mandatory\":false},"
                             "\"mariadb-dbname\":{\"type\":\"string\",\"mandatory\":false},"
                             "\"mariadb-port\":{\"type\":\"number\",\"mandatory\":false},"
                             "\"postgre-conninfo\":{\"type\":\"string\",\"mandatory\":false},"
                             "\"data-format\":{"
                              "\"field-name\":{"
                                "\"format\":{\"type\":\"list\",\"values\":[\"string\",\"number\",\"boolean\"],\"default\":\"string\"},"
                                "\"multiple\":{\"type\":\"boolean\",\"default\":false},"
                                "\"read\":{\"type\":\"boolean\",\"default\":true},"
                                "\"write\":{\"type\":\"boolean\",\"default\":true},"
                                "\"profile-read\":{\"type\":\"boolean\",\"default\":false},"
                                "\"profile-write\":{\"type\":\"boolean\",\"default\":false},"
                              "}"
                             "},"
                           "}");
  } else {
    ret = G_ERROR;
  }
  return ret;
}

int user_module_unload(struct config_module * config) {
  return G_OK;
}

int user_module_init(struct config_module * config, const char * parameters, void ** cls) {
  json_t * j_params = json_loads(parameters, JSON_DECODE_ANY, NULL);
  int ret;
  
  if (j_params != NULL) {
    // TODO: parse and validate parameters
    if (json_object_get(j_params, "use-glewlwyd-connection") != NULL && !json_is_boolean(json_object_get(j_params, "use-glewlwyd-connection"))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error parameter use-glewlwyd-connection invalid");
      ret = G_ERROR_PARAM;
    } else {
      if (json_object_get(j_params, "use-glewlwyd-connection") != json_false()) {
        *cls = o_malloc(sizeof(struct mod_parameters));
        if (*cls != NULL) {
          ((struct mod_parameters *)*cls)->use_glewlwyd_connection = 0;
          ((struct mod_parameters *)*cls)->conn = config->conn;
          ((struct mod_parameters *)*cls)->j_params = j_params;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error allocating resources for cls");
          ret = G_ERROR_MEMORY;
        }
      } else {
        // TODO
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error parsing parameters");
    ret = G_ERROR_PARAM;
  }
  json_decref(j_params);
  return ret;
}

int user_module_close(struct config_module * config, void * cls) {
  int ret;
  
  if (((struct mod_parameters *)cls)->use_glewlwyd_connection) {
    if (h_close_db(((struct mod_parameters *)cls)->conn) != H_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_close database - Error h_close_db");
      ret = G_ERROR_DB;
    } else {
      ret = G_OK;
    }
  } else {
    ret = G_OK;
  }
  o_free(cls);
  return ret;
}

size_t user_module_count_total(const char * pattern, void * cls) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query, * j_result = NULL;
  int res;
  size_t ret = 0;
  char * pattern_clause;
  
  j_query = json_pack("{sss[s]}",
                      "table",
                      G_TABLE_USER,
                      "columns",
                        "count(gu_id) AS total");
  if (o_strlen(pattern)) {
    pattern_clause = get_pattern_clause(param, pattern);
    json_object_set_new(j_query, "where", json_pack("{s{ssss}}", "gu_id", "operator", "raw", "value", pattern_clause));
    o_free(pattern_clause);
  }
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = (size_t)json_integer_value(json_object_get(json_array_get(j_result, 0), "total"));
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_count_total database - Error executing j_query");
  }
  return ret;
}

char * user_module_get_list(const char * pattern, size_t offset, size_t limit, int * result, void * cls) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query, * j_result, * j_element;
  int res;
  char * str_result = NULL, * pattern_clause;
  size_t index;
  
  j_query = json_pack("{sss[sssss]sisi}",
                      "table",
                      G_TABLE_USER,
                      "columns",
                        "gu_id",
                        "gu_username AS username",
                        "gu_name AS name",
                        "gu_email AS email",
                        "gu_enabled",
                      "offset",
                      offset,
                      "limit",
                      limit);
  if (o_strlen(pattern)) {
    pattern_clause = get_pattern_clause(param, pattern);
    json_object_set_new(j_query, "where", json_pack("{s{ssss}}", "gu_id", "operator", "raw", "value", pattern_clause));
    o_free(pattern_clause);
  }
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      json_object_set(j_element, "enabled", (json_integer_value(json_object_get(j_element, "gu_enabled"))?json_true():json_false()));
      if (append_user_properties(param, j_element, 0) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_count_total database - Error append_user_properties");
      }
      json_object_del(j_element, "gu_enabled");
      json_object_del(j_element, "gu_id");
    }
    str_result = json_dumps(j_result, JSON_COMPACT);
    *result = G_OK;
    json_decref(j_result);
  } else {
    *result = G_ERROR_DB;
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_count_total database - Error executing j_query");
  }
  return str_result;
}

char * user_module_get(const char * username, int * result, void * cls) {
  return database_user_get(username, result, cls, 0);
}

char * user_module_get_profile(const char * username, int * result, void * cls) {
  return database_user_get(username, result, cls, 0);
}

char * user_is_valid(const char * username, const char * str_user, int mode, int * result, void * cls) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_user = json_loads(str_user, JSON_DECODE_ANY, NULL), * j_result = NULL, * j_element, * j_format, * j_value;
  char * str_result = NULL, * message, p_type;
  int res;
  size_t index;
  const char * property;
  
  if (j_user != NULL && json_is_object(j_user)) {
    *result = G_OK;
    j_result = json_array();
    if (j_result != NULL) {
      if (mode == GLEWLWYD_IS_VALID_MODE_ADD) {
        if (!json_is_string(json_object_get(j_user, "username")) || json_string_length(json_object_get(j_user, "username")) > 128) {
          *result = G_ERROR_PARAM;
          json_array_append_new(j_result, json_string("username is mandatory and must be a string of at least 128 characters"));
        } else {
          o_free(user_module_get(json_string_value(json_object_get(j_user, "username")), &res, cls));
          if (res == G_OK) {
            *result = G_ERROR_PARAM;
            json_array_append_new(j_result, json_string("username already exist"));
          } else if (res != G_ERROR_NOT_FOUND) {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_is_valid database - Error user_module_get");
          }
        }
      } else if ((mode == GLEWLWYD_IS_VALID_MODE_UPDATE || mode == GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) && username == NULL) {
        *result = G_ERROR_PARAM;
        json_array_append_new(j_result, json_string("username is mandatory on update mode"));
      }
      if (!json_is_array(json_object_get(j_user, "scope"))) {
        *result = G_ERROR_PARAM;
        json_array_append_new(j_result, json_string("scope must be a JSON array of string"));
      } else {
        json_array_foreach(json_object_get(j_user, "scope"), index, j_element) {
          if (!json_is_string(j_element) || !json_string_length(j_element)) {
            *result = G_ERROR_PARAM;
            json_array_append_new(j_result, json_string("scope must be a JSON array of string"));
          }
        }
      }
      if (json_object_get(j_user, "password") != NULL && !json_is_string(json_object_get(j_user, "password"))) {
        *result = G_ERROR_PARAM;
        json_array_append_new(j_result, json_string("password must be a string"));
      }
      if (json_object_get(j_user, "name") != NULL && (!json_is_string(json_object_get(j_user, "name")) || json_string_length(json_object_get(j_user, "name")) > 256)) {
        *result = G_ERROR_PARAM;
        json_array_append_new(j_result, json_string("name must be a string of at least 256 characters"));
      }
      if (json_object_get(j_user, "email") != NULL && (!json_is_string(json_object_get(j_user, "email")) || json_string_length(json_object_get(j_user, "email")) > 512)) {
        *result = G_ERROR_PARAM;
        json_array_append_new(j_result, json_string("email must be a string of at least 512 characters"));
      }
      if (json_object_get(j_user, "enabled") != NULL && !json_is_boolean(json_object_get(j_user, "enabled"))) {
        *result = G_ERROR_PARAM;
        json_array_append_new(j_result, json_string("enabled must be a boolean"));
      }
      json_object_foreach(j_user, property, j_element) {
        if (0 != o_strcmp(property, "username") && 0 != o_strcmp(property, "name") && 0 != o_strcmp(property, "email") && 0 != o_strcmp(property, "enabled") && 0 != o_strcmp(property, "password")) {
          if ((j_format = json_object_get(json_object_get(param->j_params, "data-format"), property)) != NULL) {
            if (0 == o_strcmp("number", json_string_value(json_object_get(j_format, "format")))) {
              p_type = G_TYPE_NUMBER;
            } else if (0 == o_strcmp("boolean", json_string_value(json_object_get(j_format, "format")))) {
              p_type = G_TYPE_BOOLEAN;
            } else {
              p_type = G_TYPE_STRING;
            }
            if (json_object_get(j_format, "multiple") == json_true()) {
              if (!json_is_array(j_element)) {
                *result = G_ERROR_PARAM;
                message = msprintf("%s must be an array", property);
                json_array_append_new(j_result, json_string(message));
                o_free(message);
              } else {
                json_array_foreach(j_element, index, j_value) {
                  if (p_type == G_TYPE_NUMBER && !json_is_number(j_value)) {
                    *result = G_ERROR_PARAM;
                    message = msprintf("%s must contain number values", property);
                    json_array_append_new(j_result, json_string(message));
                    o_free(message);
                  } else if (p_type == G_TYPE_BOOLEAN && !json_is_boolean(j_value)) {
                    *result = G_ERROR_PARAM;
                    message = msprintf("%s must contain boolean values", property);
                    json_array_append_new(j_result, json_string(message));
                    o_free(message);
                  } else if (p_type == G_TYPE_STRING && !json_is_string(j_value)) {
                    *result = G_ERROR_PARAM;
                    message = msprintf("%s must contain string values", property);
                    json_array_append_new(j_result, json_string(message));
                    o_free(message);
                  }
                }
              }
            } else {
              if (p_type == G_TYPE_NUMBER && !json_is_number(j_value)) {
                *result = G_ERROR_PARAM;
                message = msprintf("%s must contain number values", property);
                json_array_append_new(j_result, json_string(message));
                o_free(message);
              } else if (p_type == G_TYPE_BOOLEAN && !json_is_boolean(j_value)) {
                *result = G_ERROR_PARAM;
                message = msprintf("%s must contain boolean values", property);
                json_array_append_new(j_result, json_string(message));
                o_free(message);
              } else if (p_type == G_TYPE_STRING && !json_is_string(j_value)) {
                *result = G_ERROR_PARAM;
                message = msprintf("%s must contain string values", property);
                json_array_append_new(j_result, json_string(message));
                o_free(message);
              }
            }
          } else {
            if (!json_is_string(j_element)) {
              *result = G_ERROR_PARAM;
              message = msprintf("%s must be a string", property);
              json_array_append_new(j_result, json_string(message));
              o_free(message);
            }
          }
        }
      }
    }
  } else {
    *result = G_ERROR_PARAM;
    j_result = json_string("user must be a valid JSON object");
  }
  json_decref(j_user);
  if (*result != G_OK) {
    str_result = json_dumps(j_result, JSON_COMPACT);
  }
  json_decref(j_result);
  return str_result;
}

int user_module_add(const char * str_new_user, void * cls) {
  return G_OK;
}

int user_module_update(const char * username, const char * str_user, void * cls) {
  return G_OK;
}

int user_module_update_profile(const char * username, const char * str_user, void * cls) {
  return G_OK;
}

int user_module_delete(const char * username, void * cls) {
  return G_OK;
}

int user_module_check_password(const char * username, const char * password, void * cls) {
  return G_OK;
}

int user_module_update_password(const char * username, const char * new_password, void * cls) {
  return G_ERROR_PARAM;
}

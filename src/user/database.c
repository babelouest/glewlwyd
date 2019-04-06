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

#define G_TABLE_USER "g_user"
#define G_TABLE_USER_SCOPE "g_user_scope"
#define G_TABLE_USER_SCOPE_USER "g_user_scope_user"
#define G_TABLE_USER_PROPERTY "g_user_property"

struct mod_parameters {
  int use_glewlwyd_connection;
  digest_algorithm hash_algorithm;
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
  
  if (param->conn->type == HOEL_DB_TYPE_MARIADB) {
    j_query = json_pack("{sss[ssss]s{sO}}",
                        "table",
                        G_TABLE_USER_PROPERTY,
                        "columns",
                          "gup_name AS name",
                          "gup_value_tiny AS value_tiny",
                          "gup_value_small AS value_small",
                          "gup_value_medium AS value_medium",
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
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "append_user_properties database - Error executing j_query");
      ret = G_ERROR_DB;
    }
  } else {
    j_query = json_pack("{sss[ssss]s{sO}}",
                        "table",
                        G_TABLE_USER_PROPERTY,
                        "columns",
                          "gup_name AS name",
                          "gup_value AS value",
                        "where",
                          "gu_id",
                          json_object_get(j_user, "gu_id"));
    res = h_select(param->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      json_array_foreach(j_result, index, j_element) {
        j_param_config = json_object_get(json_object_get(param->j_params, "data-format"), json_string_value(json_object_get(j_element, "name")));
        if ((!profile && json_object_get(j_param_config, "read") != json_false()) || (profile && json_object_get(j_param_config, "profile-read") != json_false())) {
          if (json_object_get(j_element, "value") != json_null()) {
            if (json_object_get(j_param_config, "multiple") == json_true()) {
              if (json_object_get(j_user, json_string_value(json_object_get(j_element, "name"))) == NULL) {
                json_object_set_new(j_user, json_string_value(json_object_get(j_element, "name")), json_array());
              }
              json_array_append(json_object_get(j_user, json_string_value(json_object_get(j_element, "name"))), json_object_get(j_element, "value"));
            } else {
              json_object_set(j_user, json_string_value(json_object_get(j_element, "name")), json_object_get(j_element, "value"));
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
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "append_user_properties database - Error executing j_query");
      ret = G_ERROR_DB;
    }
  }
  return ret;
}

static json_t * database_user_scope_get(struct mod_parameters * param, json_int_t gu_id) {
  json_t * j_query, * j_result, * j_return, * j_array, * j_scope;
  int res;
  size_t index;
  char * scope_clause = msprintf("IN (SELECT `gus_id` from `" G_TABLE_USER_SCOPE_USER "` WHERE `gu_id` = %"JSON_INTEGER_FORMAT")", gu_id);
  
  j_query = json_pack("{sss[s]s{s{ssss}}}",
                      "table",
                      G_TABLE_USER_SCOPE,
                      "columns",
                        "gus_name AS name",
                      "where",
                        "gus_id",
                          "operator",
                          "raw",
                          "value",
                          scope_clause);
  o_free(scope_clause);
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_array = json_array();
    if (j_array != NULL) {
      json_array_foreach(j_result, index, j_scope) {
        json_array_append(j_array, json_object_get(j_scope, "name"));
      }
      j_return = json_pack("{sisO}", "result", G_OK, "scope", j_array);
      json_decref(j_array);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "database_user_scope_get database - Error allocating resources for j_array");
      j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "database_user_scope_get database - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static json_t * database_user_get(const char * username, void * cls, int profile) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query, * j_result, * j_scope, * j_return;
  int res;
  
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
      j_scope = database_user_scope_get(param, json_integer_value(json_object_get(json_array_get(j_result, 0), "gu_id")));
      if (check_result_value(j_scope, G_OK)) {
        json_object_set(json_array_get(j_result, 0), "scope", json_object_get(j_scope, "scope"));
        json_object_set(json_array_get(j_result, 0), "enabled", (json_integer_value(json_object_get(json_array_get(j_result, 0), "gu_enabled"))?json_true():json_false()));
        if (append_user_properties(param, json_array_get(j_result, 0), profile) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "database_user_get database - Error append_user_properties");
        }
        json_object_del(json_array_get(j_result, 0), "gu_enabled");
        json_object_del(json_array_get(j_result, 0), "gu_id");
        j_return = json_pack("{sisO}", "result", G_OK, "user", json_array_get(j_result, 0));
      } else {
        j_return = json_pack("{si}", "result", G_ERROR);
        y_log_message(Y_LOG_LEVEL_ERROR, "database_user_get database - Error database_user_scope_get");
      }
      json_decref(j_scope);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_DB);
    y_log_message(Y_LOG_LEVEL_ERROR, "database_user_get database - Error executing j_query");
  }
  return j_return;
}

static json_t * is_user_database_parameters_valid(json_t * j_params) {
  json_t * j_return, * j_error = json_array(), * j_element;
  const char * field;
  
  if (j_error != NULL) {
    if (!json_is_object(j_params)) {
      json_array_append_new(j_error, json_string("parameters must be a JSON array"));
    } else {
      if (json_object_get(j_params, "use-glewlwyd-connection") != NULL && !json_is_boolean(json_object_get(j_params, "use-glewlwyd-connection"))) {
        json_array_append_new(j_error, json_string("use-glewlwyd-connection must be a boolean"));
      }
      if (json_object_get(j_params, "use-glewlwyd-connection") == json_false()) {
        if (json_object_get(j_params, "connection-type") == NULL || !json_is_string(json_object_get(j_params, "connection-type")) || (0 != o_strcmp("sqlite", json_string_value(json_object_get(j_params, "connection-type"))) && 0 != o_strcmp("mariadb", json_string_value(json_object_get(j_params, "connection-type"))) && 0 != o_strcmp("postgre", json_string_value(json_object_get(j_params, "connection-type"))))) {
          json_array_append_new(j_error, json_string("connection-type is mandatory and must be one of the following values: 'sqlite', 'mariadb', 'postgre'"));
        } else if (0 == o_strcmp("sqlite", json_string_value(json_object_get(j_params, "connection-type")))) {
          if (json_object_get(j_params, "sqlite-dbpath") == NULL || !json_is_string(json_object_get(j_params, "sqlite-dbpath"))) {
            json_array_append_new(j_error, json_string("sqlite-dbpath is mandatory and must be a string"));
          }
        } else if (0 == o_strcmp("mariadb", json_string_value(json_object_get(j_params, "connection-type")))) {
          if (json_object_get(j_params, "mariadb-host") == NULL || !json_is_string(json_object_get(j_params, "mariadb-host"))) {
            json_array_append_new(j_error, json_string("mariadb-host is mandatory and must be a string"));
          }
          if (json_object_get(j_params, "mariadb-user") == NULL || !json_is_string(json_object_get(j_params, "mariadb-user"))) {
            json_array_append_new(j_error, json_string("mariadb-user is mandatory and must be a string"));
          }
          if (json_object_get(j_params, "mariadb-password") == NULL || !json_is_string(json_object_get(j_params, "mariadb-password"))) {
            json_array_append_new(j_error, json_string("mariadb-password is mandatory and must be a string"));
          }
          if (json_object_get(j_params, "mariadb-dbname") == NULL || !json_is_string(json_object_get(j_params, "mariadb-dbname"))) {
            json_array_append_new(j_error, json_string("mariadb-dbname is mandatory and must be a string"));
          }
          if (json_object_get(j_params, "mariadb-port") != NULL && (!json_is_integer(json_object_get(j_params, "mariadb-dbname")) || json_integer_value(json_object_get(j_params, "mariadb-dbname")) < 0)) {
            json_array_append_new(j_error, json_string("mariadb-port is optional and must be a positive integer (default: 0)"));
          }
        } else if (0 == o_strcmp("postgre", json_string_value(json_object_get(j_params, "connection-type")))) {
          if (json_object_get(j_params, "postgre-conninfo") == NULL || !json_is_string(json_object_get(j_params, "postgre-conninfo"))) {
            json_array_append_new(j_error, json_string("postgre-conninfo is mandatory and must be a string"));
          }
        }
      }
      if (json_object_get(j_params, "data-format") != NULL) {
        if (!json_is_object(json_object_get(j_params, "data-format"))) {
          json_array_append_new(j_error, json_string("data-format is optional and must be a JSON object"));
        } else {
          json_object_foreach(json_object_get(j_params, "data-format"), field, j_element) {
            if (0 == o_strcmp(field, "username") || 0 == o_strcmp(field, "name") || 0 == o_strcmp(field, "email") || 0 == o_strcmp(field, "enabled") || 0 == o_strcmp(field, "password")) {
              json_array_append_new(j_error, json_string("data-format can not have settings for properties 'username', 'name', 'email', 'enabled' or 'password'"));
            } else {
              if (json_object_get(j_element, "multiple") != NULL && !json_is_boolean(json_object_get(j_element, "multiple"))) {
                json_array_append_new(j_error, json_string("multiple is optional and must be a boolean (default: false)"));
              }
              if (json_object_get(j_element, "read") != NULL && !json_is_boolean(json_object_get(j_element, "read"))) {
                json_array_append_new(j_error, json_string("read is optional and must be a boolean (default: true)"));
              }
              if (json_object_get(j_element, "write") != NULL && !json_is_boolean(json_object_get(j_element, "write"))) {
                json_array_append_new(j_error, json_string("write is optional and must be a boolean (default: true)"));
              }
              if (json_object_get(j_element, "profile-read") != NULL && !json_is_boolean(json_object_get(j_element, "profile-read"))) {
                json_array_append_new(j_error, json_string("profile-read is optional and must be a boolean (default: false)"));
              }
              if (json_object_get(j_element, "profile-write") != NULL && !json_is_boolean(json_object_get(j_element, "profile-write"))) {
                json_array_append_new(j_error, json_string("profile-write is optional and must be a boolean (default: false)"));
              }
            }
          }
        }
      }
    }
    if (json_array_size(j_error)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
    } else {
      j_return = json_pack("{si}", "result", G_OK);
    }
    json_decref(j_error);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_user_database_parameters_valid - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

static char * get_password_clause_write(struct mod_parameters * param, const char * password) {
  char * clause = NULL, * password_encoded, digest[64] = {0};
  
  if (param->conn->type == HOEL_DB_TYPE_SQLITE) {
    if (generate_digest(param->hash_algorithm, password, 0, digest)) {
      clause = msprintf("'%s'", digest);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_password_clause_write database - Error generate_digest");
    }
  } else if (param->conn->type == HOEL_DB_TYPE_MARIADB) {
    password_encoded = h_escape_string(param->conn, password);
    if (password_encoded != NULL) {
      clause = msprintf("PASSWORD('%s')", password_encoded);
      o_free(password_encoded);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_password_clause_write database - Error h_escape_string (mariadb)");
    }
  } else if (param->conn->type == HOEL_DB_TYPE_PGSQL) {
    password_encoded = h_escape_string(param->conn, password);
    if (password_encoded != NULL) {
      clause = msprintf("crypt('%s', gen_salt('bf'))", password_encoded);
      o_free(password_encoded);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_password_clause_write database - Error h_escape_string (postgre)");
    }
  }
  return clause;
}

static char * get_password_clause_check(struct mod_parameters * param, const char * password) {
  char * clause = NULL, * password_encoded, digest[64] = {0};
  
  if (param->conn->type == HOEL_DB_TYPE_SQLITE) {
    if (generate_digest(param->hash_algorithm, password, 0, digest)) {
      clause = msprintf(" = '%s'", digest);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_password_clause_write database - Error generate_digest");
    }
  } else if (param->conn->type == HOEL_DB_TYPE_MARIADB) {
    password_encoded = h_escape_string(param->conn, password);
    if (password_encoded != NULL) {
      clause = msprintf(" = PASSWORD('%s')", password_encoded);
      o_free(password_encoded);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_password_clause_write database - Error h_escape_string (mariadb)");
    }
  } else if (param->conn->type == HOEL_DB_TYPE_PGSQL) {
    password_encoded = h_escape_string(param->conn, password);
    if (password_encoded != NULL) {
      clause = msprintf(" = crypt('%s', gu_password)", password_encoded);
      o_free(password_encoded);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_password_clause_write database - Error h_escape_string (postgre)");
    }
  }
  return clause;
}

static json_t * get_property_value_db(struct mod_parameters * param, json_t * j_property, json_int_t gu_id) {
  if (param->conn->type == HOEL_DB_TYPE_MARIADB) {
    if (json_string_length(j_property) < 512) {
      return json_pack("{sIsO}", "gu_id", gu_id, "gup_value_tiny", j_property);
    } else if (json_string_length(j_property) < 16*1024) {
      return json_pack("{sIsO}", "gu_id", gu_id, "gup_value_small", j_property);
    } else {
      return json_pack("{sIsO}", "gu_id", gu_id, "gup_value_medium", j_property);
    }
  } else {
    return json_pack("{sIsO}", "gu_id", gu_id, "gup_value", j_property);;
  }
}

static int save_user_properties(struct mod_parameters * param, json_t * j_user, json_int_t gu_id, int profile) {
  json_t * j_property, * j_query, * j_array = json_array(), * j_format, * j_property_value;
  const char * name;
  int ret, res;
  size_t index;
  
  if (j_array != NULL) {
    json_object_foreach(j_user, name, j_property) {
      if (0 != o_strcmp(name, "username") && 0 != o_strcmp(name, "name") && 0 != o_strcmp(name, "password") && 0 != o_strcmp(name, "email") && 0 != o_strcmp(name, "enabled")) {
        j_format = json_object_get(json_object_get(param->j_params, "data-format"), name);
        if ((!profile && json_object_get(j_format, "write") != json_false()) || (profile && json_object_get(j_format, "profile-write") == json_true())) {
          if (!json_is_array(j_property)) {
            json_array_append_new(j_array, get_property_value_db(param, j_property, gu_id));
          } else {
            json_array_foreach(j_property, index, j_property_value) {
              json_array_append_new(j_array, get_property_value_db(param, j_property_value, gu_id));
            }
          }
        }
      }
    }
    // Delete old values
    j_query = json_pack("{sss{sI}}", "table", G_TABLE_USER_PROPERTY, "where", "gu_id", gu_id);
    res = h_delete(param->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_array)) {
        j_query = json_pack("{sssO}", "table", G_TABLE_USER_PROPERTY, "values", j_array);
        res = h_insert(param->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "insert_user_properties database - Error executing j_query insert");
          ret = G_ERROR_DB;
        }
      } else {
        ret = G_OK;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "insert_user_properties database - Error executing j_query delete");
      ret = G_ERROR_DB;
    }
    json_decref(j_array);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "insert_user_properties database - Error allocating resources for j_array");
    ret = G_ERROR_MEMORY;
  }
  return ret;
}

static int save_user_scope(struct mod_parameters * param, json_t * j_scope, json_int_t gu_id) {
  json_t * j_query, * j_result, * j_element, * j_new_scope_id;
  int res, ret;
  char * scope_clause;
  size_t index;
  
  j_query = json_pack("{sss{sI}}", "table", G_TABLE_USER_SCOPE_USER, "where", "gu_id", gu_id);
  res = h_delete(param->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
    if (json_is_array(j_scope)) {
      json_array_foreach(j_scope, index, j_element) {
        j_query = json_pack("{sss[s]s{sO}}",
                            "table",
                            G_TABLE_USER_SCOPE,
                            "columns",
                              "gus_id",
                            "where",
                              "gus_name",
                              j_element);
        res = h_select(param->conn, j_query, &j_result, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          if (json_array_size(j_result)) {
            j_query = json_pack("{sss{sIsO}}",
                                "table",
                                G_TABLE_USER_SCOPE_USER,
                                "values",
                                  "gu_id",
                                  gu_id,
                                  "gus_id",
                                  json_object_get(json_array_get(j_result, 0), "gus_id"));
            res = h_insert(param->conn, j_query, NULL);
            json_decref(j_query);
            if (res != H_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "save_user_scope database - Error executing j_query insert scope_user (1)");
            }
          } else {
            j_query = json_pack("{sss{sO}}",
                                "table",
                                G_TABLE_USER_SCOPE,
                                "values",
                                  "gus_name",
                                  j_element);
            res = h_insert(param->conn, j_query, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              j_new_scope_id = h_last_insert_id(param->conn);
              if (j_new_scope_id != NULL) {
                j_query = json_pack("{sss{sIsO}}",
                                    "table",
                                    G_TABLE_USER_SCOPE_USER,
                                    "values",
                                      "gu_id",
                                      gu_id,
                                      "gus_id",
                                      j_new_scope_id);
                res = h_insert(param->conn, j_query, NULL);
                json_decref(j_query);
                if (res != H_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "save_user_scope database - Error executing j_query insert scope_user (2)");
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "save_user_scope database - Error h_last_insert_id");
              }
              json_decref(j_new_scope_id);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "save_user_scope database - Error executing j_query insert scope");
            }
          }
          json_decref(j_result);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "save_user_scope database - Error executing j_query select scope");
        }
      }
    }
    // Clean orphan user_scope
    scope_clause = msprintf("NOT IN (SELECT DISTINCT(`gus_id`) FROM `" G_TABLE_USER_SCOPE_USER "`)");
    j_query = json_pack("{sss{s{ssss}}}",
                        "table",
                        G_TABLE_USER_SCOPE,
                        "where",
                          "gus_id",
                            "operator",
                            "raw",
                            "value",
                            scope_clause);
    o_free(scope_clause);
    res = h_delete(param->conn, j_query, NULL);
    json_decref(j_query);
    if (res != H_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "save_user_scope database - Error executing j_query delete empty scopes");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "save_user_scope database - Error executing j_query delete");
    ret = G_ERROR_DB;
  }
  
  return ret;
}

json_t * user_module_load(struct config_module * config) {
  return json_pack("{si ss ss ss s{s{ssso} s{sss[sss]so} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{s{s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} }}}}",
                   "result",
                   G_OK,
                   
                   "name",
                   "database",
                   
                   "display_name",
                   "Database backend user module",
                   
                   "description",
                   "Module to store users in the database",
                   
                   "parameters",
                     "use-glewlwyd-connection",
                       "type",
                       "boolean",
                       "mandatory",
                       json_true(),
                       
                     "connection-type",
                       "type",
                       "list",
                       "values",
                         "sqlite",
                         "mariadb",
                         "postgre",
                       "mandatory",
                       json_false(),
                       
                     "sqlite-dbpath",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                       
                     "mariadb-host",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                       
                     "mariadb-user",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                       
                     "mariadb-password",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                       
                     "mariadb-dbname",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                       
                     "mariadb-port",
                       "type",
                       "number",
                       "mandatory",
                       json_false(),
                       
                     "postgre-conninfo",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                       
                     "data-format",
                       "field-name",
                         "multiple",
                           "type",
                           "boolean",
                           "default",
                           json_false(),
                           
                         "read",
                           "type",
                           "boolean",
                           "default",
                           json_true(),
                           
                         "write",
                           "type",
                           "boolean",
                           "default",
                           json_true(),
                           
                         "profile-read",
                           "type",
                           "boolean",
                           "default",
                           json_false(),
                           
                         "profile-write",
                           "type",
                           "boolean",
                           "default",
                           json_false());
}

int user_module_unload(struct config_module * config) {
  return G_OK;
}

int user_module_init(struct config_module * config, json_t * j_parameters, void ** cls) {
  json_t * j_params = json_incref(j_parameters), * j_result;
  int ret;
  char * error_message;
  
  j_result = is_user_database_parameters_valid(j_params);
  if (check_result_value(j_result, G_OK)) {
    *cls = o_malloc(sizeof(struct mod_parameters));
    if (*cls != NULL) {
      ((struct mod_parameters *)*cls)->j_params = j_params;
      ((struct mod_parameters *)*cls)->hash_algorithm = config->hash_algorithm;
      if (json_object_get(j_params, "use-glewlwyd-connection") != json_false()) {
          ((struct mod_parameters *)*cls)->use_glewlwyd_connection = 0;
          ((struct mod_parameters *)*cls)->conn = config->conn;
      } else {
        ((struct mod_parameters *)*cls)->use_glewlwyd_connection = 1;
        if (0 == o_strcmp(json_string_value(json_object_get(j_params, "connection-type")), "sqlite")) {
          ((struct mod_parameters *)*cls)->conn = h_connect_sqlite(json_string_value(json_object_get(j_params, "sqlite-dbpath")));
        } else if (0 == o_strcmp(json_string_value(json_object_get(j_params, "connection-type")), "mariadb")) {
          ((struct mod_parameters *)*cls)->conn = h_connect_mariadb(json_string_value(json_object_get(j_params, "mariadb-host")), json_string_value(json_object_get(j_params, "mariadb-user")), json_string_value(json_object_get(j_params, "mariadb-password")), json_string_value(json_object_get(j_params, "mariadb-dbname")), json_integer_value(json_object_get(j_params, "mariadb-port")), NULL);
        } else if (0 == o_strcmp(json_string_value(json_object_get(j_params, "connection-type")), "postgre")) {
          ((struct mod_parameters *)*cls)->conn = h_connect_pgsql(json_string_value(json_object_get(j_params, "postgre-conninfo")));
        }
      }
      ret = G_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error allocating resources for cls");
      ret = G_ERROR_MEMORY;
    }
  } else if (check_result_value(j_result, G_ERROR_PARAM)) {
    error_message = json_dumps(json_object_get(j_result, "error"), JSON_COMPACT);
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error parsing parameters");
    y_log_message(Y_LOG_LEVEL_ERROR, error_message);
    o_free(error_message);
    ret = G_ERROR_PARAM;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error is_user_database_parameters_valid");
    ret = G_ERROR;
  }
  json_decref(j_result);
  return ret;
}

int user_module_close(struct config_module * config, void * cls) {
  int ret;
  
  if (((struct mod_parameters *)cls)->use_glewlwyd_connection) {
    json_decref(((struct mod_parameters *)cls)->j_params);
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

size_t user_module_count_total(struct config_module * config, const char * pattern, void * cls) {
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

json_t * user_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query, * j_result, * j_element, * j_scope, * j_return;
  int res;
  char * pattern_clause;
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
      j_scope = database_user_scope_get(param, json_integer_value(json_object_get(j_element, "gu_id")));
      if (check_result_value(j_scope, G_OK)) {
        json_object_set(j_element, "scope", json_object_get(j_scope, "scope"));
        json_object_set(j_element, "enabled", (json_integer_value(json_object_get(j_element, "gu_enabled"))?json_true():json_false()));
        if (append_user_properties(param, j_element, 0) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list database - Error append_user_properties");
        }
        json_object_del(j_element, "gu_enabled");
        json_object_del(j_element, "gu_id");
      } else {
        j_return = json_pack("{si}", "result", G_ERROR);
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list database - Error database_user_scope_get");
      }
      json_decref(j_scope);
    }
    j_return = json_pack("{sisO}", "result", G_OK, "list", j_result);
    json_decref(j_result);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_DB);
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list database - Error executing j_query");
  }
  return j_return;
}

json_t * user_module_get(struct config_module * config, const char * username, void * cls) {
  return database_user_get(username, cls, 0);
}

json_t * user_module_get_profile(struct config_module * config, const char * username, void * cls) {
  return database_user_get(username, cls, 1);
}

json_t * user_is_valid(struct config_module * config, const char * username, json_t * j_user, int mode, void * cls) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_result = json_array(), * j_element, * j_format, * j_value, * j_return = NULL, * j_cur_user;
  char * message;
  size_t index;
  const char * property;
  
  if (j_result != NULL) {
    if (mode == GLEWLWYD_IS_VALID_MODE_ADD) {
      if (!json_is_string(json_object_get(j_user, "username")) || json_string_length(json_object_get(j_user, "username")) > 128) {
        json_array_append_new(j_result, json_string("username is mandatory and must be a string of at least 128 characters"));
      } else {
        j_cur_user = user_module_get(config, json_string_value(json_object_get(j_user, "username")), cls);
        if (check_result_value(j_cur_user, G_OK)) {
          json_array_append_new(j_result, json_string("username already exist"));
        } else if (!check_result_value(j_cur_user, G_ERROR_NOT_FOUND)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_is_valid database - Error user_module_get");
        }
        json_decref(j_cur_user);
      }
    } else if ((mode == GLEWLWYD_IS_VALID_MODE_UPDATE || mode == GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) && username == NULL) {
      json_array_append_new(j_result, json_string("username is mandatory on update mode"));
    }
    if (mode != GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) {
      if (json_object_get(j_user, "scope") != NULL) {
        if (!json_is_array(json_object_get(j_user, "scope"))) {
          json_array_append_new(j_result, json_string("scope must be a JSON array of string"));
        } else {
          json_array_foreach(json_object_get(j_user, "scope"), index, j_element) {
            if (!json_is_string(j_element) || !json_string_length(j_element)) {
              json_array_append_new(j_result, json_string("scope must be a JSON array of string"));
            }
          }
        }
      }
    }
    if (mode != GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE && json_object_get(j_user, "password") != NULL && !json_is_string(json_object_get(j_user, "password"))) {
      json_array_append_new(j_result, json_string("password must be a string"));
    }
    if (json_object_get(j_user, "name") != NULL && (!json_is_string(json_object_get(j_user, "name")) || json_string_length(json_object_get(j_user, "name")) > 256)) {
      json_array_append_new(j_result, json_string("name must be a string of at least 256 characters"));
    }
    if (json_object_get(j_user, "email") != NULL && (!json_is_string(json_object_get(j_user, "email")) || json_string_length(json_object_get(j_user, "email")) > 512)) {
      json_array_append_new(j_result, json_string("email must be a string of at least 512 characters"));
    }
    if (json_object_get(j_user, "enabled") != NULL && !json_is_boolean(json_object_get(j_user, "enabled"))) {
      json_array_append_new(j_result, json_string("enabled must be a boolean"));
    }
    json_object_foreach(j_user, property, j_element) {
      if (0 != o_strcmp(property, "username") && 0 != o_strcmp(property, "name") && 0 != o_strcmp(property, "email") && 0 != o_strcmp(property, "enabled") && 0 != o_strcmp(property, "password") && 0 != o_strcmp(property, "source") && 0 != o_strcmp(property, "scope")) {
        j_format = json_object_get(json_object_get(param->j_params, "data-format"), property);
        if (json_object_get(j_format, "multiple") == json_true()) {
          if (!json_is_array(j_element)) {
            message = msprintf("property '%s' must be a JSON array", property);
            json_array_append_new(j_result, json_string(message));
            o_free(message);
          } else {
            json_array_foreach(j_element, index, j_value) {
              if (!json_is_string(j_value) || json_string_length(j_value) > 16*1024*1024) {
                message = msprintf("property '%s' must contain a string value of at least 16M characters", property);
                json_array_append_new(j_result, json_string(message));
                o_free(message);
              }
            }
          }
        } else {
          if (!json_is_string(j_element) || json_string_length(j_element) > 16*1024*1024) {
            message = msprintf("property '%s' must be a string value of at least 16M characters", property);
            json_array_append_new(j_result, json_string(message));
            o_free(message);
          }
        }
      }
    }
    if (json_array_size(j_result)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_result);
    } else {
      j_return = json_pack("{si}", "result", G_OK);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_is_valid database - Error allocating resources for j_result");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

int user_module_add(struct config_module * config, json_t * j_user, void * cls) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query, * j_gu_id;
  int res, ret;
  char * password_clause;
  
  j_query = json_pack("{sss{ss}}",
                      "table",
                      G_TABLE_USER,
                      "values",
                        "gu_username",
                        json_string_value(json_object_get(j_user, "username")));
  
  if (json_object_get(j_user, "password") != NULL) {
    password_clause = get_password_clause_write(param, json_string_value(json_object_get(j_user, "password")));
    json_object_set_new(json_object_get(j_query, "values"), "gu_password", json_pack("{ss}", "raw", password_clause));
    o_free(password_clause);
  }
  if (json_object_get(j_user, "name") != NULL) {
    json_object_set(json_object_get(j_query, "values"), "gu_name", json_object_get(j_user, "name"));
  }
  if (json_object_get(j_user, "email") != NULL) {
    json_object_set(json_object_get(j_query, "values"), "gu_email", json_object_get(j_user, "email"));
  }
  if (json_object_get(j_user, "enabled") != NULL) {
    json_object_set_new(json_object_get(j_query, "values"), "gu_enabled", json_object_get(j_user, "enabled")==json_false()?json_integer(0):json_integer(1));
  }
  res = h_insert(param->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_gu_id = h_last_insert_id(param->conn);
    if (save_user_properties(param, j_user, json_integer_value(j_gu_id), 0) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add database - Error save_user_properties");
      ret = G_ERROR_DB;
    } else if (save_user_scope(param, json_object_get(j_user, "scope"), json_integer_value(j_gu_id)) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add database - Error save_user_scope");
      ret = G_ERROR_DB;
    } else {
      ret = G_OK;
    }
    json_decref(j_gu_id);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add database - Error executing j_query insert");
    ret = G_ERROR_DB;
  }
  return ret;
}

int user_module_update(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query, * j_result = NULL;
  int res, ret;
  char * password_clause;
  
  j_query = json_pack("{sss[s]s{ss}}", "table", G_TABLE_USER, "columns", "gu_id", "where", "gu_username", username);
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK && json_array_size(j_result)) {
    j_query = json_pack("{sss{}s{sO}}",
                        "table",
                        G_TABLE_USER,
                        "set",
                        "where",
                          "gu_id",
                          json_object_get(json_array_get(j_result, 0), "gu_id"));
    
    if (json_object_get(j_user, "password") != NULL) {
      password_clause = get_password_clause_write(param, json_string_value(json_object_get(j_user, "password")));
    json_object_set_new(json_object_get(j_query, "values"), "gu_password", json_pack("{ss}", "raw", password_clause));
      o_free(password_clause);
    }
    if (json_object_get(j_user, "name") != NULL) {
      json_object_set(json_object_get(j_query, "set"), "gu_name", json_object_get(j_user, "name"));
    }
    if (json_object_get(j_user, "email") != NULL) {
      json_object_set(json_object_get(j_query, "set"), "gu_email", json_object_get(j_user, "email"));
    }
    if (json_object_get(j_user, "enabled") != NULL) {
      json_object_set_new(json_object_get(j_query, "values"), "gu_enabled", json_object_get(j_user, "enabled")==json_false()?json_integer(0):json_integer(1));
    }
    if (json_object_size(json_object_get(j_query, "set"))) {
      res = h_update(param->conn, j_query, NULL);
    } else {
      res = H_OK;
    }
    json_decref(j_query);
    if (res == H_OK) {
      if (save_user_properties(param, j_user, json_integer_value(json_object_get(json_array_get(j_result, 0), "gu_id")), 0) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add database - Error save_user_properties");
        ret = G_ERROR_DB;
      } else if (save_user_scope(param, json_object_get(j_user, "scope"), json_integer_value(json_object_get(json_array_get(j_result, 0), "gu_id"))) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add database - Error save_user_scope");
        ret = G_ERROR_DB;
      } else {
        ret = G_OK;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add database - Error executing j_query update");
      ret = G_ERROR_DB;
    }
  } else {
    ret = G_ERROR_NOT_FOUND;
  }
  json_decref(j_result);
  return ret;
}

int user_module_update_profile(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query, * j_result = NULL;
  int res, ret;
  
  j_query = json_pack("{sss[s]s{sO}}", "table", G_TABLE_USER, "columns", "gu_id", "where", "gu_username", username);
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK && json_array_size(j_result)) {
    j_query = json_pack("{sss{}s{ss}}",
                        "table",
                        G_TABLE_USER,
                        "set",
                        "where",
                          "gu_id",
                          json_object_get(json_array_get(j_result, 0), "gu_id"));
    
    if (json_object_get(j_user, "name") != NULL) {
      json_object_set(json_object_get(j_query, "set"), "gu_name", json_object_get(j_user, "name"));
    }
    if (json_object_size(json_object_get(j_query, "set"))) {
      res = h_update(param->conn, j_query, NULL);
    } else {
      res = H_OK;
    }
    json_decref(j_query);
    if (res == H_OK) {
      if (save_user_properties(param, j_user, json_integer_value(json_object_get(json_array_get(j_result, 0), "gu_id")), 0) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add database - Error save_user_properties");
        ret = G_ERROR_DB;
      } else {
        ret = G_OK;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add database - Error executing j_query insert");
      ret = G_ERROR_DB;
    }
  } else {
    ret = G_ERROR_NOT_FOUND;
  }
  json_decref(j_result);
  return ret;
}

int user_module_delete(struct config_module * config, const char * username, void * cls) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query;
  int res, ret;
  
  j_query = json_pack("{sss{ss}}",
                      "table",
                      G_TABLE_USER,
                      "where",
                        "gu_username",
                        username);
  res = h_delete(param->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_delete database - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

int user_module_check_password(struct config_module * config, const char * username, const char * password, void * cls) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  int ret, res;
  json_t * j_query, * j_result;
  char * clause = get_password_clause_check(param, password);
  
  j_query = json_pack("{sss[s]s{sss{ssss}}}",
                      "table",
                      G_TABLE_USER,
                      "columns",
                        "gu_id",
                      "where",
                        "gu_username",
                        username,
                        "gu_password",
                          "operator",
                          "raw",
                          "value",
                          clause);
  o_free(clause);
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      ret = G_OK;
    } else {
      ret = G_ERROR_UNAUTHORIZED;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_check_password database - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

int user_module_update_password(struct config_module * config, const char * username, const char * new_password, void * cls) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query;
  int res, ret;
  char * password_clause;
  
  password_clause = get_password_clause_write(param, new_password);
  j_query = json_pack("{sss{s{ss}}s{sO}}",
                      "table",
                      G_TABLE_USER,
                      "set",
                        "gu_password",
                          "raw",
                          password_clause,
                      "where",
                        "gu_username",
                        username);
  o_free(password_clause);
  res = h_update(param->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update_password database - Error executing j_query update");
    ret = G_ERROR_DB;
  }
  return ret;
}

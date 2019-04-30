/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Clients are authenticated via various backend available: database, ldap
 * 
 * Database client module
 * 
 * Copyright 2019 Nicolas Mora <mail@babelouest.org>
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

#define G_TABLE_CLIENT "g_client"
#define G_TABLE_CLIENT_SCOPE "g_client_scope"
#define G_TABLE_CLIENT_SCOPE_CLIENT "g_client_scope_client"
#define G_TABLE_CLIENT_PROPERTY "g_client_property"

struct mod_parameters {
  int use_glewlwyd_connection;
  digest_algorithm hash_algorithm;
  struct _h_connection * conn;
  json_t * j_params;
};

static char * get_pattern_clause(struct mod_parameters * param, const char * pattern) {
  char * escape_pattern = h_escape_string(param->conn, pattern), * clause = NULL;
  
  if (escape_pattern != NULL) {
    clause = msprintf("IN (SELECT gc_id from " G_TABLE_CLIENT " WHERE gc_client_id LIKE '%%%s%%' OR gc_name LIKE '%%%s%%' OR gc_description LIKE '%%%s%%')", escape_pattern, escape_pattern, escape_pattern);
  }
  o_free(escape_pattern);
  return clause;
}

static int append_client_properties(struct mod_parameters * param, json_t * j_client, int profile) {
  json_t * j_query, * j_result, * j_element = NULL, * j_param_config;
  int res, ret;
  size_t index = 0;
  
  if (param->conn->type == HOEL_DB_TYPE_MARIADB) {
    j_query = json_pack("{sss[ssss]s{sO}}",
                        "table",
                        G_TABLE_CLIENT_PROPERTY,
                        "columns",
                          "gcp_name AS name",
                          "gcp_value_tiny AS value_tiny",
                          "gcp_value_small AS value_small",
                          "gcp_value_medium AS value_medium",
                        "where",
                          "gc_id",
                          json_object_get(j_client, "gc_id"));
    res = h_select(param->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      json_array_foreach(j_result, index, j_element) {
        j_param_config = json_object_get(json_object_get(param->j_params, "data-format"), json_string_value(json_object_get(j_element, "name")));
        if ((!profile && json_object_get(j_param_config, "read") != json_false()) || (profile && json_object_get(j_param_config, "profile-read") != json_false())) {
          if (json_object_get(j_element, "value_tiny") != json_null()) {
            if (json_object_get(j_param_config, "multiple") == json_true()) {
              if (json_object_get(j_client, json_string_value(json_object_get(j_element, "name"))) == NULL) {
                json_object_set_new(j_client, json_string_value(json_object_get(j_element, "name")), json_array());
              }
              json_array_append(json_object_get(j_client, json_string_value(json_object_get(j_element, "name"))), json_object_get(j_element, "value_tiny"));
            } else {
              json_object_set(j_client, json_string_value(json_object_get(j_element, "name")), json_object_get(j_element, "value_tiny"));
            }
          } else if (json_object_get(j_element, "value_small") != json_null()) {
            if (json_object_get(j_param_config, "multiple") == json_true()) {
              if (json_object_get(j_client, json_string_value(json_object_get(j_element, "name"))) == NULL) {
                json_object_set_new(j_client, json_string_value(json_object_get(j_element, "name")), json_array());
              }
              json_array_append(json_object_get(j_client, json_string_value(json_object_get(j_element, "name"))), json_object_get(j_element, "value_small"));
            } else {
              json_object_set(j_client, json_string_value(json_object_get(j_element, "name")), json_object_get(j_element, "value_small"));
            }
          } else if (json_object_get(j_element, "value_medium") != json_null()) {
            if (json_object_get(j_param_config, "multiple") == json_true()) {
              if (json_object_get(j_client, json_string_value(json_object_get(j_element, "name"))) == NULL) {
                json_object_set_new(j_client, json_string_value(json_object_get(j_element, "name")), json_array());
              }
              json_array_append(json_object_get(j_client, json_string_value(json_object_get(j_element, "name"))), json_object_get(j_element, "value_medium"));
            } else {
              json_object_set(j_client, json_string_value(json_object_get(j_element, "name")), json_object_get(j_element, "value_medium"));
            }
          } else {
            if (json_object_get(j_param_config, "multiple") == json_true()) {
              if (json_object_get(j_client, json_string_value(json_object_get(j_element, "name"))) == NULL) {
                json_object_set_new(j_client, json_string_value(json_object_get(j_element, "name")), json_array());
              }
              json_array_append(json_object_get(j_client, json_string_value(json_object_get(j_element, "name"))), json_null());
            } else {
              json_object_set(j_client, json_string_value(json_object_get(j_element, "name")), json_null());
            }
          }
        }
      }
      ret = G_OK;
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "append_client_properties database - Error executing j_query");
      ret = G_ERROR_DB;
    }
  } else {
    j_query = json_pack("{sss[ss]s{sO}}",
                        "table",
                        G_TABLE_CLIENT_PROPERTY,
                        "columns",
                          "gcp_name AS name",
                          "gcp_value AS value",
                        "where",
                          "gc_id",
                          json_object_get(j_client, "gc_id"));
    res = h_select(param->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      json_array_foreach(j_result, index, j_element) {
        j_param_config = json_object_get(json_object_get(param->j_params, "data-format"), json_string_value(json_object_get(j_element, "name")));
        if ((!profile && json_object_get(j_param_config, "read") != json_false()) || (profile && json_object_get(j_param_config, "profile-read") != json_false())) {
          if (json_object_get(j_element, "value") != json_null()) {
            if (json_object_get(j_param_config, "multiple") == json_true()) {
              if (json_object_get(j_client, json_string_value(json_object_get(j_element, "name"))) == NULL) {
                json_object_set_new(j_client, json_string_value(json_object_get(j_element, "name")), json_array());
              }
              json_array_append(json_object_get(j_client, json_string_value(json_object_get(j_element, "name"))), json_object_get(j_element, "value"));
            } else {
              json_object_set(j_client, json_string_value(json_object_get(j_element, "name")), json_object_get(j_element, "value"));
            }
          } else {
            if (json_object_get(j_param_config, "multiple") == json_true()) {
              if (json_object_get(j_client, json_string_value(json_object_get(j_element, "name"))) == NULL) {
                json_object_set_new(j_client, json_string_value(json_object_get(j_element, "name")), json_array());
              }
              json_array_append(json_object_get(j_client, json_string_value(json_object_get(j_element, "name"))), json_null());
            } else {
              json_object_set(j_client, json_string_value(json_object_get(j_element, "name")), json_null());
            }
          }
        }
      }
      ret = G_OK;
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "append_client_properties database - Error executing j_query");
      ret = G_ERROR_DB;
    }
  }
  return ret;
}

static json_t * database_client_scope_get(struct mod_parameters * param, json_int_t gc_id) {
  json_t * j_query, * j_result, * j_return, * j_array, * j_scope = NULL;
  int res;
  size_t index = 0;
  char * scope_clause = msprintf("IN (SELECT gcs_id from " G_TABLE_CLIENT_SCOPE_CLIENT " WHERE gc_id = %"JSON_INTEGER_FORMAT")", gc_id);
  
  j_query = json_pack("{sss[s]s{s{ssss}}}",
                      "table",
                      G_TABLE_CLIENT_SCOPE,
                      "columns",
                        "gcs_name AS name",
                      "where",
                        "gcs_id",
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
      y_log_message(Y_LOG_LEVEL_ERROR, "database_client_scope_get database - Error allocating resources for j_array");
      j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "database_client_scope_get database - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static json_t * database_client_get(const char * client_id, void * cls, int profile) {
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query, * j_result, * j_scope, * j_return;
  int res;
  char * client_id_escaped, * client_id_clause;
  
  client_id_escaped = h_escape_string(param->conn, client_id);
  client_id_clause = msprintf(" = UPPER('%s')", client_id_escaped);  
  j_query = json_pack("{sss[ssssss]s{s{ssss}}}",
                      "table",
                      G_TABLE_CLIENT,
                      "columns",
                        "gc_id",
                        "gc_client_id AS client_id",
                        "gc_name AS name",
                        "gc_description AS description",
                        "gc_enabled",
                        "gc_confidential",
                      "where",
                        "UPPER(gc_client_id)",
                          "operator",
                          "raw",
                          "value",
                          client_id_clause);
  o_free(client_id_escaped);
  o_free(client_id_clause);
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      j_scope = database_client_scope_get(param, json_integer_value(json_object_get(json_array_get(j_result, 0), "gc_id")));
      if (check_result_value(j_scope, G_OK)) {
        json_object_set(json_array_get(j_result, 0), "scope", json_object_get(j_scope, "scope"));
        json_object_set(json_array_get(j_result, 0), "enabled", (json_integer_value(json_object_get(json_array_get(j_result, 0), "gc_enabled"))?json_true():json_false()));
        json_object_set(json_array_get(j_result, 0), "confidential", (json_integer_value(json_object_get(json_array_get(j_result, 0), "gc_confidential"))?json_true():json_false()));
        if (append_client_properties(param, json_array_get(j_result, 0), profile) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "database_client_get database - Error append_client_properties");
        }
        json_object_del(json_array_get(j_result, 0), "gc_enabled");
        json_object_del(json_array_get(j_result, 0), "gc_confidential");
        json_object_del(json_array_get(j_result, 0), "gc_id");
        j_return = json_pack("{sisO}", "result", G_OK, "client", json_array_get(j_result, 0));
      } else {
        j_return = json_pack("{si}", "result", G_ERROR);
        y_log_message(Y_LOG_LEVEL_ERROR, "database_client_get database - Error database_client_scope_get");
      }
      json_decref(j_scope);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_DB);
    y_log_message(Y_LOG_LEVEL_ERROR, "database_client_get database - Error executing j_query");
  }
  return j_return;
}

static json_t * is_client_database_parameters_valid(json_t * j_params) {
  json_t * j_return, * j_error = json_array(), * j_element = NULL;
  const char * field = NULL;
  
  if (j_error != NULL) {
    if (!json_is_object(j_params)) {
      json_array_append_new(j_error, json_string("parameters must be a JSON object"));
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
          if (json_object_get(j_params, "mariadb-client") == NULL || !json_is_string(json_object_get(j_params, "mariadb-client"))) {
            json_array_append_new(j_error, json_string("mariadb-client is mandatory and must be a string"));
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
            if (0 == o_strcmp(field, "client_id") || 0 == o_strcmp(field, "name") || 0 == o_strcmp(field, "description") || 0 == o_strcmp(field, "enabled") || 0 == o_strcmp(field, "confidential") || 0 == o_strcmp(field, "password")) {
              json_array_append_new(j_error, json_string("data-format can not have settings for properties 'client_id', 'name', 'description', 'enabled', 'confidential' or 'password'"));
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
    y_log_message(Y_LOG_LEVEL_ERROR, "is_client_database_parameters_valid - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

static char * get_password_clause_write(struct mod_parameters * param, const char * password) {
  char * clause = NULL, * password_encoded, digest[1024] = {0};
  
  if (param->conn->type == HOEL_DB_TYPE_SQLITE) {
    if (generate_digest_pbkdf2(password, NULL, digest)) {
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

static char * get_salt_from_password_hash(struct mod_parameters * param, const char * client_id) {
  json_t * j_query, * j_result;
  int res;
  unsigned char password_b64_decoded[1024] = {0};
  char * salt = NULL, * client_id_escaped, * client_id_clause;
  size_t password_b64_decoded_len;
  
  client_id_escaped = h_escape_string(param->conn, client_id);
  client_id_clause = msprintf(" = UPPER('%s')", client_id_escaped);
  j_query = json_pack("{sss[s]s{s{ssss}}}",
                      "table",
                      G_TABLE_CLIENT,
                      "columns",
                        "gc_password",
                      "where",
                        "UPPER(gc_client_id)",
                          "operator",
                          "raw",
                          "value",
                          client_id_clause);
  o_free(client_id_clause);
  o_free(client_id_escaped);
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      if (o_base64_decode((const unsigned char *)json_string_value(json_object_get(json_array_get(j_result, 0), "gc_password")), json_string_length(json_object_get(json_array_get(j_result, 0), "gc_password")), password_b64_decoded, &password_b64_decoded_len)) {
        if ((salt = o_strdup((const char *)password_b64_decoded + password_b64_decoded_len - GLEWLWYD_DEFAULT_SALT_LENGTH)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_salt_from_password_hash - Error extracting salt");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_salt_from_password_hash - Error o_base64_decode");
      }
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_salt_from_password_hash - Error executing j_query");
  }
  return salt;
}

static char * get_password_clause_check(struct mod_parameters * param, const char * client_id, const char * password) {
  char * clause = NULL, * password_encoded, digest[1024] = {0}, * salt;
  
  if (param->conn->type == HOEL_DB_TYPE_SQLITE) {
    if ((salt = get_salt_from_password_hash(param, client_id)) != NULL) {
      if (generate_digest_pbkdf2(password, salt, digest)) {
        clause = msprintf(" = '%s'", digest);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_password_clause_write database - Error generate_digest_pbkdf2");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_password_clause_write database - Error get_salt_from_password_hash");
    }
    o_free(salt);
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

static json_t * get_property_value_db(struct mod_parameters * param, const char * name, json_t * j_property, json_int_t gc_id) {
  if (param->conn->type == HOEL_DB_TYPE_MARIADB) {
    if (json_string_length(j_property) < 512) {
      return json_pack("{sIsssO}", "gc_id", gc_id, "gcp_name", name, "gcp_value_tiny", j_property);
    } else if (json_string_length(j_property) < 16*1024) {
      return json_pack("{sIsssO}", "gc_id", gc_id, "gcp_name", name, "gcp_value_small", j_property);
    } else {
      return json_pack("{sIsssO}", "gc_id", gc_id, "gcp_name", name, "gcp_value_medium", j_property);
    }
  } else {
    return json_pack("{sIsssO}", "gc_id", gc_id, "gcp_name", name, "gcp_value", j_property);;
  }
}

static int save_client_properties(struct mod_parameters * param, json_t * j_client, json_int_t gc_id, int profile) {
  json_t * j_property = NULL, * j_query, * j_array = json_array(), * j_format, * j_property_value = NULL;
  const char * name = NULL;
  int ret, res;
  size_t index = 0;
  
  if (j_array != NULL) {
    json_object_foreach(j_client, name, j_property) {
      if (0 != o_strcmp(name, "client_id") && 0 != o_strcmp(name, "name") && 0 != o_strcmp(name, "password") && 0 != o_strcmp(name, "description") && 0 != o_strcmp(name, "enabled") && 0 != o_strcmp(name, "confidential") && 0 != o_strcmp(name, "scope")) {
        j_format = json_object_get(json_object_get(param->j_params, "data-format"), name);
        if ((!profile && json_object_get(j_format, "write") != json_false()) || (profile && json_object_get(j_format, "profile-write") == json_true())) {
          if (!json_is_array(j_property)) {
            json_array_append_new(j_array, get_property_value_db(param, name, j_property, gc_id));
          } else {
            json_array_foreach(j_property, index, j_property_value) {
              json_array_append_new(j_array, get_property_value_db(param, name, j_property_value, gc_id));
            }
          }
        }
      }
    }
    // Delete old values
    j_query = json_pack("{sss{sI}}", "table", G_TABLE_CLIENT_PROPERTY, "where", "gc_id", gc_id);
    res = h_delete(param->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      // Add new values
      if (json_array_size(j_array)) {
        j_query = json_pack("{sssO}", "table", G_TABLE_CLIENT_PROPERTY, "values", j_array);
        res = h_insert(param->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "insert_client_properties database - Error executing j_query insert");
          ret = G_ERROR_DB;
        }
      } else {
        ret = G_OK;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "insert_client_properties database - Error executing j_query delete");
      ret = G_ERROR_DB;
    }
    json_decref(j_array);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "insert_client_properties database - Error allocating resources for j_array");
    ret = G_ERROR_MEMORY;
  }
  return ret;
}

static int save_client_scope(struct mod_parameters * param, json_t * j_scope, json_int_t gc_id) {
  json_t * j_query, * j_result, * j_element = NULL, * j_new_scope_id;
  int res, ret;
  char * scope_clause;
  size_t index = 0;
  
  j_query = json_pack("{sss{sI}}", "table", G_TABLE_CLIENT_SCOPE_CLIENT, "where", "gc_id", gc_id);
  res = h_delete(param->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
    if (json_is_array(j_scope)) {
      json_array_foreach(j_scope, index, j_element) {
        j_query = json_pack("{sss[s]s{sO}}",
                            "table",
                            G_TABLE_CLIENT_SCOPE,
                            "columns",
                              "gcs_id",
                            "where",
                              "gcs_name",
                              j_element);
        res = h_select(param->conn, j_query, &j_result, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          if (json_array_size(j_result)) {
            j_query = json_pack("{sss{sIsO}}",
                                "table",
                                G_TABLE_CLIENT_SCOPE_CLIENT,
                                "values",
                                  "gc_id",
                                  gc_id,
                                  "gcs_id",
                                  json_object_get(json_array_get(j_result, 0), "gcs_id"));
            res = h_insert(param->conn, j_query, NULL);
            json_decref(j_query);
            if (res != H_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "save_client_scope database - Error executing j_query insert scope_client (1)");
            }
          } else {
            j_query = json_pack("{sss{sO}}",
                                "table",
                                G_TABLE_CLIENT_SCOPE,
                                "values",
                                  "gcs_name",
                                  j_element);
            res = h_insert(param->conn, j_query, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              j_new_scope_id = h_last_insert_id(param->conn);
              if (j_new_scope_id != NULL) {
                j_query = json_pack("{sss{sIsO}}",
                                    "table",
                                    G_TABLE_CLIENT_SCOPE_CLIENT,
                                    "values",
                                      "gc_id",
                                      gc_id,
                                      "gcs_id",
                                      j_new_scope_id);
                res = h_insert(param->conn, j_query, NULL);
                json_decref(j_query);
                if (res != H_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "save_client_scope database - Error executing j_query insert scope_client (2)");
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "save_client_scope database - Error h_last_insert_id");
              }
              json_decref(j_new_scope_id);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "save_client_scope database - Error executing j_query insert scope");
            }
          }
          json_decref(j_result);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "save_client_scope database - Error executing j_query select scope");
        }
      }
    }
    // Clean orphan client_scope
    scope_clause = msprintf("NOT IN (SELECT DISTINCT(gcs_id) FROM " G_TABLE_CLIENT_SCOPE_CLIENT ")");
    j_query = json_pack("{sss{s{ssss}}}",
                        "table",
                        G_TABLE_CLIENT_SCOPE,
                        "where",
                          "gcs_id",
                            "operator",
                            "raw",
                            "value",
                            scope_clause);
    o_free(scope_clause);
    res = h_delete(param->conn, j_query, NULL);
    json_decref(j_query);
    if (res != H_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "save_client_scope database - Error executing j_query delete empty scopes");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "save_client_scope database - Error executing j_query delete");
    ret = G_ERROR_DB;
  }
  
  return ret;
}

json_t * client_module_load(struct config_module * config) {
  UNUSED(config);
  return json_pack("{si ss ss ss s{s{ssso} s{sss[sss]so} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{s{s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} }}}}",
                   "result",
                   G_OK,
                   
                   "name",
                   "database",
                   
                   "display_name",
                   "Database backend client module",
                   
                   "description",
                   "Module to store clients in the database",
                   
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
                       
                     "mariadb-client",
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

int client_module_unload(struct config_module * config) {
  UNUSED(config);
  return G_OK;
}

int client_module_init(struct config_module * config, int readonly, json_t * j_parameters, void ** cls) {
  UNUSED(readonly);
  json_t * j_result;
  int ret;
  char * error_message;
  
  j_result = is_client_database_parameters_valid(j_parameters);
  if (check_result_value(j_result, G_OK)) {
    *cls = o_malloc(sizeof(struct mod_parameters));
    if (*cls != NULL) {
      ((struct mod_parameters *)*cls)->j_params = json_incref(j_parameters);
      ((struct mod_parameters *)*cls)->hash_algorithm = config->hash_algorithm;
      if (json_object_get(j_parameters, "use-glewlwyd-connection") != json_false()) {
          ((struct mod_parameters *)*cls)->use_glewlwyd_connection = 0;
          ((struct mod_parameters *)*cls)->conn = config->conn;
      } else {
        ((struct mod_parameters *)*cls)->use_glewlwyd_connection = 1;
        if (0 == o_strcmp(json_string_value(json_object_get(j_parameters, "connection-type")), "sqlite")) {
          ((struct mod_parameters *)*cls)->conn = h_connect_sqlite(json_string_value(json_object_get(j_parameters, "sqlite-dbpath")));
        } else if (0 == o_strcmp(json_string_value(json_object_get(j_parameters, "connection-type")), "mariadb")) {
          ((struct mod_parameters *)*cls)->conn = h_connect_mariadb(json_string_value(json_object_get(j_parameters, "mariadb-host")), json_string_value(json_object_get(j_parameters, "mariadb-client")), json_string_value(json_object_get(j_parameters, "mariadb-password")), json_string_value(json_object_get(j_parameters, "mariadb-dbname")), json_integer_value(json_object_get(j_parameters, "mariadb-port")), NULL);
        } else if (0 == o_strcmp(json_string_value(json_object_get(j_parameters, "connection-type")), "postgre")) {
          ((struct mod_parameters *)*cls)->conn = h_connect_pgsql(json_string_value(json_object_get(j_parameters, "postgre-conninfo")));
        }
      }
      if (((struct mod_parameters *)*cls)->conn != NULL) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error connecting to database");
        ret = G_ERROR_PARAM;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_module_init database - Error allocating resources for cls");
      ret = G_ERROR_MEMORY;
    }
  } else if (check_result_value(j_result, G_ERROR_PARAM)) {
    error_message = json_dumps(json_object_get(j_result, "error"), JSON_COMPACT);
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_init database - Error parsing parameters");
    y_log_message(Y_LOG_LEVEL_ERROR, error_message);
    o_free(error_message);
    ret = G_ERROR_PARAM;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_init database - Error is_client_database_parameters_valid");
    ret = G_ERROR;
  }
  json_decref(j_result);
  return ret;
}

int client_module_close(struct config_module * config, void * cls) {
  UNUSED(config);
  int ret;
  
  if (cls != NULL) {
    if (((struct mod_parameters *)cls)->use_glewlwyd_connection) {
      if (h_close_db(((struct mod_parameters *)cls)->conn) != H_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "client_module_close database - Error h_close_db");
        ret = G_ERROR_DB;
      } else {
        ret = G_OK;
      }
    } else {
      ret = G_OK;
    }
    json_decref(((struct mod_parameters *)cls)->j_params);
    o_free(cls);
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

size_t client_module_count_total(struct config_module * config, const char * pattern, void * cls) {
  UNUSED(config);
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query, * j_result = NULL;
  int res;
  size_t ret = 0;
  char * pattern_clause;
  
  j_query = json_pack("{sss[s]}",
                      "table",
                      G_TABLE_CLIENT,
                      "columns",
                        "count(gc_id) AS total");
  if (o_strlen(pattern)) {
    pattern_clause = get_pattern_clause(param, pattern);
    json_object_set_new(j_query, "where", json_pack("{s{ssss}}", "gc_id", "operator", "raw", "value", pattern_clause));
    o_free(pattern_clause);
  }
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = (size_t)json_integer_value(json_object_get(json_array_get(j_result, 0), "total"));
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_count_total database - Error executing j_query");
  }
  return ret;
}

json_t * client_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls) {
  UNUSED(config);
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query, * j_result, * j_element = NULL, * j_scope, * j_return;
  int res;
  char * pattern_clause;
  size_t index = 0;
  
  j_query = json_pack("{sss[ssssss]sisiss}",
                      "table",
                      G_TABLE_CLIENT,
                      "columns",
                        "gc_id",
                        "gc_client_id AS client_id",
                        "gc_name AS name",
                        "gc_description AS description",
                        "gc_enabled",
                        "gc_confidential",
                      "offset",
                      offset,
                      "limit",
                      limit,
                      "order_by",
                      "gc_client_id");
  if (o_strlen(pattern)) {
    pattern_clause = get_pattern_clause(param, pattern);
    json_object_set_new(j_query, "where", json_pack("{s{ssss}}", "gc_id", "operator", "raw", "value", pattern_clause));
    o_free(pattern_clause);
  }
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      j_scope = database_client_scope_get(param, json_integer_value(json_object_get(j_element, "gc_id")));
      if (check_result_value(j_scope, G_OK)) {
        json_object_set(j_element, "scope", json_object_get(j_scope, "scope"));
        json_object_set(j_element, "enabled", (json_integer_value(json_object_get(j_element, "gc_enabled"))?json_true():json_false()));
        json_object_set(j_element, "confidential", (json_integer_value(json_object_get(j_element, "gc_confidential"))?json_true():json_false()));
        if (append_client_properties(param, j_element, 0) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get_list database - Error append_client_properties");
        }
        json_object_del(j_element, "gc_enabled");
        json_object_del(j_element, "gc_confidential");
        json_object_del(j_element, "gc_id");
      } else {
        j_return = json_pack("{si}", "result", G_ERROR);
        y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get_list database - Error database_client_scope_get");
      }
      json_decref(j_scope);
    }
    j_return = json_pack("{sisO}", "result", G_OK, "list", j_result);
    json_decref(j_result);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_DB);
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get_list database - Error executing j_query");
  }
  return j_return;
}

json_t * client_module_get(struct config_module * config, const char * client_id, void * cls) {
  UNUSED(config);
  return database_client_get(client_id, cls, 0);
}

json_t * client_module_get_profile(struct config_module * config, const char * client_id, void * cls) {
  UNUSED(config);
  return database_client_get(client_id, cls, 1);
}

json_t * client_module_is_valid(struct config_module * config, const char * client_id, json_t * j_client, int mode, void * cls) {
  UNUSED(config);
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_result = json_array(), * j_element, * j_format, * j_value, * j_return = NULL, * j_cur_client;
  char * message;
  size_t index = 0;
  const char * property;
  
  if (j_result != NULL) {
    if (mode == GLEWLWYD_IS_VALID_MODE_ADD) {
      if (!json_is_string(json_object_get(j_client, "client_id")) || json_string_length(json_object_get(j_client, "client_id")) > 128) {
        json_array_append_new(j_result, json_string("client_id is mandatory and must be a string of at least 128 characters"));
      } else {
        j_cur_client = client_module_get(config, json_string_value(json_object_get(j_client, "client_id")), cls);
        if (check_result_value(j_cur_client, G_OK)) {
          json_array_append_new(j_result, json_string("client_id already exist"));
        } else if (!check_result_value(j_cur_client, G_ERROR_NOT_FOUND)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "client_module_is_valid database - Error client_module_get");
        }
        json_decref(j_cur_client);
      }
    } else if ((mode == GLEWLWYD_IS_VALID_MODE_UPDATE || mode == GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) && client_id == NULL) {
      json_array_append_new(j_result, json_string("client_id is mandatory on update mode"));
    }
    if (mode != GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) {
      if (json_object_get(j_client, "scope") != NULL) {
        if (!json_is_array(json_object_get(j_client, "scope"))) {
          json_array_append_new(j_result, json_string("scope must be a JSON array of string"));
        } else {
          json_array_foreach(json_object_get(j_client, "scope"), index, j_element) {
            if (!json_is_string(j_element) || !json_string_length(j_element)) {
              json_array_append_new(j_result, json_string("scope must be a JSON array of string"));
            }
          }
        }
      }
    }
    if (mode != GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE && json_object_get(j_client, "password") != NULL && !json_is_string(json_object_get(j_client, "password"))) {
      json_array_append_new(j_result, json_string("password must be a string"));
    }
    if (json_object_get(j_client, "name") != NULL && (!json_is_string(json_object_get(j_client, "name")) || json_string_length(json_object_get(j_client, "name")) > 256)) {
      json_array_append_new(j_result, json_string("name must be a string of at least 256 characters"));
    }
    if (json_object_get(j_client, "description") != NULL && (!json_is_string(json_object_get(j_client, "description")) || json_string_length(json_object_get(j_client, "description")) > 512)) {
      json_array_append_new(j_result, json_string("description must be a string of at least 512 characters"));
    }
    if (json_object_get(j_client, "enabled") != NULL && !json_is_boolean(json_object_get(j_client, "enabled"))) {
      json_array_append_new(j_result, json_string("enabled must be a boolean"));
    }
    if (json_object_get(j_client, "confidential") != NULL && !json_is_boolean(json_object_get(j_client, "confidential"))) {
      json_array_append_new(j_result, json_string("confidential must be a boolean"));
    }
    json_object_foreach(j_client, property, j_element) {
      if (0 != o_strcmp(property, "client_id") && 0 != o_strcmp(property, "name") && 0 != o_strcmp(property, "confidential") && 0 != o_strcmp(property, "enabled") && 0 != o_strcmp(property, "password") && 0 != o_strcmp(property, "source") && 0 != o_strcmp(property, "scope")) {
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
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_is_valid database - Error allocating resources for j_result");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

int client_module_add(struct config_module * config, json_t * j_client, void * cls) {
  UNUSED(config);
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query, * j_gc_id;
  int res, ret;
  char * password_clause;
  
  j_query = json_pack("{sss{ss}}",
                      "table",
                      G_TABLE_CLIENT,
                      "values",
                        "gc_client_id",
                        json_string_value(json_object_get(j_client, "client_id")));
  
  if (json_object_get(j_client, "password") != NULL) {
    password_clause = get_password_clause_write(param, json_string_value(json_object_get(j_client, "password")));
    json_object_set_new(json_object_get(j_query, "values"), "gc_password", json_pack("{ss}", "raw", password_clause));
    o_free(password_clause);
  }
  if (json_object_get(j_client, "name") != NULL) {
    json_object_set(json_object_get(j_query, "values"), "gc_name", json_object_get(j_client, "name"));
  }
  if (json_object_get(j_client, "description") != NULL) {
    json_object_set(json_object_get(j_query, "values"), "gc_description", json_object_get(j_client, "description"));
  }
  if (json_object_get(j_client, "enabled") != NULL) {
    json_object_set_new(json_object_get(j_query, "values"), "gc_enabled", json_object_get(j_client, "enabled")==json_false()?json_integer(0):json_integer(1));
  }
  if (json_object_get(j_client, "confidential") != NULL) {
    json_object_set_new(json_object_get(j_query, "values"), "gc_confidential", json_object_get(j_client, "confidential")==json_false()?json_integer(0):json_integer(1));
  }
  res = h_insert(param->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_gc_id = h_last_insert_id(param->conn);
    if (save_client_properties(param, j_client, json_integer_value(j_gc_id), 0) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_module_add database - Error save_client_properties");
      ret = G_ERROR_DB;
    } else if (save_client_scope(param, json_object_get(j_client, "scope"), json_integer_value(j_gc_id)) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_module_add database - Error save_client_scope");
      ret = G_ERROR_DB;
    } else {
      ret = G_OK;
    }
    json_decref(j_gc_id);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_add database - Error executing j_query insert");
    ret = G_ERROR_DB;
  }
  return ret;
}

int client_module_update(struct config_module * config, const char * client_id, json_t * j_client, void * cls) {
  UNUSED(config);
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query, * j_result = NULL;
  int res, ret;
  char * password_clause;
  char * client_id_escaped, * client_id_clause;
  
  client_id_escaped = h_escape_string(param->conn, client_id);
  client_id_clause = msprintf(" = UPPER('%s')", client_id_escaped);  
  j_query = json_pack("{sss[s]s{s{ssss}}}", "table", G_TABLE_CLIENT, "columns", "gc_id", "where", "UPPER(gc_client_id)", "operator", "raw", "value", client_id_clause);
  o_free(client_id_escaped);
  o_free(client_id_clause);
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK && json_array_size(j_result)) {
    j_query = json_pack("{sss{}s{sO}}",
                        "table",
                        G_TABLE_CLIENT,
                        "set",
                        "where",
                          "gc_id",
                          json_object_get(json_array_get(j_result, 0), "gc_id"));
    
    if (json_object_get(j_client, "password") != NULL) {
      password_clause = get_password_clause_write(param, json_string_value(json_object_get(j_client, "password")));
    json_object_set_new(json_object_get(j_query, "set"), "gc_password", json_pack("{ss}", "raw", password_clause));
      o_free(password_clause);
    }
    if (json_object_get(j_client, "name") != NULL) {
      json_object_set(json_object_get(j_query, "set"), "gc_name", json_object_get(j_client, "name"));
    }
    if (json_object_get(j_client, "description") != NULL) {
      json_object_set(json_object_get(j_query, "set"), "gc_description", json_object_get(j_client, "description"));
    }
    if (json_object_get(j_client, "enabled") != NULL) {
      json_object_set_new(json_object_get(j_query, "set"), "gc_enabled", json_object_get(j_client, "enabled")==json_false()?json_integer(0):json_integer(1));
    }
    if (json_object_get(j_client, "confidential") != NULL) {
      json_object_set_new(json_object_get(j_query, "set"), "gc_confidential", json_object_get(j_client, "confidential")==json_false()?json_integer(0):json_integer(1));
    }
    if (json_object_size(json_object_get(j_query, "set"))) {
      res = h_update(param->conn, j_query, NULL);
    } else {
      res = H_OK;
    }
    json_decref(j_query);
    if (res == H_OK) {
      if (save_client_properties(param, j_client, json_integer_value(json_object_get(json_array_get(j_result, 0), "gc_id")), 0) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "client_module_add database - Error save_client_properties");
        ret = G_ERROR_DB;
      } else if (save_client_scope(param, json_object_get(j_client, "scope"), json_integer_value(json_object_get(json_array_get(j_result, 0), "gc_id"))) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "client_module_add database - Error save_client_scope");
        ret = G_ERROR_DB;
      } else {
        ret = G_OK;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_module_add database - Error executing j_query update");
      ret = G_ERROR_DB;
    }
  } else {
    ret = G_ERROR_NOT_FOUND;
  }
  json_decref(j_result);
  return ret;
}

int client_module_delete(struct config_module * config, const char * client_id, void * cls) {
  UNUSED(config);
  struct mod_parameters * param = (struct mod_parameters *)cls;
  json_t * j_query;
  int res, ret;
  char * client_id_escaped, * client_id_clause;
  
  client_id_escaped = h_escape_string(param->conn, client_id);
  client_id_clause = msprintf(" = UPPER('%s')", client_id_escaped);  
  j_query = json_pack("{sss{s{ssss}}}",
                      "table",
                      G_TABLE_CLIENT,
                      "where",
                        "UPPER(gc_client_id)",
                          "operator",
                          "raw",
                          "value",
                          client_id_clause);
  o_free(client_id_escaped);
  o_free(client_id_clause);
  res = h_delete(param->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_delete database - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

int client_module_check_password(struct config_module * config, const char * client_id, const char * password, void * cls) {
  UNUSED(config);
  struct mod_parameters * param = (struct mod_parameters *)cls;
  int ret, res;
  json_t * j_query, * j_result;
  char * clause = get_password_clause_check(param, client_id, password);
  char * client_id_escaped, * client_id_clause;
  
  client_id_escaped = h_escape_string(param->conn, client_id);
  client_id_clause = msprintf(" = UPPER('%s')", client_id_escaped);  
  j_query = json_pack("{sss[s]s{s{ssss}s{ssss}}}",
                      "table",
                      G_TABLE_CLIENT,
                      "columns",
                        "gc_id",
                      "where",
                        "UPPER(gc_client_id)",
                          "operator",
                          "raw",
                          "value",
                          client_id_clause,
                        "gc_password",
                          "operator",
                          "raw",
                          "value",
                          clause);
  o_free(client_id_escaped);
  o_free(client_id_clause);
  o_free(clause);
  res = h_select(param->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      ret = G_OK;
    } else {
      ret = G_ERROR_UNAUTHORIZED;
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_check_password database - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

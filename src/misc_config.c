/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Misc Config functions definition
 *
 * Copyright 2016-2021 Nicolas Mora <mail@babelouest.org>
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

json_t * get_misc_config_list(struct config_elements * config) {
  json_t * j_query, * j_result = NULL, * j_return, * j_element = NULL;
  int res;
  size_t index;
  
  j_query = json_pack("{sss[sss]}",
                      "table", GLEWLWYD_TABLE_MISC_CONFIG,
                      "columns",
                        "gmc_type AS type",
                        "gmc_name AS name",
                        "gmc_value");
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      if (json_object_get(j_element, "gmc_value") != json_null()) {
        json_object_set_new(j_element, "value", json_loads(json_string_value(json_object_get(j_element, "gmc_value")), JSON_DECODE_ANY, NULL));
      } else {
        json_object_set(j_element, "value", json_null());
      }
      json_object_del(j_element, "gmc_value");
    }
    j_return = json_pack("{siso}", "result", G_OK, "misc_config", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_misc_config_list - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

json_t * get_misc_config(struct config_elements * config, const char * type, const char * name) {
  json_t * j_query, * j_result = NULL, * j_return;
  int res;
  
  j_query = json_pack("{sss[sss]s{}}",
                      "table", GLEWLWYD_TABLE_MISC_CONFIG,
                      "columns",
                        "gmc_type AS type",
                        "gmc_name AS name",
                        "gmc_value",
                      "where");
  if (!o_strnullempty(type)) {
    json_object_set_new(json_object_get(j_query, "where"), "gmc_type", json_string(type));
  }
  if (!o_strnullempty(name)) {
    json_object_set_new(json_object_get(j_query, "where"), "gmc_name", json_string(name));
  }
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      if (json_object_get(json_array_get(j_result, 0), "gmc_value") != json_null()) {
        json_object_set_new(json_array_get(j_result, 0), "value", json_loads(json_string_value(json_object_get(json_array_get(j_result, 0), "gmc_value")), JSON_DECODE_ANY, NULL));
      } else {
        json_object_set(json_array_get(j_result, 0), "value", json_null());
      }
      json_object_del(json_array_get(j_result, 0), "gmc_value");
      j_return = json_pack("{sisO}", "result", G_OK, "misc_config", json_array_get(j_result, 0));
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_misc_config - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

json_t * is_misc_config_valid(const char * name, json_t * j_misc_config) {
  json_t * j_error = json_array(), * j_return;
  char * value;
  
  if (j_error != NULL) {
    if (o_strnullempty(name) || o_strlen(name) > 128) {
      json_array_append_new(j_error, json_string("name is mandatory and must be a non empty string, maximum 128 characters"));
    }
    if (json_string_null_or_empty(json_object_get(j_misc_config, "type")) || json_string_length(json_object_get(j_misc_config, "type")) > 128) {
      json_array_append_new(j_error, json_string("type is mandatory and must be a non empty string, maximum 128 characters"));
    }
    if (json_object_get(j_misc_config, "value") != NULL) {
      value = json_dumps(json_object_get(j_misc_config, "value"), JSON_COMPACT);
      if (o_strlen(value) > 16*1024*1024) {
        json_array_append_new(j_error, json_string("value is optional and must be a string, maximum 16M characters"));
      }
      o_free(value);
    }
    if (json_array_size(j_error)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
    } else {
      j_return = json_pack("{si}", "result", G_OK);
    }
    json_decref(j_error);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_misc_config_valid - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

int add_misc_config(struct config_elements * config, const char * name, json_t * j_misc_config) {
  json_t * j_query;
  int res, ret;
  char * value = NULL;
  
  if (json_object_get(j_misc_config, "value") != NULL && json_object_get(j_misc_config, "value") != json_null()) {
    value = json_dumps(json_object_get(j_misc_config, "value"), JSON_COMPACT);
  }
  j_query = json_pack("{sss{sOssss?}}",
                      "table", GLEWLWYD_TABLE_MISC_CONFIG,
                      "values",
                        "gmc_type", json_object_get(j_misc_config, "type"),
                        "gmc_name", name,
                        "gmc_value", value);
  o_free(value);
  res = h_insert(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_misc_config - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

int set_misc_config(struct config_elements * config, const char * name, json_t * j_misc_config) {
  json_t * j_query;
  int res, ret;
  char * value = NULL;
  
  if (json_object_get(j_misc_config, "value") != NULL && json_object_get(j_misc_config, "value") != json_null()) {
    value = json_dumps(json_object_get(j_misc_config, "value"), JSON_COMPACT);
  }
  j_query = json_pack("{sss{sOss?}s{ss}}",
                      "table", GLEWLWYD_TABLE_MISC_CONFIG,
                      "set",
                        "gmc_type", json_object_get(j_misc_config, "type"),
                        "gmc_value", value,
                      "where",
                        "gmc_name", name);
  o_free(value);
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_misc_config - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

int delete_misc_config(struct config_elements * config, const char * name) {
  json_t * j_query;
  int res, ret;
  
  j_query = json_pack("{sss{ss}}",
                      "table", GLEWLWYD_TABLE_MISC_CONFIG,
                      "where",
                        "gmc_name", name);
  res = h_delete(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_misc_config - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

struct _update_issued_for {
  struct config_elements * config;
  const struct _h_connection * conn;
  json_t * j_query;
  char * issued_for_column;
  char * issued_for_value;
};

void * run_thread_update_issued_for(void * args) {
  struct _update_issued_for * thread_config = (struct _update_issued_for *)args;
  char * ip_address = o_strdup(thread_config->issued_for_value), * ip_data = NULL;
  int res;

  if (o_strchr(ip_address, ',') != NULL) {
    *o_strchr(ip_address, ',') = '\0';
  }
  if (o_strchr(ip_address, ' ') != NULL) {
    *o_strchr(ip_address, ' ') = '\0';
  }
  if (o_strchr(ip_address, '-') != NULL) {
    *o_strchr(ip_address, '-') = '\0';
  }
  ip_data = get_ip_data(thread_config->config, ip_address);
  if (ip_data != NULL) {
    json_object_set_new(json_object_get(thread_config->j_query, "set"), thread_config->issued_for_column, json_pack("s++", thread_config->issued_for_value, " - ", ip_data));
    res = h_update(thread_config->conn, thread_config->j_query, NULL);
    if (res != H_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "run_thread_update_issued_for - Error executing j_query");
    }
  }
  o_free(ip_data);
  o_free(ip_address);
  o_free(thread_config->issued_for_column);
  o_free(thread_config->issued_for_value);
  json_decref(thread_config->j_query);
  o_free(thread_config);
  
  return NULL;
}

void update_issued_for(struct config_elements * config, const struct _h_connection * conn, const char * sql_table, const char * issued_for_column, const char * issued_for_value, const char * id_column, json_int_t id_value) {
  struct _update_issued_for * thread_config = o_malloc(sizeof(struct _update_issued_for));
  pthread_t thread_update_issued_for;
  int thread_ret, thread_detach;
  pthread_attr_t attr;
  struct sched_param param;

  if (thread_config != NULL) {
    thread_config->config = config;
    if (conn != NULL) {
      thread_config->conn = conn;
    } else {
      thread_config->conn = config->conn;
    }
    thread_config->j_query = json_pack("{sss{}s{sI}}",
                                "table", sql_table,
                                "set",
                                "where",
                                  id_column, id_value);
    thread_config->issued_for_column = o_strdup(issued_for_column);
    thread_config->issued_for_value = o_strdup(issued_for_value);

    pthread_attr_init (&attr);
    pthread_attr_getschedparam (&attr, &param);
    param.sched_priority = 0;
    pthread_attr_setschedparam (&attr, &param);
    thread_ret = pthread_create(&thread_update_issued_for, &attr, run_thread_update_issued_for, (void *)thread_config);
    thread_detach = pthread_detach(thread_update_issued_for);
    if (thread_ret || thread_detach) {
      y_log_message(Y_LOG_LEVEL_ERROR, "update_issued_for - Error thread");
      o_free(thread_config->issued_for_column);
      o_free(thread_config->issued_for_value);
      json_decref(thread_config->j_query);
      o_free(thread_config);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "update_issued_for - Error allocating resources for thread_config");
  }
}

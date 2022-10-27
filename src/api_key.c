/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * API key functions definition
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

int verify_api_key(struct config_elements * config, const char * token) {
  json_t * j_query, * j_result = NULL;
  int res, ret;
  char * token_hash = NULL, * tmp;
  
  if (o_strlen(token) == GLEWLWYD_API_KEY_LENGTH) {
    if ((token_hash = generate_hash(config->hash_algorithm, token)) != NULL) {
      tmp = str_replace(token_hash, "/", "_");
      o_free(token_hash);
      token_hash = str_replace(tmp, "+", "-");
      o_free(tmp);
      j_query = json_pack("{sss[ss]s{ss?si}}",
                          "table",
                          GLEWLWYD_TABLE_API_KEY,
                          "columns",
                            "gak_id",
                            "gak_counter",
                          "where",
                            "gak_token_hash",
                            token_hash,
                            "gak_enabled",
                            1);
      o_free(token_hash);
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          j_query = json_pack("{sss{sI}s{sO}}",
                              "table",
                              GLEWLWYD_TABLE_API_KEY,
                              "set",
                                "gak_counter",
                                json_integer_value(json_object_get(json_array_get(j_result, 0), "gak_counter"))+1,
                              "where",
                                "gak_id",
                                json_object_get(json_array_get(j_result, 0), "gak_id"));
          res = h_update(config->conn, j_query, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            ret = G_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "verify_api_key - Error executing j_query (2)");
            glewlwyd_metrics_increment_counter_va(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
            ret = G_ERROR_DB;
          }
        } else {
          ret = G_ERROR_UNAUTHORIZED;
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "verify_api_key - Error executing j_query (1)");
        glewlwyd_metrics_increment_counter_va(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        ret = G_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "verify_api_key - Error generate_hash");
      ret = G_ERROR;
    }
  } else {
    ret = G_ERROR_UNAUTHORIZED;
  }
  return ret;
}

json_t * get_api_key_list(struct config_elements * config, const char * pattern, size_t offset, size_t limit) {
  json_t * j_query, * j_result, * j_return, * j_element;
  int res;
  size_t index;
  char * pattern_escaped, * pattern_clause;

  j_query = json_pack("{sss[sssssss]siss}",
                      "table",
                      GLEWLWYD_TABLE_API_KEY,
                      "columns",
                        "gak_token_hash AS token_hash",
                        "gak_counter AS counter",
                        "gak_username AS username",
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gak_issued_at) AS issued_at", "strftime('%s', gak_issued_at) AS issued_at", "EXTRACT(EPOCH FROM gak_issued_at)::integer AS issued_at"),
                        "gak_issued_for AS issued_for",
                        "gak_user_agent AS user_agent",
                        "gak_enabled",
                      "offset",
                      offset,
                      "order_by",
                      "gak_issued_at");
  if (limit) {
    json_object_set_new(j_query, "limit", json_integer((json_int_t)limit));
  }
  if (!o_strnullempty(pattern)) {
    pattern_escaped = h_escape_string_with_quotes(config->conn, pattern);
    pattern_clause = msprintf("IN (SELECT gak_id FROM " GLEWLWYD_TABLE_API_KEY " WHERE gak_username LIKE '%%'||%s||'%%' OR gak_issued_for LIKE '%%'||%s||'%%' OR gak_user_agent LIKE '%%'||%s||'%%')", pattern_escaped, pattern_escaped, pattern_escaped);
    json_object_set_new(j_query, "where", json_pack("{s{ssss}}", "gak_id", "operator", "raw", "value", pattern_clause));
    o_free(pattern_escaped);
    o_free(pattern_clause);
  }
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      json_object_set(j_element, "enabled", json_integer_value(json_object_get(j_element, "gak_enabled"))?json_true():json_false());
      json_object_del(j_element, "gak_enabled");
    }
    j_return = json_pack("{siso}", "result", G_OK, "api_key", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_api_key_list - Error executing j_query");
    glewlwyd_metrics_increment_counter_va(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

json_t * generate_api_key(struct config_elements * config, const char * username, const char * issued_for, const char * user_agent) {
  json_t * j_query, * j_return, * j_last_index;
  int res;
  char token[GLEWLWYD_API_KEY_LENGTH+1] = {0}, * token_hash, * tmp;
  
  if (rand_string(token, GLEWLWYD_API_KEY_LENGTH) != NULL) {
    token_hash = generate_hash(config->hash_algorithm, token);
    if (token_hash != NULL) {
      tmp = str_replace(token_hash, "/", "_");
      o_free(token_hash);
      token_hash = str_replace(tmp, "+", "-");
      o_free(tmp);
      if (pthread_mutex_lock(&config->insert_lock)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_api_key - Error pthread_mutex_lock");
        j_return = json_pack("{si}", "result", G_ERROR);
      } else {
        j_query = json_pack("{sss{ssssssss?}}",
                            "table", GLEWLWYD_TABLE_API_KEY,
                            "values",
                              "gak_token_hash", token_hash,
                              "gak_username", username,
                              "gak_issued_for", issued_for,
                              "gak_user_agent", user_agent);
        res = h_insert(config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          if ((j_last_index = h_last_insert_id(config->conn)) != NULL) {
            update_issued_for(config, NULL, GLEWLWYD_TABLE_API_KEY, "gak_issued_for", issued_for, "gak_id", json_integer_value(j_last_index));
            j_return = json_pack("{sis{ss}}", "result", G_OK, "api_key", "key", token);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "generate_api_key - Error j_last_index");
            glewlwyd_metrics_increment_counter_va(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
            j_return = json_pack("{si}", "result", G_ERROR_DB);
          }
          json_decref(j_last_index);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_api_key - Error executing j_query");
          glewlwyd_metrics_increment_counter_va(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        pthread_mutex_unlock(&config->insert_lock);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_api_key - Error generate_hash");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(token_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_api_key - Error rand_string");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

int disable_api_key(struct config_elements * config, const char * token_hash) {
  json_t * j_query;
  int res, ret;
  
  if (!o_strnullempty(token_hash)) {
    j_query = json_pack("{sss{si}s{sssi}}",
                        "table",
                        GLEWLWYD_TABLE_API_KEY,
                        "set",
                          "gak_enabled",
                          0,
                        "where",
                          "gak_token_hash",
                          token_hash,
                          "gak_enabled",
                          1);
    res = h_update(config->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      ret = G_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "disable_api_key - Error executing j_query");
      glewlwyd_metrics_increment_counter_va(config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
      ret = G_ERROR_DB;
    }
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

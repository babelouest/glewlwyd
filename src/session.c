/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * HTTP Session functions definition
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

json_t * get_session_scheme(struct config_elements * config, json_int_t gus_id) {
  json_t * j_query, * j_result, * j_return;
  int res;
  char * expire_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?o_strdup("> NOW()"):o_strdup("> (strftime('%s','now'))");
  
  j_query = json_pack("{sss[ss]s{sIsis{ssss}}}",
                      "table",
                      GLEWLWYD_TABLE_USER_SESSION_SCHEME,
                      "columns",
                        "guss_scheme_name AS scheme_name",
                        "UNIX_TIMESTAMP(`guss_expiration`) AS expiration",
                      "where",
                        "gus_id",
                        gus_id,
                        "guss_enabled",
                        1,
                        "guss_expiration",
                          "operator",
                          "raw",
                          "value",
                          expire_clause);
  o_free(expire_clause);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_return = json_pack("{siso}", "result", G_OK, "scheme", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_session_scheme - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

json_t * get_session_for_username(struct config_elements * config, const char * session_uid, const char * username) {
  json_t * j_query, * j_result, * j_return, * j_session_scheme;
  int res;
  char * expire_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?o_strdup("> NOW()"):o_strdup("> (strftime('%s','now'))");
  char * session_uid_hash = generate_hash(config, config->hash_algorithm, session_uid);

  if (session_uid_hash != NULL) {
    j_query = json_pack("{sss[ss]s{sssssis{ssss}}}",
                        "table",
                        GLEWLWYD_TABLE_USER_SESSION,
                        "columns",
                          "gus_id",
                          "UNIX_TIMESTAMP(`gus_expiration`) AS expiration",
                        "where",
                          "gus_uuid",
                          session_uid_hash,
                          "gus_username",
                          username,
                          "gus_enabled",
                          1,
                          "gus_expiration",
                            "operator",
                            "raw",
                            "value",
                            expire_clause);
    o_free(expire_clause);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result) > 0) {
        j_session_scheme = get_session_scheme(config, json_integer_value(json_object_get(json_array_get(j_result, 0), "gus_id")));
        if (check_result_value(j_session_scheme, G_OK)) {
          j_return = json_pack("{sis{sssOsOsI}}", 
                                "result", 
                                G_OK, 
                                "session", 
                                  "username", 
                                  username, 
                                  "expiration", 
                                  json_object_get(json_array_get(j_result, 0), "expiration"),
                                  "scheme",
                                  json_object_get(j_session_scheme, "scheme"),
                                  "gus_id",
                                  json_integer_value(json_object_get(json_array_get(j_result, 0), "gus_id")));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_available_session_from_username - Error get_session_scheme");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_session_scheme);
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_available_session_from_username - Error executing j_query");
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
    o_free(session_uid_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_available_session_from_username - Error generate_hash");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

json_t * get_session(struct config_elements * config, const char * session_uid) {
  json_t * j_query, * j_result, * j_return, * j_session, * j_element;
  size_t index;
  int res;
  char * expire_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?o_strdup("> NOW()"):o_strdup("> (strftime('%s','now'))");
  char * session_uid_hash = generate_hash(config, config->hash_algorithm, session_uid);

  if (session_uid_hash != NULL) {
    j_query = json_pack("{sss[ss]s{sssis{ssss}}}",
                        "table",
                        GLEWLWYD_TABLE_USER_SESSION,
                        "columns",
                          "gus_username",
                          "UNIX_TIMESTAMP(`gus_expiration`) AS expiration",
                        "where",
                          "gus_uuid",
                          session_uid_hash,
                          "gus_enabled",
                          1,
                          "gus_expiration",
                            "operator",
                            "raw",
                            "value",
                            expire_clause);
    o_free(expire_clause);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result) > 0) {
        j_return = json_pack("{sis[]}", "result", G_OK, "session");
        if (j_return != NULL) {
          json_array_foreach(j_result, index, j_element) {
            j_session = get_session_for_username(config, session_uid, json_string_value(json_object_get(j_element, "gus_username")));
            if (check_result_value(j_session, G_OK)) {
              json_array_append(json_object_get(j_return, "session"), json_object_get(j_session, "session"));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_available_session_from_username - Error get_session_for_username for %s", json_string_value(json_object_get(j_result, "gus_username")));
            }
            json_decref(j_session);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_available_session_from_username - Error allocating resources for j_return");
          j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
        }
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_available_session_from_username - Error executing j_query");
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
    o_free(session_uid_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_available_session_from_username - Error generate_hash");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

int update_session(struct config_elements * config, const char * session_uid, const char * username, char * scheme_name, uint expiration) {
  json_t * j_query, * j_element, * j_session = get_session_for_username(config, session_uid, username), * j_last_id;
  int res, ret;
  size_t index;
  time_t now;
  char * expiration_clause;
  char * query = NULL;
  char * session_uid_hash = generate_hash(config, config->hash_algorithm, session_uid);
  
  time(&now);
  if (session_uid_hash != NULL) {
    if (check_result_value(j_session, G_OK)) {
      json_array_foreach(json_object_get(json_object_get(j_session, "session"), "scheme"), index, j_element) {
        if (0 == o_strcmp(json_string_value(json_object_get(j_element, "scheme_name")), scheme_name)) {
          j_query = json_pack("{sss{si}s{sssO}}",
                              "table",
                              GLEWLWYD_TABLE_USER_SESSION_SCHEME,
                              "set",
                                "guss_enabled",
                                0,
                              "where",
                                "guss_scheme_name",
                                scheme_name,
                                "gus_id",
                                json_object_get(json_object_get(j_session, "session"), "gus_id"));
          res = h_update(config->conn, j_query, &query);
          json_decref(j_query);
          if (res != H_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "update_session - Error executing j_query (1)");
          }
        }
      }
      expiration_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?msprintf("FROM_UNIXTIME(%u)", (now + expiration)):msprintf("%u", (now + expiration));
      j_query = json_pack("{sss{sOsss{ss}}}",
                          "table",
                          GLEWLWYD_TABLE_USER_SESSION_SCHEME,
                          "values",
                            "gus_id",
                            json_object_get(json_object_get(j_session, "session"), "gus_id"),
                            "guss_scheme_name",
                            scheme_name,
                            "guss_expiration",
                              "raw",
                              expiration_clause);
      o_free(expiration_clause);
      res = h_insert(config->conn, j_query, &query);
      json_decref(j_query);
      if (res == H_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "update_session - Error executing j_query (2)");
        ret = G_ERROR_DB;
      }
    } else {
      char * query;
      expiration_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?msprintf("FROM_UNIXTIME(%u)", (now + GLEWLWYD_DEFAULT_SESSION_EXPIRATION_COOKIE)):msprintf("%u", (now + expiration));
      j_query = json_pack("{sss{sssss{ss}}}",
                          "table",
                          GLEWLWYD_TABLE_USER_SESSION,
                          "values",
                            "gus_uuid",
                            session_uid_hash,
                            "gus_username",
                            username,
                            "gus_expiration",
                              "raw",
                              expiration_clause);
      o_free(expiration_clause);
      res = h_insert(config->conn, j_query, &query);
      
      json_decref(j_query);
      if (res == H_OK) {
        j_last_id = h_last_insert_id(config->conn);
        if (j_last_id != NULL) {
          expiration_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?msprintf("FROM_UNIXTIME(%u)", (now + expiration)):msprintf("%u", (now + expiration));
          j_query = json_pack("{sss{sIsss{ss}}}",
                              "table",
                              GLEWLWYD_TABLE_USER_SESSION_SCHEME,
                              "values",
                                "gus_id",
                                json_integer_value(j_last_id),
                                "guss_scheme_name",
                                scheme_name,
                                "guss_expiration",
                                  "raw",
                                  expiration_clause);
          o_free(expiration_clause);
          res = h_insert(config->conn, j_query, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            ret = G_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "update_session - Error executing j_query (3)");
            ret = G_ERROR_DB;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "update_session - Error h_last_insert_id");
          ret = G_ERROR_DB;
        }
        json_decref(j_last_id);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "update_session - Error executing j_query (4)");
        ret = G_ERROR_DB;
      }
    }
    o_free(session_uid_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "update_session - Error generate_hash");
    ret = G_ERROR;
  }
  return ret;
}

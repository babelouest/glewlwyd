/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * HTTP Session functions definition
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

json_t * get_session_scheme(struct config_elements * config, json_int_t gus_id) {
  json_t * j_query, * j_result, * j_return;
  int res;
  char * expire_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?o_strdup("> NOW()"):o_strdup("> (strftime('%s','now'))");
  
  j_query = json_pack("{sss[ss]s{sIsis{ssss}}}",
                      "table",
                      GLEWLWYD_TABLE_USER_SESSION_SCHEME,
                      "columns",
                        "guasmi_id",
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
          y_log_message(Y_LOG_LEVEL_ERROR, "get_session_for_username - Error get_session_scheme");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_session_scheme);
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_session_for_username - Error executing j_query");
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
    o_free(session_uid_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_session_for_username - Error generate_hash");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

json_t * get_users_for_session(struct config_elements * config, const char * session_uid) {
  json_t * j_query, * j_result, * j_return, * j_element, * j_user;
  int res;
  size_t index;
  char * expire_clause, * session_uid_hash;

  if (session_uid != NULL && o_strlen(session_uid)) {
    expire_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?o_strdup("> NOW()"):o_strdup("> (strftime('%s','now'))");
    session_uid_hash = generate_hash(config, config->hash_algorithm, session_uid);
    if (session_uid_hash != NULL) {
      j_query = json_pack("{sss[ss]s{sssis{ssss}}ss}",
                          "table",
                          GLEWLWYD_TABLE_USER_SESSION,
                          "columns",
                            "gus_username",
                            "gus_last_login",
                          "where",
                            "gus_uuid",
                            session_uid_hash,
                            "gus_enabled",
                            1,
                            "gus_expiration",
                              "operator",
                              "raw",
                              "value",
                              expire_clause,
                          "order_by",
                          "gus_current DESC");
      o_free(expire_clause);
      o_free(session_uid_hash);
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result) > 0) {
          j_return = json_pack("{sis[]}", "result", G_OK, "session");
          if (j_return != NULL) {
            json_array_foreach(j_result, index, j_element) {
              j_user = get_user(config, json_string_value(json_object_get(j_element, "gus_username")), NULL);
              if (check_result_value(j_user, G_OK)) {
                json_object_set(json_object_get(j_user, "user"), "last_login", json_object_get(j_element, "gus_last_login"));
                json_array_append(json_object_get(j_return, "session"), json_object_get(j_user, "user"));
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_users_for_session - Error get_user");
              }
              json_decref(j_user);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_users_for_session - Error allocating resources for j_return");
            j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
          }
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_session_for_username - Error executing j_query");
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_session_for_username - Error generate_hash");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

json_t * get_user_for_session(struct config_elements * config, const char * session_uid) {
  json_t * j_query, * j_result, * j_return;
  int res;
  char * expire_clause, * session_uid_hash;

  if (session_uid != NULL && o_strlen(session_uid)) {
    expire_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?o_strdup("> NOW()"):o_strdup("> (strftime('%s','now'))");
    session_uid_hash = generate_hash(config, config->hash_algorithm, session_uid);
    if (session_uid_hash != NULL) {
      j_query = json_pack("{sss[ss]s{sssis{ssss}si}sssi}",
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
                              expire_clause,
                            "gus_current",
                            1,
                          "order_by",
                          "gus_current DESC",
                          "limit",
                          1);
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result) > 0) {
          j_return = get_user(config, json_string_value(json_object_get(json_array_get(j_result, 0), "gus_username")), NULL);
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_session_for_username - Error executing j_query");
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else if (session_uid == NULL) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_session_for_username - Error generate_hash");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(session_uid_hash);
    o_free(expire_clause);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

int user_session_update(struct config_elements * config, const char * session_uid, const char * user_agent, const char * username, const char * scheme_type, const char * scheme_name) {
  json_t * j_query, * j_session = get_session_for_username(config, session_uid, username);
  struct _user_auth_scheme_module_instance * scheme_instance = NULL;
  int res, ret;
  time_t now;
  char * expiration_clause, * last_login_clause;
  char * session_uid_hash = generate_hash(config, config->hash_algorithm, session_uid);
  
  time(&now);
  if (session_uid_hash != NULL) {
    if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
      j_query = json_pack("{sss{si}s{ss}}",
                          "table",
                          GLEWLWYD_TABLE_USER_SESSION,
                          "set",
                            "gus_current",
                            0,
                          "where",
                            "gus_uuid",
                            session_uid_hash);
      res = h_update(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        // Create session for user if not exist
        expiration_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?msprintf("FROM_UNIXTIME(%u)", (now + GLEWLWYD_DEFAULT_SESSION_EXPIRATION_COOKIE)):msprintf("%u", (now + GLEWLWYD_DEFAULT_SESSION_EXPIRATION_COOKIE));
        last_login_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?msprintf("FROM_UNIXTIME(%u)", (now)):msprintf("%u", (now));
        j_query = json_pack("{sss{sssssss{ss}s{ss}si}}",
                            "table",
                            GLEWLWYD_TABLE_USER_SESSION,
                            "values",
                              "gus_uuid",
                              session_uid_hash,
                              "gus_username",
                              username,
                              "gus_user_agent",
                              user_agent!=NULL?user_agent:"",
                              "gus_expiration",
                                "raw",
                                expiration_clause,
                              "gus_last_login",
                                "raw",
                                last_login_clause,
                              "gus_current",
                              1);
        o_free(expiration_clause);
        o_free(last_login_clause);
        res = h_insert(config->conn, j_query, NULL);
        json_decref(j_query);
        json_decref(j_session);
        if (res == H_OK) {
          j_session = get_session_for_username(config, session_uid, username);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_session_update - Error h_insert session");
          j_session = json_pack("{si}", "result", G_ERROR_DB);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_session_update - Error h_update session (0)");
        j_session = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      j_query = json_pack("{sss{si}s{ss}}",
                          "table",
                          GLEWLWYD_TABLE_USER_SESSION,
                          "set",
                            "gus_current",
                            0,
                          "where",
                            "gus_uuid",
                            session_uid_hash);
      res = h_update(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        // Refresh session for user
        last_login_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?msprintf("FROM_UNIXTIME(%u)", (now)):msprintf("%u", (now));
        j_query = json_pack("{sss{s{ss}sssi}s{ssss}}",
                            "table",
                            GLEWLWYD_TABLE_USER_SESSION,
                            "set",
                              "gus_last_login",
                                "raw",
                                last_login_clause,
                              "gus_user_agent",
                              user_agent!=NULL?user_agent:"",
                              "gus_current",
                              1,
                            "where",
                              "gus_uuid",
                              session_uid_hash,
                              "gus_username",
                              username);
        o_free(last_login_clause);
        res = h_update(config->conn, j_query, NULL);
        json_decref(j_query);
        json_decref(j_session);
        if (res == H_OK) {
          j_session = get_session_for_username(config, session_uid, username);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_session_update - Error h_update session (2)");
          j_session = json_pack("{si}", "result", G_ERROR_DB);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_session_update - Error h_update session (1)");
        j_session = json_pack("{si}", "result", G_ERROR_DB);
      }
    }
    if (check_result_value(j_session, G_OK)) {
      if (scheme_name != NULL) {
        scheme_instance = get_user_auth_scheme_module_instance(config, scheme_name);
        if (scheme_instance != NULL && scheme_instance->enabled) {
          // Disable all session schemes with this scheme instance
          j_query = json_pack("{sss{si}s{sOsI}}",
                              "table",
                              GLEWLWYD_TABLE_USER_SESSION_SCHEME,
                              "set",
                                "guss_enabled",
                                0,
                              "where",
                                "gus_id",
                                json_object_get(json_object_get(j_session, "session"), "gus_id"),
                                "guasmi_id",
                                scheme_instance->guasmi_id);
          res = h_update(config->conn, j_query, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            // Set session scheme for this scheme with the timeout
            expiration_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)scheme_instance->guasmi_expiration)):msprintf("%u", (now + (unsigned int)scheme_instance->guasmi_expiration));
            last_login_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?msprintf("FROM_UNIXTIME(%u)", (now)):msprintf("%u", (now));
            j_query = json_pack("{sss{sOsIs{ss}s{ss}}}",
                                "table",
                                GLEWLWYD_TABLE_USER_SESSION_SCHEME,
                                "values",
                                  "gus_id",
                                  json_object_get(json_object_get(j_session, "session"), "gus_id"),
                                  "guasmi_id",
                                  scheme_instance->guasmi_id,
                                  "guss_expiration",
                                    "raw",
                                    expiration_clause,
                                  "guss_last_login",
                                    "raw",
                                    last_login_clause);
            o_free(expiration_clause);
            o_free(last_login_clause);
            res = h_insert(config->conn, j_query, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              ret = G_OK;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "user_session_update - Error executing j_query (1)");
              ret = G_ERROR_DB;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_session_update - Error executing j_query (2)");
            ret = G_ERROR_DB;
          }
        } else {
          ret = G_ERROR_PARAM;
        }
      } else {
        // Disable all session schemes with the scheme password
        j_query = json_pack("{sss{si}s{sOsn}}",
                            "table",
                            GLEWLWYD_TABLE_USER_SESSION_SCHEME,
                            "set",
                              "guss_enabled",
                              0,
                            "where",
                              "gus_id",
                              json_object_get(json_object_get(j_session, "session"), "gus_id"),
                              "guasmi_id");
        res = h_update(config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          // Set session scheme password with the timeout
          expiration_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?msprintf("FROM_UNIXTIME(%u)", (now + GLEWLWYD_RESET_PASSWORD_DEFAULT_SESSION_EXPIRATION)):msprintf("%u", (now + GLEWLWYD_RESET_PASSWORD_DEFAULT_SESSION_EXPIRATION));
          last_login_clause = config->conn->type==HOEL_DB_TYPE_MARIADB?msprintf("FROM_UNIXTIME(%u)", (now)):msprintf("%u", (now));
          j_query = json_pack("{sss{sOsns{ss}s{ss}}}",
                              "table",
                              GLEWLWYD_TABLE_USER_SESSION_SCHEME,
                              "values",
                                "gus_id",
                                json_object_get(json_object_get(j_session, "session"), "gus_id"),
                                "guasmi_id",
                                "guss_expiration",
                                  "raw",
                                  expiration_clause,
                                "guss_last_login",
                                  "raw",
                                  last_login_clause);
          o_free(expiration_clause);
          o_free(last_login_clause);
          res = h_insert(config->conn, j_query, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            ret = G_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_session_update - Error executing j_query (3)");
            ret = G_ERROR_DB;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_session_update - Error executing j_query (4)");
          ret = G_ERROR_DB;
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_session_update - Error get_session_for_username");
      ret = G_ERROR;
    }
    o_free(session_uid_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_session_update - Error generate_hash");
    ret = G_ERROR;
  }
  json_decref(j_session);
  return ret;
}

int user_session_delete(struct config_elements * config, const char * session_uid) {
  json_t * j_query;
  int res, ret;
  char * session_uid_hash = generate_hash(config, config->hash_algorithm, session_uid);

  if (session_uid_hash != NULL) {
    j_query = json_pack("{sss{sisi}s{ss}}",
                        "table",
                        GLEWLWYD_TABLE_USER_SESSION,
                        "set",
                          "gus_enabled",
                          0,
                          "gus_current",
                          0,
                        "where",
                          "gus_uuid",
                          session_uid_hash);
    o_free(session_uid_hash);
    res = h_update(config->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      ret = G_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_session_delete - Error executing j_query");
      ret = G_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_session_delete - Error generate_hash");
    ret = G_ERROR;
  }
  return ret;
}

char * get_session_id(struct config_elements * config, const struct _u_request * request) {
  return o_strdup(u_map_get(request->map_cookie, GLEWLWYD_DEFAULT_SESSION_KEY));
}

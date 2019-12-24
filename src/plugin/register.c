/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * register plugin
 * Allow unauthentified users to register a new account
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

#include <jansson.h>
#include "../glewlwyd-common.h"

#define GLEWLWYD_PLUGIN_REGSITER_DEFAULT_SESSION_DURATION 3600
#define GLEWLWYD_PLUGIN_REGSITER_DEFAULT_CODE_LENGTH 8
#define GLEWLWYD_PLUGIN_REGSITER_DEFAULT_CODE_DURATION 600
#define GLEWLWYD_PLUGIN_REGSITER_DEFAULT_CONTENT_TYPE "text/plain; charset=utf-8"
#define GLEWLWYD_DATE_BUFFER 128
#define GLEWLWYD_SESSION_ID_LENGTH 32

#define GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION "gpr_session"

struct _register_config {
  struct config_plugin * glewlwyd_config;
  pthread_mutex_t        insert_lock;
  char                 * name;
  json_t               * j_parameters;
};

static int can_register_scheme(struct _register_config * config, const char * scheme_name) {
  json_t * j_element = NULL;
  size_t index = 0;
  
  if (json_object_get(config->j_parameters, "schemes") != NULL) {
    json_array_foreach(json_object_get(config->j_parameters, "schemes"), index, j_element) {
      if (0 == o_strcmp(json_string_value(json_object_get(j_element, "name")), scheme_name)) {
        return 1;
      }
    }
  }
  return 0;
}

static json_t * register_generate_email_verification_code(struct _register_config * config, const char * username, const char * email, const char * issued_for, const char * user_agent, const char * ip_source) {
  char * code, * code_hash, * expires_at_clause, * body;
  json_t * j_return, * j_query;
  int res;
  size_t code_len;
  time_t now;
  
  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error pthread_mutex_lock");
    j_return = json_pack("{si}", "result", G_ERROR);
  } else {
    // Disable existing sessions for the specified e-mail address
    time(&now);
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
    } else { // HOEL_DB_TYPE_SQLITE
      expires_at_clause = msprintf("> %u", (now));
    }
    j_query = json_pack("{sss{si}s{sssss{ssss}si}}",
                        "table",
                        GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                        "set",
                          "gprs_enabled",
                          0,
                        "where",
                          "gprs_plugin_name",
                          config->name,
                          "gprs_email",
                          email,
                          "gprs_expires_at",
                            "operator",
                            "raw",
                            "value",
                            expires_at_clause,
                          "gprs_enabled",
                          1);
    o_free(expires_at_clause);
    res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      code_len = json_integer_value(json_object_get(config->j_parameters, "verification-code-length"));
      if ((code = o_malloc((code_len+1)*sizeof(char))) != NULL) {
        if (rand_code(code, code_len)) {
          if ((code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code)) != NULL) {
            if ((body = str_replace(json_string_value(json_object_get(config->j_parameters, "body-pattern")), "{CODE}", code)) != NULL) {
              if (ulfius_send_smtp_email(json_string_value(json_object_get(config->j_parameters, "host")),
                                         json_integer_value(json_object_get(config->j_parameters, "port")),
                                         json_object_get(config->j_parameters, "use-tls")==json_true()?1:0,
                                         json_object_get(config->j_parameters, "verify-certificate")==json_false()?0:1,
                                         json_string_length(json_object_get(config->j_parameters, "user"))?json_string_value(json_object_get(config->j_parameters, "user")):NULL,
                                         json_string_length(json_object_get(config->j_parameters, "password"))?json_string_value(json_object_get(config->j_parameters, "password")):NULL,
                                         json_string_value(json_object_get(config->j_parameters, "from")),
                                         email,
                                         NULL,
                                         NULL,
                                         json_string_value(json_object_get(config->j_parameters, "subject")),
                                         body) == G_OK) {
                y_log_message(Y_LOG_LEVEL_WARNING, "Security - register new user - code sent for email %s at IP Address %s", email, ip_source);
                if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
                  expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "verification-code-duration"))));
                } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
                  expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "verification-code-duration"))));
                } else { // HOEL_DB_TYPE_SQLITE
                  expires_at_clause = msprintf("%u", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "verification-code-duration"))));
                }
                j_query = json_pack("{sss{sssssssss{ss}ssss}}",
                                    "table",
                                    GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                                    "values",
                                      "gprs_plugin_name",
                                      config->name,
                                      "gprs_username",
                                      username,
                                      "gprs_email",
                                      email,
                                      "gprs_code_hash",
                                      code_hash,
                                      "gprs_expires_at",
                                        "raw",
                                        expires_at_clause,
                                      "gprs_issued_for",
                                      issued_for,
                                      "gprs_user_agent",
                                      user_agent!=NULL?user_agent:"");
                o_free(expires_at_clause);
                res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
                json_decref(j_query);
                if (res == H_OK) {
                  j_return = json_pack("{siss}", "result", G_OK, "code", code);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error executing j_query");
                  j_return = json_pack("{si}", "result", G_ERROR_DB);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error ulfius_send_smtp_email");
                j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
              }
              o_free(body);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error str_replace");
              j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
            }
            o_free(code_hash);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error rand_code");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error rand_code");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        o_free(code);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error allocating resources for code");
        j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error executing j_query");
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
    pthread_mutex_unlock(&config->insert_lock);
  }
  return j_return;
}

static json_t * register_verify_email_code(struct _register_config * config, const char * username, const char * email, const char * code, const char * ip_source) {
  json_t * j_query, * j_result = NULL, * j_return, * j_new_user;
  int res;
  char * code_hash = NULL, * expires_at_clause = NULL, session[GLEWLWYD_SESSION_ID_LENGTH+1] = {}, * session_hash = NULL;
  time_t now;
  
  if ((code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code)) != NULL) {
    time(&now);
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
    } else { // HOEL_DB_TYPE_SQLITE
      expires_at_clause = msprintf("> %u", (now));
    }
    j_query = json_pack("{sss[s]s{sssssssss{ssss}si}}",
                        "table",
                        GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                        "columns",
                          "gprs_id",
                        "where",
                          "gprs_plugin_name",
                          config->name,
                          "gprs_code_hash",
                          code_hash,
                          "gprs_username",
                          username,
                          "gprs_email",
                          email,
                          "gprs_expires_at",
                            "operator",
                            "raw",
                            "value",
                            expires_at_clause,
                          "gprs_enabled",
                          1);
    o_free(expires_at_clause);
    res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        j_new_user = json_pack("{sssssosO}", "username", username, "email", email, "enabled", json_false(), "scope", json_object_get(config->j_parameters, "scope"));
        if (config->glewlwyd_config->glewlwyd_plugin_callback_add_user(config->glewlwyd_config, j_new_user) == G_OK) {
          if (rand_string_nonce(session, GLEWLWYD_SESSION_ID_LENGTH) != NULL) {
            if ((session_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, session)) != NULL) {
              time(&now);
              if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
                expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "session-duration"))));
              } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
                expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "session-duration"))));
              } else { // HOEL_DB_TYPE_SQLITE
                expires_at_clause = msprintf("%u", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "session-duration"))));
              }
              j_query = json_pack("{sss{sss{ss}}s{sssO}}",
                                  "table",
                                  GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                                  "set",
                                    "gprs_session_hash",
                                    session_hash,
                                    "gprs_expires_at",
                                      "raw",
                                      expires_at_clause,
                                  "where",
                                    "gprs_plugin_name",
                                    config->name,
                                    "gprs_id",
                                    json_object_get(json_array_get(j_result, 0), "gprs_id"));
              o_free(expires_at_clause);
              res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
              json_decref(j_query);
              if (res == H_OK) {
                j_return = json_pack("{siss}", "result", G_OK, "session", session);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "register_verify_email_code - Error executing j_query");
                j_return = json_pack("{si}", "result", G_ERROR_DB);
              }
              o_free(session_hash);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "register_verify_email_code - Error glewlwyd_callback_generate_hash");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "register_verify_email_code - Error rand_string_nonce");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_verify_email_code - Error glewlwyd_plugin_callback_add_user");
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        json_decref(j_new_user);
      } else {
        y_log_message(Y_LOG_LEVEL_WARNING, "Security - verify e-mail code - code invalid for email %s at IP Address %s", email, ip_source);
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_verify_email_code - Error executing j_query");
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "register_verify_email_code - Error generate hash for session");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  o_free(code_hash);
  return j_return;
}

static json_t * register_check_session(struct _register_config * config, const char * session) {
  json_t * j_query, * j_result = NULL, * j_return;
  int res;
  char * session_hash = NULL, * expires_at_clause = NULL;
  time_t now;
  
  if (o_strlen(session)) {
    session_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, session);
    if (session_hash != NULL) {
      time(&now);
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
      } else { // HOEL_DB_TYPE_SQLITE
        expires_at_clause = msprintf("> %u", (now));
      }
      j_query = json_pack("{sss[ssss]s{sssss{ssss}si}}",
                          "table",
                          GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                          "columns",
                            "gprs_username AS username",
                            "gprs_name AS name",
                            "gprs_email AS email",
                            "gprs_password_set",
                          "where",
                            "gprs_plugin_name",
                            config->name,
                            "gprs_session_hash",
                            session_hash,
                            "gprs_expires_at",
                              "operator",
                              "raw",
                              "value",
                              expires_at_clause,
                            "gprs_enabled",
                            1);
      o_free(expires_at_clause);
      res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gprs_password_set"))) {
            json_object_set(json_array_get(j_result, 0), "password_set", json_true());
          } else {
            json_object_set(json_array_get(j_result, 0), "password_set", json_false());
          }
          json_object_del(json_array_get(j_result, 0), "gprs_password_set");
          j_return = json_pack("{sisO}", "result", G_OK, "user", json_array_get(j_result, 0));
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "register_check_session - Error executing j_query");
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_check_session - Error generate hash for session");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(session_hash);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

static json_t * register_check_username(struct _register_config * config, const char * username) {
  json_t * j_query, * j_result = NULL, * j_return;
  int res;
  char * expires_at_clause = NULL;
  time_t now;
  
  if (o_strlen(username)) {
    time(&now);
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
    } else { // HOEL_DB_TYPE_SQLITE
      expires_at_clause = msprintf("> %u", (now));
    }
    j_query = json_pack("{sss[s]s{sssss{ssss}si}}",
                        "table",
                        GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                        "columns",
                          "gprs_username",
                        "where",
                          "gprs_plugin_name",
                          config->name,
                          "gprs_username",
                          username,
                          "gprs_expires_at",
                            "operator",
                            "raw",
                            "value",
                            expires_at_clause,
                          "gprs_enabled",
                          1);
    o_free(expires_at_clause);
    res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        j_return = json_pack("{si}", "result", G_OK);
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_check_username - Error executing j_query");
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

static json_t * register_new_user(struct _register_config * config, const char * username, const char * issued_for, const char * user_agent) {
  json_t * j_query, * j_return, * j_user, * j_new_user;
  int res;
  char * expires_at_clause, session[GLEWLWYD_SESSION_ID_LENGTH+1] = {}, * session_hash = NULL;
  time_t now;
  
  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "register_new_user - Error pthread_mutex_lock");
    j_return = json_pack("{si}", "result", G_ERROR);
  } else {
    j_user = register_check_username(config, username);
    if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
      j_new_user = json_pack("{sssosO}", "username", username, "enabled", json_false(), "scope", json_object_get(config->j_parameters, "scope"));
      if (config->glewlwyd_config->glewlwyd_plugin_callback_add_user(config->glewlwyd_config, j_new_user) == G_OK) {
        if (rand_string_nonce(session, GLEWLWYD_SESSION_ID_LENGTH) != NULL) {
          if ((session_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, session)) != NULL) {
            time(&now);
            if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
              expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "session-duration"))));
            } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
              expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "session-duration"))));
            } else { // HOEL_DB_TYPE_SQLITE
              expires_at_clause = msprintf("%u", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "session-duration"))));
            }
            j_query = json_pack("{sss{sssssss{ss}ssss}}",
                                "table",
                                GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                                "values",
                                  "gprs_plugin_name",
                                  config->name,
                                  "gprs_username",
                                  username,
                                  "gprs_session_hash",
                                  session_hash,
                                  "gprs_expires_at",
                                    "raw",
                                    expires_at_clause,
                                  "gprs_issued_for",
                                  issued_for,
                                  "gprs_user_agent",
                                  user_agent!=NULL?user_agent:"");
            o_free(expires_at_clause);
            res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              j_return = json_pack("{siss}", "result", G_OK, "session", session);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "register_new_user - Error executing j_query");
              j_return = json_pack("{si}", "result", G_ERROR_DB);
            }
            o_free(session_hash);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "register_new_user - Error glewlwyd_callback_generate_hash");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_new_user - Error rand_string_nonce");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "register_new_user - Error glewlwyd_plugin_callback_add_user");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_new_user);
    } else if (check_result_value(j_user, G_OK) || check_result_value(j_user, G_ERROR_PARAM)) {
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_new_user - Error register_check_username");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_user);
    pthread_mutex_unlock(&config->insert_lock);
  }
  return j_return;
}

static int register_user_set(struct _register_config * config, const char * username, json_t * j_user) {
  json_t * j_query;
  int res, ret;
  char * expires_at_clause = NULL;
  time_t now;
  
  time(&now);
  if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
    expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
  } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
    expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
  } else { // HOEL_DB_TYPE_SQLITE
    expires_at_clause = msprintf("> %u", (now));
  }
  j_query = json_pack("{sss{sO}s{sssss{ssss}si}}",
                      "table",
                      GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                      "set",
                        "gprs_name",
                        json_object_get(j_user, "name"),
                      "where",
                        "gprs_plugin_name",
                        config->name,
                        "gprs_username",
                        username,
                        "gprs_expires_at",
                          "operator",
                          "raw",
                          "value",
                          expires_at_clause,
                        "gprs_enabled",
                        1);
  o_free(expires_at_clause);
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "register_user_set - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static int register_user_password_set(struct _register_config * config, const char * username) {
  json_t * j_query;
  int res, ret;
  char * expires_at_clause = NULL;
  time_t now;
  
  time(&now);
  if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
    expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
  } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
    expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
  } else { // HOEL_DB_TYPE_SQLITE
    expires_at_clause = msprintf("> %u", (now));
  }
  j_query = json_pack("{sss{si}s{sssss{ssss}si}}",
                      "table",
                      GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                      "set",
                        "gprs_password_set",
                        1,
                      "where",
                        "gprs_plugin_name",
                        config->name,
                        "gprs_username",
                        username,
                        "gprs_expires_at",
                          "operator",
                          "raw",
                          "value",
                          expires_at_clause,
                        "gprs_enabled",
                        1);
  o_free(expires_at_clause);
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "register_user_password_set - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static int register_user_complete(struct _register_config * config, const char * username) {
  json_t * j_query;
  int res, ret;
  char * expires_at_clause = NULL;
  time_t now;
  
  time(&now);
  if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
    expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
  } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
    expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
  } else { // HOEL_DB_TYPE_SQLITE
    expires_at_clause = msprintf("> %u", (now));
  }
  j_query = json_pack("{sss{si}s{sssss{ssss}si}}",
                      "table",
                      GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                      "set",
                        "gprs_enabled",
                        0,
                      "where",
                        "gprs_plugin_name",
                        config->name,
                        "gprs_username",
                        username,
                        "gprs_expires_at",
                          "operator",
                          "raw",
                          "value",
                          expires_at_clause,
                        "gprs_enabled",
                        1);
  o_free(expires_at_clause);
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "register_user_complete - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static int register_delete_new_user(struct _register_config * config, const char * username) {
  json_t * j_element = NULL;
  size_t index = 0;
  int ret = G_OK;

  if (register_user_complete(config, username) == G_OK) {
    if (config->glewlwyd_config->glewlwyd_plugin_callback_delete_user(config->glewlwyd_config, username) == G_OK) {
      if (json_object_get(config->j_parameters, "schemes") != NULL) {
        json_array_foreach(json_object_get(config->j_parameters, "schemes"), index, j_element) {
          if (config->glewlwyd_config->glewlwyd_plugin_callback_scheme_deregister(config->glewlwyd_config, json_string_value(json_object_get(j_element, "name")), username) != G_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "register_delete_new_user - Error glewlwyd_plugin_callback_scheme_deregister for user %s on scheme %s/%s", username, json_string_value(json_object_get(j_element, "module")), json_string_value(json_object_get(j_element, "name")));
            ret = G_ERROR;
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_delete_new_user - Error glewlwyd_plugin_callback_delete_user");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "register_delete_new_user - Error register_user_complete");
    ret = G_ERROR;
  }
  return ret;
}

static int callback_register_config(const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  struct _register_config * config = (struct _register_config *)user_data; 
  json_t * j_config = json_pack("{sOsOsOsO}", "set-password", json_object_get(config->j_parameters, "set-password"), 
                                              "schemes", json_object_get(config->j_parameters, "schemes")!=NULL?json_object_get(config->j_parameters, "schemes"):json_null(),
                                              "verify-email", json_object_get(config->j_parameters, "verify-email")!=NULL?json_object_get(config->j_parameters, "verify-email"):json_false(),
                                              "email-is-username", json_object_get(config->j_parameters, "email-is-username")!=NULL?json_object_get(config->j_parameters, "email-is-username"):json_false());
  if (ulfius_set_json_body_response(response, 200, j_config) != U_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_config - Error ulfius_set_json_body_response");
    response->status = 500;
  }
  json_decref(j_config);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_verify_session(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  int ret = U_CALLBACK_CONTINUE;
  
  json_t * j_session = register_check_session(config, u_map_get(request->map_cookie, json_string_value(json_object_get(config->j_parameters, "session-key"))));
  if (check_result_value(j_session, G_OK)) {
    response->shared_data = json_incref(json_object_get(j_session, "user"));
  } else if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
    ret = U_CALLBACK_UNAUTHORIZED;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_verify_session - Error register_check_session");
    ret = U_CALLBACK_ERROR;
  }
  json_decref(j_session);
  return ret;
}

static int callback_register_get_data(const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  UNUSED(user_data);
  if (ulfius_set_json_body_response(response, 200, (json_t *)response->shared_data) != U_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_get_data - Error ulfius_set_json_body_response");
    response->status = 500;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_register_check_username(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_params = ulfius_get_json_body_request(request, NULL), * j_user, * j_user_reg, * j_return;

  if (j_params != NULL && json_string_length(json_object_get(j_params, "username"))) {
    j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, json_string_value(json_object_get(j_params, "username")));
    if (check_result_value(j_user, G_OK)) {
      j_return = json_pack("{ss}", "error", "username already taken");
      ulfius_set_json_body_response(response, 400, j_return);
      json_decref(j_return);
    } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
      j_user_reg = register_check_username(config, json_string_value(json_object_get(j_params, "username")));
      if (check_result_value(j_user_reg, G_OK)) {
        j_return = json_pack("{ss}", "error", "username already taken");
        ulfius_set_json_body_response(response, 400, j_return);
        json_decref(j_return);
      } else if (!check_result_value(j_user_reg, G_ERROR_NOT_FOUND)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_check_username - Error register_check_username");
        response->status = 500;
      }
      json_decref(j_user_reg);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_check_username - Error glewlwyd_plugin_callback_get_user");
      response->status = 500;
    }
    json_decref(j_user);
  } else {
    j_return = json_pack("{ss}", "result", "username invalid");
    ulfius_set_json_body_response(response, 400, j_return);
    json_decref(j_return);
  }
  json_decref(j_params);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_register_user(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_result, * j_parameters = ulfius_get_json_body_request(request, NULL);
  char * issued_for, expires[GLEWLWYD_DATE_BUFFER+1];
  time_t now;
  struct tm ts;
  
  time(&now);
  now += json_integer_value(json_object_get(config->j_parameters, "session-duration"));
  ts = *gmtime(&now);
  strftime(expires, GLEWLWYD_DATE_BUFFER, "%a, %d %b %Y %T %Z", &ts);
  
  if (json_object_get(config->j_parameters, "verify-email") != json_true()) {
    if (json_string_length(json_object_get(j_parameters, "username"))) {
      issued_for = get_client_hostname(request);
      if (issued_for != NULL) {
        j_result = register_new_user(config, json_string_value(json_object_get(j_parameters, "username")), issued_for, u_map_get_case(request->map_header, "user-agent"));
        if (check_result_value(j_result, G_OK)) {
          ulfius_add_cookie_to_response(response, json_string_value(json_object_get(config->j_parameters, "session-key")), json_string_value(json_object_get(j_result, "session")), expires, 0, config->glewlwyd_config->glewlwyd_config->cookie_domain, "/", config->glewlwyd_config->glewlwyd_config->cookie_secure, 0);
        } else if (check_result_value(j_result, G_ERROR_PARAM)) {
          response->status = 400;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_register_user - Error register_new_user");
          response->status = 500;
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_register_user - Error get_client_hostname");
        response->status = 500;
      }
      o_free(issued_for);
    } else {
      response->status = 400;
    }
  } else {
    response->status = 403;
  }
  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_send_email_verification(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_result, * j_parameters = ulfius_get_json_body_request(request, NULL);
  const char * username, * email;
  char * issued_for;
  
  if (json_object_get(config->j_parameters, "verify-email") == json_true()) {
    email = json_string_value(json_object_get(j_parameters, "email"));
    if (json_object_get(config->j_parameters, "email-is-username") == json_true()) {
      username = json_string_value(json_object_get(j_parameters, "email"));
    } else {
      username = json_string_value(json_object_get(j_parameters, "username"));
    }
    if (o_strlen(email) && o_strlen(username)) {
      issued_for = get_client_hostname(request);
      if (issued_for != NULL) {
        j_result = register_generate_email_verification_code(config, username, email, issued_for, u_map_get_case(request->map_header, "user-agent"), get_ip_source(request));
        if (check_result_value(j_result, G_ERROR_PARAM)) {
          response->status = 400;
        } else if(!check_result_value(j_result, G_OK)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_register_user - Error register_new_user");
          response->status = 500;
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_register_user - Error get_client_hostname");
        response->status = 500;
      }
      o_free(issued_for);
    } else {
      response->status = 400;
    }
  } else {
    response->status = 403;
  }
  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_verify_email(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL), * j_result;
  const char * username, * email;
  char expires[GLEWLWYD_DATE_BUFFER+1];
  time_t now;
  struct tm ts;

  if (json_object_get(config->j_parameters, "verify-email") == json_true()) {
    email = json_string_value(json_object_get(j_parameters, "email"));
    if (json_object_get(config->j_parameters, "email-is-username") == json_true()) {
      username = json_string_value(json_object_get(j_parameters, "email"));
    } else {
      username = json_string_value(json_object_get(j_parameters, "username"));
    }
    if (o_strlen(email) && o_strlen(username) && (json_int_t)json_string_length(json_object_get(j_parameters, "code")) == json_integer_value(json_object_get(config->j_parameters, "verification-code-length"))) {
      j_result = register_verify_email_code(config,
                                             username,
                                             email,
                                             json_string_value(json_object_get(j_parameters, "code")),
                                             get_ip_source(request));
      if (check_result_value(j_result, G_OK)) {
        time(&now);
        now += json_integer_value(json_object_get(config->j_parameters, "session-duration"));
        ts = *gmtime(&now);
        strftime(expires, GLEWLWYD_DATE_BUFFER, "%a, %d %b %Y %T %Z", &ts);
        ulfius_add_cookie_to_response(response, 
                                      json_string_value(json_object_get(config->j_parameters, "session-key")),
                                      json_string_value(json_object_get(j_result, "session")),
                                      expires,
                                      0,
                                      config->glewlwyd_config->glewlwyd_config->cookie_domain,
                                      "/",
                                      config->glewlwyd_config->glewlwyd_config->cookie_secure,
                                      0);
      } else if (check_result_value(j_result, G_ERROR_PARAM)) {
        response->status = 401;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_verify_email - Error register_verify_email_code");
        response->status = 500;
      }
      json_decref(j_result);
    } else {
      response->status = 401;
    }
  } else {
    response->status = 403;
  }

  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_update_password(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL);
  
  if (0 != o_strcmp("no", json_string_value(json_object_get(config->j_parameters, "set-password")))) {
    if (json_string_length(json_object_get(j_parameters, "password"))) {
      if (config->glewlwyd_config->glewlwyd_plugin_callback_user_update_password(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), json_string_value(json_object_get(j_parameters, "password"))) == G_OK) {
        if (register_user_password_set(config, json_string_value(json_object_get((json_t *)response->shared_data, "username"))) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_update_password - Error register_user_password_set");
          response->status = 500;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_update_password - Error glewlwyd_plugin_callback_user_update_password");
        response->status = 500;
      }
    } else {
      response->status = 400;
    }
  } else {
    response->status = 400;
  }
  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_update_data(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL), * j_user;
  
  if (json_is_string(json_object_get(j_parameters, "name")) || json_object_get(j_parameters, "name") == json_null()) {
    j_user = json_pack("{ss}", "name", json_is_string(json_object_get(j_parameters, "name"))?json_string_value(json_object_get(j_parameters, "name")):"");
    if (config->glewlwyd_config->glewlwyd_plugin_callback_set_user(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), j_user) == G_OK) {
      if (register_user_set(config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), j_user) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_update_data - Error register_user_set");
        response->status = 500;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_update_data - Error glewlwyd_plugin_callback_set_user");
      response->status = 500;
    }
    json_decref(j_user);
  } else {
    response->status = 400;
  }
  
  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_cancel(const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  struct _register_config * config = (struct _register_config *)user_data;
  
  if (register_delete_new_user(config, json_string_value(json_object_get((json_t *)response->shared_data, "username"))) != G_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_cancel - Error register_delete_new_user");
    response->status = 500;
  } else {
    ulfius_add_cookie_to_response(response, json_string_value(json_object_get(config->j_parameters, "session-key")), "", 0, 0, config->glewlwyd_config->glewlwyd_config->cookie_domain, "/", config->glewlwyd_config->glewlwyd_config->cookie_secure, 0);
  }
  
  return U_CALLBACK_CONTINUE;
}

static int callback_register_get_scheme_registration(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL), * j_response;
  
  if (json_string_length(json_object_get(j_parameters, "scheme_name")) && json_string_length(json_object_get(j_parameters, "username")) && 0 == o_strcmp(json_string_value(json_object_get(j_parameters, "username")), json_string_value(json_object_get((json_t *)response->shared_data, "username"))) && can_register_scheme(config, json_string_value(json_object_get(j_parameters, "scheme_name")))) {
    j_response = config->glewlwyd_config->glewlwyd_plugin_callback_scheme_register_get(config->glewlwyd_config, json_string_value(json_object_get(j_parameters, "scheme_name")), request, json_string_value(json_object_get((json_t *)response->shared_data, "username")));
    if (check_result_value(j_response, G_OK)) {
      if (json_object_get(j_response, "response") != NULL) {
        ulfius_set_json_body_response(response, 200, json_object_get(j_response, "response"));
      } else {
        response->status = 200;
      }
    } else if (check_result_value(j_response, G_ERROR_PARAM)) {
      response->status = 400;
    } else if (check_result_value(j_response, G_ERROR_UNAUTHORIZED)) {
      response->status = 401;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_get_scheme_registration - Error glewlwyd_plugin_callback_scheme_register_get");
      response->status = 500;
    }
    json_decref(j_response);
  } else {
    response->status = 400;
  }
  
  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_update_scheme_registration(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL), * j_response;
  
  if (json_string_length(json_object_get(j_parameters, "scheme_name")) && json_is_object(json_object_get(j_parameters, "value")) && json_string_length(json_object_get(j_parameters, "username")) && 0 == o_strcmp(json_string_value(json_object_get(j_parameters, "username")), json_string_value(json_object_get((json_t *)response->shared_data, "username"))) && can_register_scheme(config, json_string_value(json_object_get(j_parameters, "scheme_name")))) {
    j_response = config->glewlwyd_config->glewlwyd_plugin_callback_scheme_register(config->glewlwyd_config, json_string_value(json_object_get(j_parameters, "scheme_name")), request, json_string_value(json_object_get((json_t *)response->shared_data, "username")), json_object_get(j_parameters, "value"));
    if (check_result_value(j_response, G_ERROR_PARAM)) {
      if (json_object_get(j_response, "response") != NULL) {
        ulfius_set_json_body_response(response, 400, json_object_get(j_response, "response"));
      } else {
        ulfius_set_string_body_response(response, 400, "bad scheme response");
      }
    } else if (check_result_value(j_response, G_ERROR_NOT_FOUND)) {
      response->status = 404;
    } else if (check_result_value(j_response, G_ERROR_UNAUTHORIZED)) {
      response->status = 401;
    } else if (check_result_value(j_response, G_OK)) {
      if (json_object_get(j_response, "response") != NULL) {
        ulfius_set_json_body_response(response, 200, json_object_get(j_response, "response"));
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_auth_register - Error auth_check_user_scheme");
      response->status = 500;
    }
    json_decref(j_response);
  } else {
    response->status = 400;
  }
  
  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_canuse_scheme_registration(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL);
  int ret;
  
  if (json_string_length(json_object_get(j_parameters, "scheme_name")) && json_string_length(json_object_get(j_parameters, "username")) && 0 == o_strcmp(json_string_value(json_object_get(j_parameters, "username")), json_string_value(json_object_get((json_t *)response->shared_data, "username"))) && can_register_scheme(config, json_string_value(json_object_get(j_parameters, "scheme_name")))) {
    ret = config->glewlwyd_config->glewlwyd_plugin_callback_scheme_can_use(config->glewlwyd_config, json_string_value(json_object_get(j_parameters, "scheme_name")), json_string_value(json_object_get((json_t *)response->shared_data, "username")));
    if (ret == GLEWLWYD_IS_NOT_AVAILABLE) {
      response->status = 403;
    } else if (ret == GLEWLWYD_IS_AVAILABLE) {
      response->status = 401;
    } else if (ret != GLEWLWYD_IS_REGISTERED) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_canuse_scheme_registration - Error glewlwyd_plugin_callback_scheme_can_use");
      response->status = 500;
    }
  } else {
    response->status = 400;
  }
  
  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_complete_registration(const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_user, * j_element = NULL, * j_error = json_array();
  size_t index = 0;
  char * message;
  
  if (j_error != NULL) {
    // Does the user need to set password?
    if (0 == o_strcmp("always", json_string_value(json_object_get(config->j_parameters, "set-password")))) {
      if (json_object_get((json_t *)response->shared_data, "password_set") != json_true()) {
        json_array_append_new(j_error, json_string("Password not set"));
      }
    }
    
    // Has the user registered all its required schemes?
    json_array_foreach(json_object_get(config->j_parameters, "schemes"), index, j_element) {
      if (0 == o_strcmp("always", json_string_value(json_object_get(j_element, "register")))) {
        if (config->glewlwyd_config->glewlwyd_plugin_callback_scheme_can_use(config->glewlwyd_config, json_string_value(json_object_get(j_element, "name")), json_string_value(json_object_get((json_t *)response->shared_data, "username"))) != GLEWLWYD_IS_REGISTERED) {
          message = msprintf("Scheme '%s' not registered", json_string_value(json_object_get(j_element, "name")));
          json_array_append_new(j_error, json_string(message));
          o_free(message);
        }
      }
    }
    
    if (!json_array_size(j_error)) {
      j_user = json_pack("{so}", "enabled", json_true());
      if (config->glewlwyd_config->glewlwyd_plugin_callback_set_user(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), j_user) == G_OK) {
        if (register_user_complete(config, json_string_value(json_object_get((json_t *)response->shared_data, "username"))) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_complete_registration - Error register_user_complete");
          response->status = 500;
        } else {
          ulfius_add_cookie_to_response(response, json_string_value(json_object_get(config->j_parameters, "session-key")), "", 0, 0, config->glewlwyd_config->glewlwyd_config->cookie_domain, "/", config->glewlwyd_config->glewlwyd_config->cookie_secure, 0);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_complete_registration - Error glewlwyd_plugin_callback_set_user");
        response->status = 500;
      }
      json_decref(j_user);
    } else {
      ulfius_set_json_body_response(response, 400, j_error);
    }
    json_decref(j_error);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_complete_registration - Error allocating resources for j_error");
    response->status = 500;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_register_clean_session(const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(user_data);
  json_decref((json_t *)response->shared_data);
  if (request->callback_position == 1) {
    response->status = 404;
  }
  return U_CALLBACK_COMPLETE;
}

json_t * is_plugin_parameters_valid(json_t * j_params) {
  json_t * j_return, * j_errors = json_array(), * j_element = NULL;
  size_t index = 0, has_mandatory = 0;

  if (j_errors != NULL) {
    if (!json_is_object(j_params)) {
      json_array_append_new(j_errors, json_string("parameters must be a JSON object"));
    } else {
      if (!json_string_length(json_object_get(j_params, "session-key"))) {
        json_array_append_new(j_errors, json_string("session-key is mandatory and must be a non empty string"));
      }
      if (json_integer_value(json_object_get(j_params, "session-duration")) <= 0) {
        json_array_append_new(j_errors, json_string("session-duration is optional and must be a positive integer"));
      }
      if (json_object_get(j_params, "verify-email") != NULL && !json_is_boolean(json_object_get(j_params, "verify-email"))) {
        json_array_append_new(j_errors, json_string("verify-email is optional and must be boolean"));
      }
      if (json_object_get(j_params, "email-is-username") != NULL && !json_is_boolean(json_object_get(j_params, "email-is-username"))) {
        json_array_append_new(j_errors, json_string("email-is-username is optional and must be boolean"));
      }
      if (0 != o_strcmp(json_string_value(json_object_get(j_params, "set-password")), "always") && 0 != o_strcmp(json_string_value(json_object_get(j_params, "set-password")), "yes") && 0 != o_strcmp(json_string_value(json_object_get(j_params, "set-password")), "no")) {
        json_array_append_new(j_errors, json_string("set-password is mandatory and must have one of the following string values: 'always', 'yes', 'no'"));
      } else if (0 == o_strcmp(json_string_value(json_object_get(j_params, "set-password")), "always")) {
        has_mandatory = 1;
      }
      if (!json_is_array(json_object_get(j_params, "scope")) || !json_array_size(json_object_get(j_params, "scope"))) {
        json_array_append_new(j_errors, json_string("scope is mandatory and must be a non empty array of non empty strings"));
      } else {
        json_array_foreach(json_object_get(j_params, "scope"), index, j_element) {
          if (!json_string_length(j_element)) {
            json_array_append_new(j_errors, json_string("scope is mandatory and must be a non empty array of non empty strings"));
          }
        }
      }
      if (json_object_get(j_params, "schemes") != NULL && !json_is_array(json_object_get(j_params, "schemes"))) {
        json_array_append_new(j_errors, json_string("schemes is optional and must be an array of objects"));
      } else {
        json_array_foreach(json_object_get(j_params, "schemes"), index, j_element) {
          if (!json_string_length(json_object_get(j_element, "module"))) {
            json_array_append_new(j_errors, json_string("scheme object must have a attribute 'module' with a non empty string value"));
          }
          if (!json_string_length(json_object_get(j_element, "name"))) {
            json_array_append_new(j_errors, json_string("scheme object must have a attribute 'name' with a non empty string value"));
          }
          if (0 != o_strcmp("always", json_string_value(json_object_get(j_element, "register"))) && 0 != o_strcmp("yes", json_string_value(json_object_get(j_element, "register")))) {
            json_array_append_new(j_errors, json_string("scheme object must have a attribute 'register' with one of the following values: 'yes', 'always'"));
          }
          if (0 == o_strcmp("always", json_string_value(json_object_get(j_element, "register")))) {
            has_mandatory = 1;
          }
        }
      }
      if (!has_mandatory) {
        json_array_append_new(j_errors, json_string("At least one authentication method must be mandatory"));
      }
      if (json_object_get(j_params, "verify-email") == json_true()) {
        if (json_integer_value(json_object_get(j_params, "verification-code-duration")) <= 0) {
          json_array_append_new(j_errors, json_string("verification-code-duration is optional and must be a positive integer"));
        }
        if (json_integer_value(json_object_get(j_params, "verification-code-length")) <= 0) {
          json_array_append_new(j_errors, json_string("verification-code-length is optional and must be a positive integer"));
        }
        if (!json_is_boolean(json_object_get(j_params, "email-is-username"))) {
          json_array_append_new(j_errors, json_string("email-is-username is optional and must be boolean"));
        }
        if (!json_string_length(json_object_get(j_params, "host"))) {
          json_array_append_new(j_errors, json_string("host is mandatory and must be a non empty string"));
        }
        if (json_object_get(j_params, "port") != NULL && (!json_is_integer(json_object_get(j_params, "port")) || json_integer_value(json_object_get(j_params, "port")) < 0 || json_integer_value(json_object_get(j_params, "port")) > 65535)) {
          json_array_append_new(j_errors, json_string("port is optional and must be a integer between 0 and 65535"));
        } else if (json_object_get(j_params, "port") == NULL) {
          json_object_set_new(j_params, "port", json_integer(0));
        }
        if (json_object_get(j_params, "use-tls") != NULL && !json_is_boolean(json_object_get(j_params, "use-tls"))) {
          json_array_append_new(j_errors, json_string("use-tls is optional and must be a boolean"));
        }
        if (json_object_get(j_params, "check-certificate") != NULL && !json_is_boolean(json_object_get(j_params, "check-certificate"))) {
          json_array_append_new(j_errors, json_string("check-certificate is optional and must be a boolean"));
        }
        if (json_object_get(j_params, "user") != NULL && !json_is_string(json_object_get(j_params, "user"))) {
          json_array_append_new(j_errors, json_string("user is optional and must be a string"));
        }
        if (json_object_get(j_params, "password") != NULL && !json_is_string(json_object_get(j_params, "password"))) {
          json_array_append_new(j_errors, json_string("password is optional and must be a string"));
        }
        if (json_object_get(j_params, "from") != NULL && !json_string_length(json_object_get(j_params, "from"))) {
          json_array_append_new(j_errors, json_string("from is mandatory and must be a non empty string"));
        }
        if (json_object_get(j_params, "content-type") != NULL && !json_string_length(json_object_get(j_params, "content-type"))) {
          json_array_append_new(j_errors, json_string("content-type is optional and must be a string"));
        }
        if (json_object_get(j_params, "subject") != NULL && !json_string_length(json_object_get(j_params, "subject"))) {
          json_array_append_new(j_errors, json_string("subject is mandatory and must be a non empty string"));
        }
        if (json_object_get(j_params, "body-pattern") != NULL && !json_string_length(json_object_get(j_params, "body-pattern"))) {
          json_array_append_new(j_errors, json_string("body-pattern is mandatory and must be a non empty string"));
        }
      }
    }
    if (json_array_size(j_errors)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_errors);
    } else {
      j_return = json_pack("{si}", "result", G_OK);
    }
    json_decref(j_errors);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "plugin register - is_parameter_valid error allocating resources for j_errors");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

/**
 * 
 * plugin_module_load
 * 
 * Executed once when Glewlwyd service is started
 * Used to identify the module and to show its parameters on init
 * You can also use it to load resources that are required once for all
 * instance modules for example
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  name: string, mandatory, name of the module, must be unique among other scheme modules
 *                  display_name: string, optional, long name of the module
 *                  description: string, optional, description for the module
 *                  parameters: object, optional, parameters description for the module
 *                }
 * 
 *                Example:
 *                {
 *                  result: G_OK,
 *                  name: "mock",
 *                  display_name: "Mock scheme module",
 *                  description: "Mock scheme module for glewlwyd tests",
 *                  parameters: {
 *                    mock-value: {
 *                      type: "string",
 *                      mandatory: true
 *                    }
 *                  }
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * 
 */
json_t * plugin_module_load(struct config_plugin * config) {
  UNUSED(config);
  return json_pack("{sisssssss{s{ssso} s{sssosi} s{sssoso} s{sssosi} s{sssosi} s{sssoso}\
                               s{ssso} s{sssosi} s{sssoso} s{sssoso} s{ssso} s{ssso} s{ssso} s{ssso} s{sssoss} s{ssso}\
                               s{ssso} s{ssso}\
                               s[s{ssso} s{ssso} s{ssso}]}}",
                   "result",
                   G_OK,
                   "name",
                   "register",
                   "display_name",
                   "Register new user plugin",
                   "description",
                   "Adds self registered users in the user backend",
                   "parameters",
                     "session-key", 
                       "type", "string",
                       "mandatory", json_true(),
                     "session-duration", 
                       "type", "number",
                       "mandatory", json_false(),
                       "default", GLEWLWYD_PLUGIN_REGSITER_DEFAULT_SESSION_DURATION,
                     "verify-email", 
                       "type", "boolean",
                       "mandatory", json_false(),
                       "default", json_false(),
                     "verification-code-length", 
                       "type", "number",
                       "mandatory", json_false(),
                       "default", GLEWLWYD_PLUGIN_REGSITER_DEFAULT_CODE_LENGTH,
                     "verification-code-duration", 
                       "type", "number",
                       "mandatory", json_false(),
                       "default", GLEWLWYD_PLUGIN_REGSITER_DEFAULT_CODE_DURATION,
                     "email-is-username", 
                       "type", "boolean",
                       "mandatory", json_false(),
                       "default", json_false(),
                       
                     "host", 
                       "type", "string",
                       "mandatory", json_true(),
                     "port", 
                       "type", "number",
                       "mandatory", json_false(),
                       "default", 0,
                     "use-tls", 
                       "type", "boolean",
                       "mandatory", json_false(),
                       "default", json_false(),
                     "check-certificate", 
                       "type", "boolean",
                       "mandatory", json_false(),
                       "default", json_false(),
                     "user", 
                       "type", "string",
                       "mandatory", json_false(),
                     "password", 
                       "type", "string",
                       "mandatory", json_false(),
                     "from", 
                       "type", "string",
                       "mandatory", json_false(),
                     "subject", 
                       "type", "string",
                       "mandatory", json_true(),
                     "content-type", 
                       "type", "string",
                       "mandatory", json_true(),
                       "default", GLEWLWYD_PLUGIN_REGSITER_DEFAULT_CONTENT_TYPE,
                     "body-pattern", 
                       "type", "string",
                       "mandatory", json_true(),
                       
                     "add-scope", 
                       "type", "array",
                       "mandatory", json_true(),
                     "register-password", 
                       "type", "string",
                       "mandatory", json_true(),
                       
                     "schemes",
                       "module", 
                         "type", "string",
                         "mandatory", json_true(),
                       "name", 
                         "type", "string",
                         "mandatory", json_true(),
                       "register", 
                         "type", "string",
                         "mandatory", json_true());
}

/**
 * 
 * plugin_module_unload
 * 
 * Executed once when Glewlwyd service is stopped
 * You can use it to release resources that are required once for all
 * instance modules for example
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * 
 */
int plugin_module_unload(struct config_plugin * config) {
  UNUSED(config);
  return G_OK;
}

/**
 * 
 * plugin_module_init
 * 
 * Initialize an instance of this module declared in Glewlwyd service.
 * If required, you must dynamically allocate a pointer to the configuration
 * for this instance and pass it to *cls
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, G_ERROR_PARAM on input parameters error, another value on error)
 *                  error: array of strings containg the list of input errors, mandatory on result G_ERROR_PARAM, ignored otherwise
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter j_parameters: used to initialize an instance in JSON format
 *                          The module must validate itself its parameters
 * @parameter cls: will contain an allocated void * pointer that will be sent back
 *                 as void * in all module functions
 * 
 */
json_t * plugin_module_init(struct config_plugin * config, const char * name, json_t * j_parameters, void ** cls) {
  json_t * j_return, * j_result;
  struct _register_config * register_config;
  pthread_mutexattr_t mutexattr;
  
  y_log_message(Y_LOG_LEVEL_INFO, "Init plugin Glewlwyd register '%s'", name);
  j_result = is_plugin_parameters_valid(j_parameters);
  if (check_result_value(j_result, G_OK)) {
    register_config = o_malloc(sizeof(struct _register_config));
    if (register_config != NULL) {
      pthread_mutexattr_init ( &mutexattr );
      pthread_mutexattr_settype( &mutexattr, PTHREAD_MUTEX_RECURSIVE );
      if (!pthread_mutex_init(&register_config->insert_lock, &mutexattr)) {
        register_config->glewlwyd_config = config;
        register_config->name = o_strdup(name);
        register_config->j_parameters = json_incref(j_parameters);
        *cls = (void*)register_config;
        y_log_message(Y_LOG_LEVEL_INFO, "Add endpoints with plugin prefix %s", name);
        if (config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "config", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_config, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "username", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_check_username, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "register", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_register_user, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "verify", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_send_email_verification, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "verify", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_verify_email, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "*", name, "profile/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_register_verify_session, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "profile/password", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_update_password, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_get_data, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_update_data, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "DELETE", name, "profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_cancel, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "profile/scheme/register", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_get_scheme_registration, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "profile/scheme/register", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_update_scheme_registration, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "profile/scheme/register/canuse", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_canuse_scheme_registration, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "profile/complete", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_complete_registration, (void*)register_config) == G_OK &&
            config->glewlwyd_callback_add_plugin_endpoint(config, "*", name, "profile/*", GLEWLWYD_CALLBACK_PRIORITY_CLOSE, &callback_register_clean_session, NULL) == G_OK) {
          j_return = json_pack("{si}", "result", G_OK);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init register - Error glewlwyd_callback_add_plugin_endpoint");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init register - Error pthread_mutex_init");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init register - Error allocating resources for register_config");
      j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init register - Error input parameters");
    j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", json_object_get(j_result, "error"));
  }
  json_decref(j_result);
  return j_return;
}

/**
 * 
 * plugin_module_close
 * 
 * Close an instance of this module declared in Glewlwyd service.
 * You must free the memory previously allocated in
 * the client_module_init function as void * cls
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter cls: pointer to the void * cls value allocated in client_module_init
 * 
 */
int plugin_module_close(struct config_plugin * config, const char * name, void * cls) {
  y_log_message(Y_LOG_LEVEL_INFO, "Close plugin Glewlwyd register '%s'", name);
  if (cls != NULL) {
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "config");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "username");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "register");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "PUT", name, "verify");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "verify");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "profile/password");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "profile");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "PUT", name, "profile");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "DELETE", name, "profile");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "*", name, "profile/*");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "profile/scheme/register");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "PUT", name, "profile/scheme/register/canuse");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "profile/complete");
    o_free(((struct _register_config *)cls)->name);
    pthread_mutex_destroy(&((struct _register_config *)cls)->insert_lock);
    json_decref(((struct _register_config *)cls)->j_parameters);
    o_free(cls);
  }
  return G_OK;
}

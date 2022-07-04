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
 * Copyright 2019-2020 Nicolas Mora <mail@babelouest.org>
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

#include <ctype.h>
#include <regex.h>
#include <jansson.h>
#include "glewlwyd-common.h"

#define GLEWLWYD_PLUGIN_REGSITER_DEFAULT_SESSION_DURATION 3600
#define GLEWLWYD_PLUGIN_REGSITER_DEFAULT_CODE_LENGTH 8
#define GLEWLWYD_PLUGIN_REGSITER_DEFAULT_CODE_DURATION 600
#define GLEWLWYD_PLUGIN_REGSITER_DEFAULT_CONTENT_TYPE "text/plain; charset=utf-8"
#define GLEWLWYD_DATE_BUFFER 128
#define GLEWLWYD_SESSION_ID_LENGTH 32
#define GLEWLWYD_TOKEN_LENGTH 32
#define GLEWLWYD_RESET_CREDENTIALS_CODE_LENGTH 16
#define GLEWLWYD_MAX_USERNAME_LENGTH 128

#define GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION "gpr_session"
#define GLEWLWYD_PLUGIN_REGISTER_TABLE_UPDATE_EMAIL "gpr_update_email"
#define GLEWLWYD_PLUGIN_REGISTER_TABLE_RESET_CREDENTIALS_SESSION "gpr_reset_credentials_session"
#define GLEWLWYD_PLUGIN_REGISTER_TABLE_RESET_CREDENTIALS_EMAIL "gpr_reset_credentials_email"

#define GLWD_METRICS_REGISTRATION_STARTED        "glewlwyd_registration_started"
#define GLWD_METRICS_REGISTRATION_COMPLETED      "glewlwyd_registration_completed"
#define GLWD_METRICS_REGISTRATION_CANCELLED      "glewlwyd_registration_cancelled"
#define GLWD_METRICS_EMAIL_UPDATED               "glewlwyd_email_updated"
#define GLWD_METRICS_RESET_CREDENTIALS_STARTED   "glewlwyd_reset_credentials_started"
#define GLWD_METRICS_RESET_CREDENTIALS_COMPLETED "glewlwyd_reset_credentials_completed"

struct _register_config {
  struct config_plugin * glewlwyd_config;
  pthread_mutex_t        insert_lock;
  char                 * name;
  json_t               * j_parameters;
};

static int text_match_pattern(const char * text, const char * pattern, size_t pattern_length) {
  int match = 1, char_match;
  size_t i, j;

  for (i=0; i<o_strlen(text) && match; i++) {
    char_match = 0;
    for (j=0; j<pattern_length; j++) {
      if (text[i] == pattern[j]) {
        char_match = 1;
      }
    }
    if (!char_match) {
      match = 0;
    }
  }
  return match;
}

static int is_email_valid(const char * email) {
  int ret;
  char ** mail_splitted = NULL, ** domain_splitted = NULL;
  static const char login_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-",
                    domain_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-",
                    extension_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  size_t domain_elts, i;

  if (!o_strnullempty(email)) {
    if (split_string(email, "@", &mail_splitted) == 2) {
      if (!o_strnullempty(mail_splitted[0]) && !o_strnullempty(mail_splitted[1])) {
        if (text_match_pattern(mail_splitted[0], login_chars, o_strlen(login_chars))) {
          if ((domain_elts = split_string(mail_splitted[1], ".", &domain_splitted)) >= 2) {
            ret = 1;
            for (i=0; i<domain_elts-1 && ret; i++) {
              if (!text_match_pattern(domain_splitted[i], domain_chars, o_strlen(domain_chars))) {
                ret = 0;
              }
            }
            if (!text_match_pattern(domain_splitted[domain_elts-1], extension_chars, o_strlen(extension_chars)) || o_strlen(domain_splitted[domain_elts-1]) < 2 || o_strlen(domain_splitted[domain_elts-1]) > 4) {
              ret = 0;
            }
          } else {
            ret = 0;
          }
          free_string_array(domain_splitted);
        } else {
          ret = 0;
        }
      } else {
        ret = 0;
      }
    } else {
      ret = 0;
    }
    free_string_array(mail_splitted);
  } else {
    ret = 0;
  }
  return ret;
}

static int is_username_valid(const char * username) {
  static const char login_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@";
  return (!o_strnullempty(username) && o_strlen(username) <= 128 && text_match_pattern(username, login_chars, o_strlen(login_chars)));
}

static const char * get_template_property(json_t * j_params, const char * user_lang, const char * property_field) {
  json_t * j_template = NULL;
  const char * property = NULL, * property_default = NULL, * lang = NULL;
  
  if (json_object_get(j_params, "templates") == NULL) {
    property = json_string_value(json_object_get(j_params, property_field));
  } else {
    json_object_foreach(json_object_get(j_params, "templates"), lang, j_template) {
      if (0 == o_strcmp(user_lang, lang)) {
        property = json_string_value(json_object_get(j_template, property_field));
      }
      if (json_object_get(j_template, "defaultLang") == json_true()) {
        property_default = json_string_value(json_object_get(j_template, property_field));
      }
    }
    if (property == NULL) {
      property = property_default;
    }
  }
  return property;
}

static const char * get_template_email_update_property(json_t * j_params, const char * user_lang, const char * property_field) {
  json_t * j_template = NULL;
  const char * property = NULL, * property_default = NULL, * lang = NULL;
  
  if (json_object_get(j_params, "templatesUpdateEmail") == NULL) {
    property = json_string_value(json_object_get(j_params, property_field));
  } else {
    json_object_foreach(json_object_get(j_params, "templatesUpdateEmail"), lang, j_template) {
      if (0 == o_strcmp(user_lang, lang)) {
        property = json_string_value(json_object_get(j_template, property_field));
      }
      if (json_object_get(j_template, "defaultLang") == json_true()) {
        property_default = json_string_value(json_object_get(j_template, property_field));
      }
    }
    if (property == NULL) {
      property = property_default;
    }
  }
  return property;
}

static const char * get_template_reset_credentials_property(json_t * j_params, const char * user_lang, const char * property_field) {
  json_t * j_template = NULL;
  const char * property = NULL, * property_default = NULL, * lang = NULL;
  
  if (json_object_get(j_params, "templatesResetCredentials") == NULL) {
    property = json_string_value(json_object_get(j_params, property_field));
  } else {
    json_object_foreach(json_object_get(j_params, "templatesResetCredentials"), lang, j_template) {
      if (0 == o_strcmp(user_lang, lang)) {
        property = json_string_value(json_object_get(j_template, property_field));
      }
      if (json_object_get(j_template, "defaultLang") == json_true()) {
        property_default = json_string_value(json_object_get(j_template, property_field));
      }
    }
    if (property == NULL) {
      property = property_default;
    }
  }
  return property;
}

static int can_register_scheme(struct _register_config * config, const struct _u_request * request, const char * scheme_name) {
  json_t * j_element = NULL;
  size_t index = 0;
  
  if (o_strstr(request->url_path, "reset-credentials") == NULL) {
    if (json_object_get(config->j_parameters, "schemes") != NULL) {
      json_array_foreach(json_object_get(config->j_parameters, "schemes"), index, j_element) {
        if (0 == o_strcmp(json_string_value(json_object_get(j_element, "name")), scheme_name)) {
          return 1;
        }
      }
    }
    return 0;
  } else {
    return 1;
  }
}

static json_t * register_generate_email_verification_code(struct _register_config * config, const char * username, const char * email, const char * lang, const char * callback_url, const char * issued_for, const char * user_agent, const char * ip_source) {
  char * code, * code_hash, * expires_at_clause, * tmp_body, * body, token[GLEWLWYD_TOKEN_LENGTH+1], * token_hash;
  json_t * j_return, * j_query, * j_last_id;
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
      if ((code = o_malloc((code_len+1))) != NULL) {
        if (rand_code(code, code_len)) {
          if ((code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code)) != NULL) {
            if (rand_string_nonce(token, GLEWLWYD_TOKEN_LENGTH)) {
              if ((token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token)) != NULL) {
                if ((tmp_body = str_replace(get_template_property(config->j_parameters, lang, "body-pattern"), "{TOKEN}", token)) != NULL) {
                  if ((body = str_replace(tmp_body, "{CODE}", code)) != NULL) {
                    if (ulfius_send_smtp_rich_email(json_string_value(json_object_get(config->j_parameters, "host")),
                                                   json_integer_value(json_object_get(config->j_parameters, "port")),
                                                   json_object_get(config->j_parameters, "use-tls")==json_true()?1:0,
                                                   json_object_get(config->j_parameters, "verify-certificate")==json_false()?0:1,
                                                   !json_string_null_or_empty(json_object_get(config->j_parameters, "user"))?json_string_value(json_object_get(config->j_parameters, "user")):NULL,
                                                   !json_string_null_or_empty(json_object_get(config->j_parameters, "password"))?json_string_value(json_object_get(config->j_parameters, "password")):NULL,
                                                   json_string_value(json_object_get(config->j_parameters, "from")),
                                                   email,
                                                   NULL,
                                                   NULL,
                                                   !json_string_null_or_empty(json_object_get(config->j_parameters, "content-type"))?json_string_value(json_object_get(config->j_parameters, "content-type")):"text/plain; charset=utf-8",
                                                   get_template_property(config->j_parameters, lang, "subject"),
                                                   body) == U_OK) {
                      y_log_message(Y_LOG_LEVEL_WARNING, "Security - Register new user - code sent to email %s at IP Address %s", email, ip_source);
                      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
                        expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "verification-code-duration"))));
                      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
                        expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "verification-code-duration"))));
                      } else { // HOEL_DB_TYPE_SQLITE
                        expires_at_clause = msprintf("%u", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "verification-code-duration"))));
                      }
                      j_query = json_pack("{sss{ssssssssss?sss{ss}ssss}}",
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
                                            "gprs_callback_url",
                                            callback_url,
                                            "gprs_token_hash",
                                            token_hash,
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
                        if ((j_last_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn)) != NULL) {
                          config->glewlwyd_config->glewlwyd_callback_update_issued_for(config->glewlwyd_config, NULL, GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION, "gprs_issued_for", issued_for, "gprs_id", json_integer_value(j_last_id));
                          j_return = json_pack("{siss}", "result", G_OK, "code", code);
                        } else {
                          y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error h_last_insert_id");
                          config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
                          j_return = json_pack("{si}", "result", G_ERROR_DB);
                        }
                        json_decref(j_last_id);
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error executing j_query");
                        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
                        j_return = json_pack("{si}", "result", G_ERROR_DB);
                      }
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error ulfius_send_smtp_rich_email");
                      j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
                    }
                    o_free(body);
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error str_replace");
                    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
                  }
                  o_free(tmp_body);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error str_replace tmp_body");
                  j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
                }
                o_free(token_hash);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error glewlwyd_callback_generate_hash rand_string_nonce token");
                j_return = json_pack("{si}", "result", G_ERROR);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error rand_string_nonce token");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
            o_free(code_hash);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error glewlwyd_callback_generate_hash rand_code code");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error rand_code code");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        o_free(code);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error allocating resources for code");
        j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_generate_email_verification_code - Error executing j_query");
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
    pthread_mutex_unlock(&config->insert_lock);
  }
  return j_return;
}

static json_t * register_verify_email_token(struct _register_config * config, const char * token, const char * ip_source) {
  json_t * j_query, * j_result = NULL, * j_return, * j_new_user;
  int res;
  char * token_hash = NULL, * expires_at_clause = NULL, session[GLEWLWYD_SESSION_ID_LENGTH+1] = {}, * session_hash = NULL;
  time_t now;
  
  if ((token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token)) != NULL) {
    time(&now);
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
    } else { // HOEL_DB_TYPE_SQLITE
      expires_at_clause = msprintf("> %u", (now));
    }
    j_query = json_pack("{sss[sss]s{sssss{ssss}si}}",
                        "table",
                        GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                        "columns",
                          "gprs_id",
                          "gprs_username AS username",
                          "gprs_email AS email",
                        "where",
                          "gprs_plugin_name",
                          config->name,
                          "gprs_token_hash",
                          token_hash,
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
        j_new_user = json_pack("{sOsOsosO}", "username", json_object_get(json_array_get(j_result, 0), "username"), "email", json_object_get(json_array_get(j_result, 0), "email"), "enabled", json_false(), "scope", json_object_get(config->j_parameters, "scope"));
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
              j_query = json_pack("{sss{sss{ss}ss}s{sssO}}",
                                  "table",
                                  GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                                  "set",
                                    "gprs_session_hash",
                                    session_hash,
                                    "gprs_expires_at",
                                      "raw",
                                      expires_at_clause,
                                    "gprs_token_hash",
                                    "VERIFIED",
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
                config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
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
          config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        json_decref(j_new_user);
      } else {
        y_log_message(Y_LOG_LEVEL_WARNING, "Security - Verify e-mail - code invalid at IP Address %s", ip_source);
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_verify_email_code - Error executing j_query");
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "register_verify_email_code - Error generate hash for session");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  o_free(token_hash);
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
              j_query = json_pack("{sss{sss{ss}ss}s{sssO}}",
                                  "table",
                                  GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                                  "set",
                                    "gprs_session_hash",
                                    session_hash,
                                    "gprs_expires_at",
                                      "raw",
                                      expires_at_clause,
                                    "gprs_code_hash",
                                    "VERIFIED",
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
                config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
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
          config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        json_decref(j_new_user);
      } else {
        y_log_message(Y_LOG_LEVEL_WARNING, "Security - Verify e-mail - code invalid at IP Address %s", ip_source);
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_verify_email_code - Error executing j_query");
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
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
  
  if (o_strlen(session) == GLEWLWYD_SESSION_ID_LENGTH) {
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
      j_query = json_pack("{sss[sssss]s{sssss{ssss}si}}",
                          "table",
                          GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION,
                          "columns",
                            "gprs_username AS username",
                            "gprs_name AS name",
                            "gprs_email AS email",
                            "gprs_callback_url AS callback_url",
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
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
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
  
  if (!o_strnullempty(username)) {
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
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

static json_t * register_new_user(struct _register_config * config, const char * username, const char * issued_for, const char * user_agent) {
  json_t * j_query, * j_return, * j_user, * j_new_user, * j_last_id, * j_result;
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
      j_result = config->glewlwyd_config->glewlwyd_plugin_callback_is_user_valid(config->glewlwyd_config, username, j_new_user, 1);
      if (check_result_value(j_result, G_OK)) {
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
                if ((j_last_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn)) != NULL) {
                  config->glewlwyd_config->glewlwyd_callback_update_issued_for(config->glewlwyd_config, NULL, GLEWLWYD_PLUGIN_REGISTER_TABLE_SESSION, "gprs_issued_for", issued_for, "gprs_id", json_integer_value(j_last_id));
                  j_return = json_pack("{siss}", "result", G_OK, "session", session);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "register_new_user - Error h_last_insert_id");
                  config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
                  j_return = json_pack("{si}", "result", G_ERROR_DB);
                }
                json_decref(j_last_id);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "register_new_user - Error executing j_query");
                config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
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
      } else if (check_result_value(j_result, G_ERROR_PARAM)) {
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "register_new_user - Error glewlwyd_plugin_callback_is_user_valid");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_new_user);
      json_decref(j_result);
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
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
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
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
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
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
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

static int register_update_email_trigger(struct _register_config * config, const char * username, const char * email, const char * lang, const char * issued_for, const char * user_agent, const char * ip_source) {
  json_t * j_query, * j_last_id;
  int ret, res;
  char token[GLEWLWYD_TOKEN_LENGTH+1] = {0}, * token_hash = NULL, * body = NULL, * expires_at_clause;
  time_t now;
  
  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "register_update_email_trigger - Error pthread_mutex_lock");
    ret = G_ERROR;
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
    j_query = json_pack("{sss{si}s{sssssis{ssss}}}",
                        "table",
                        GLEWLWYD_PLUGIN_REGISTER_TABLE_UPDATE_EMAIL,
                        "set",
                          "gprue_enabled",
                          0,
                        "where",
                          "gprue_plugin_name",
                          config->name,
                          "gprue_username",
                          username,
                          "gprue_enabled",
                          1,
                          "gprue_expires_at",
                            "operator",
                            "raw",
                            "value",
                            expires_at_clause);
    o_free(expires_at_clause);
    res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (rand_string(token, GLEWLWYD_TOKEN_LENGTH) != NULL) {
        if ((token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token)) != NULL) {
          if ((body = str_replace(get_template_email_update_property(config->j_parameters, lang, "body-pattern"), "{TOKEN}", token)) != NULL) {
            if (ulfius_send_smtp_rich_email(json_string_value(json_object_get(config->j_parameters, "host")),
                                           json_integer_value(json_object_get(config->j_parameters, "port")),
                                           json_object_get(config->j_parameters, "use-tls")==json_true()?1:0,
                                           json_object_get(config->j_parameters, "verify-certificate")==json_false()?0:1,
                                           !json_string_null_or_empty(json_object_get(config->j_parameters, "user"))?json_string_value(json_object_get(config->j_parameters, "user")):NULL,
                                           !json_string_null_or_empty(json_object_get(config->j_parameters, "password"))?json_string_value(json_object_get(config->j_parameters, "password")):NULL,
                                           json_string_value(json_object_get(config->j_parameters, "update-email-from")),
                                           email,
                                           NULL,
                                           NULL,
                                           !json_string_null_or_empty(json_object_get(config->j_parameters, "update-email-content-type"))?json_string_value(json_object_get(config->j_parameters, "update-email-content-type")):"text/plain; charset=utf-8",
                                           get_template_email_update_property(config->j_parameters, lang, "subject"),
                                           body) == U_OK) {
              y_log_message(Y_LOG_LEVEL_WARNING, "Security - Update e-mail - token sent to email %s at IP Address %s", email, ip_source);
              if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
                expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "update-email-token-duration"))));
              } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
                expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "update-email-token-duration"))));
              } else { // HOEL_DB_TYPE_SQLITE
                expires_at_clause = msprintf("%u", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "update-email-token-duration"))));
              }
              j_query = json_pack("{sss{sssssssss{ss}ssss}}",
                                  "table",
                                  GLEWLWYD_PLUGIN_REGISTER_TABLE_UPDATE_EMAIL,
                                  "values",
                                    "gprue_plugin_name",
                                    config->name,
                                    "gprue_username",
                                    username,
                                    "gprue_email",
                                    email,
                                    "gprue_token_hash",
                                    token_hash,
                                    "gprue_expires_at",
                                      "raw",
                                      expires_at_clause,
                                    "gprue_issued_for",
                                    issued_for,
                                    "gprue_user_agent",
                                    user_agent!=NULL?user_agent:"");
              o_free(expires_at_clause);
              res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
              json_decref(j_query);
              if (res == H_OK) {
                if ((j_last_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn)) != NULL) {
                  config->glewlwyd_config->glewlwyd_callback_update_issued_for(config->glewlwyd_config, NULL, GLEWLWYD_PLUGIN_REGISTER_TABLE_UPDATE_EMAIL, "gprue_issued_for", issued_for, "gprue_id", json_integer_value(j_last_id));
                  ret = G_OK;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "register_update_email_trigger - Error h_last_insert_id");
                  config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
                  ret = G_ERROR_DB;
                }
                json_decref(j_last_id);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "register_update_email_trigger - Error executing j_query (2)");
                config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
                ret = G_ERROR_DB;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "register_update_email_trigger - Error ulfius_send_smtp_rich_email");
              ret = G_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "register_update_email_trigger - Error get_template_email_update_property");
            ret = G_ERROR;
          }
          o_free(body);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_update_email_trigger - Error glewlwyd_callback_generate_hash");
          ret = G_ERROR;
        }
        o_free(token_hash);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "register_update_email_trigger - Error rand_string");
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_update_email_trigger - Error executing j_query (1)");
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
      ret = G_ERROR_DB;
    }
    pthread_mutex_unlock(&config->insert_lock);
  }
  return ret;
}

static int register_update_email_verify(struct _register_config * config, const char * token, const char * ip_source) {
  json_t * j_query, * j_result = NULL, * j_updated_user = NULL;
  int res, ret;
  char * token_hash = NULL, * expires_at_clause = NULL;
  time_t now;
  
  if (o_strlen(token) == GLEWLWYD_TOKEN_LENGTH) {
    if ((token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token)) != NULL) {
      time(&now);
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
      } else { // HOEL_DB_TYPE_SQLITE
        expires_at_clause = msprintf("> %u", (now));
      }
      j_query = json_pack("{sss[sss]s{sssss{ssss}si}}",
                          "table",
                          GLEWLWYD_PLUGIN_REGISTER_TABLE_UPDATE_EMAIL,
                          "columns",
                            "gprue_id",
                            "gprue_username AS username",
                            "gprue_email AS email",
                          "where",
                            "gprue_plugin_name",
                            config->name,
                            "gprue_token_hash",
                            token_hash,
                            "gprue_expires_at",
                              "operator",
                              "raw",
                              "value",
                              expires_at_clause,
                            "gprue_enabled",
                            1);
      o_free(expires_at_clause);
      res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          j_updated_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, json_string_value(json_object_get(json_array_get(j_result, 0), "username")));
          if (check_result_value(j_updated_user, G_OK)) {
            json_object_set(json_object_get(j_updated_user, "user"), "email", json_object_get(json_array_get(j_result, 0), "email"));
            if (config->glewlwyd_config->glewlwyd_plugin_callback_set_user(config->glewlwyd_config, json_string_value(json_object_get(json_array_get(j_result, 0), "username")), json_object_get(j_updated_user, "user")) == G_OK) {
              j_query = json_pack("{sss{si}s{sO}}",
                                  "table",
                                  GLEWLWYD_PLUGIN_REGISTER_TABLE_UPDATE_EMAIL,
                                  "set",
                                    "gprue_enabled",
                                    0,
                                  "where",
                                    "gprue_id",
                                    json_object_get(json_array_get(j_result, 0), "gprue_id"));
              res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
              json_decref(j_query);
              if (res == H_OK) {
                ret = G_OK;
                y_log_message(Y_LOG_LEVEL_INFO, "Event register - Plugin '%s' - user '%s' updated its e-mail address to '%s', origin: %s", config->name, json_string_value(json_object_get(json_array_get(j_result, 0), "username")), json_string_value(json_object_get(json_array_get(j_result, 0), "email")), ip_source);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "register_update_email_verify - Error executing j_query (2)");
                config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
                ret = G_ERROR_DB;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "register_update_email_verify - Error glewlwyd_plugin_callback_set_user");
              ret = G_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "register_update_email_verify - Error glewlwyd_plugin_callback_get_user");
            ret = G_ERROR;
          }
          json_decref(j_updated_user);
        } else {
          y_log_message(Y_LOG_LEVEL_WARNING, "Security - Update e-mail - token invalid at IP Address %s", ip_source);
          ret = G_ERROR_PARAM;
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "register_update_email_verify - Error executing j_query (1)");
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        ret = G_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_update_email_verify - Error generate hash");
      ret = G_ERROR;
    }
    o_free(token_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_WARNING, "Security - Update e-mail - token invalid at IP Address %s", ip_source);
    ret = G_ERROR_PARAM;
  }
  return ret;
}

static json_t * reset_credentials_check_session(struct _register_config * config, const char * session) {
  json_t * j_query, * j_result = NULL, * j_return, * j_user;
  int res;
  char * session_hash = NULL, * expires_at_clause = NULL;
  time_t now;
  
  if (o_strlen(session) == GLEWLWYD_SESSION_ID_LENGTH) {
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
      j_query = json_pack("{sss[ss]s{sssss{ssss}si}}",
                          "table",
                          GLEWLWYD_PLUGIN_REGISTER_TABLE_RESET_CREDENTIALS_SESSION,
                          "columns",
                            "gprrcs_username AS username",
                            "gprrcs_callback_url AS callback_url",
                          "where",
                            "gprrcs_plugin_name",
                            config->name,
                            "gprrcs_session_hash",
                            session_hash,
                            "gprrcs_expires_at",
                              "operator",
                              "raw",
                              "value",
                              expires_at_clause,
                            "gprrcs_enabled",
                            1);
      o_free(expires_at_clause);
      res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, json_string_value(json_object_get(json_array_get(j_result, 0), "username")));
          if (check_result_value(j_user, G_OK)) {
            j_return = json_pack("{sisO}", "result", G_OK, "user", json_object_get(j_user, "user"));
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_check_session - Error glewlwyd_plugin_callback_get_user");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          json_decref(j_user);
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_check_session - Error executing j_query");
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_check_session - Error generate hash for session");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(session_hash);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

static int reset_credentials_remove_session(struct _register_config * config, const char * session) {
  json_t * j_query;
  int res, ret;
  char * session_hash = NULL;
  
  session_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, session);
  if (session_hash != NULL) {
    j_query = json_pack("{sss{si}s{ssss}}",
                        "table",
                        GLEWLWYD_PLUGIN_REGISTER_TABLE_RESET_CREDENTIALS_SESSION,
                        "set",
                          "gprrcs_enabled", 0,
                        "where",
                          "gprrcs_plugin_name", config->name,
                          "gprrcs_session_hash", session_hash);
    res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      ret = G_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_remove_session - Error executing j_query");
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
      ret = G_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_remove_session - Error generate hash for session");
    ret = G_ERROR;
  }
  o_free(session_hash);
  return ret;
}

static int register_reset_credentials_trigger(struct _register_config * config, const char * username, const char * lang, const char * callback_url, const char * issued_for, const char * user_agent, const char * ip_source) {
  json_t * j_query, * j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, username), * j_last_id = NULL;
  int ret, res;
  char token[GLEWLWYD_TOKEN_LENGTH+1] = {0}, * token_hash = NULL, * body = NULL, * expires_at_clause;
  time_t now;
  const char * email = NULL;
  
  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "register_reset_credentials_trigger - Error pthread_mutex_lock");
    ret = G_ERROR;
  } else {
    if (check_result_value(j_user, G_OK) && !json_string_null_or_empty(json_object_get(json_object_get(j_user, "user"), "email"))) {
      email = json_string_value(json_object_get(json_object_get(j_user, "user"), "email"));
      // Disable existing sessions for the specified e-mail address
      time(&now);
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
      } else { // HOEL_DB_TYPE_SQLITE
        expires_at_clause = msprintf("> %u", (now));
      }
      j_query = json_pack("{sss{si}s{sssssis{ssss}}}",
                          "table",
                          GLEWLWYD_PLUGIN_REGISTER_TABLE_RESET_CREDENTIALS_EMAIL,
                          "set",
                            "gprrct_enabled",
                            0,
                          "where",
                            "gprrct_plugin_name",
                            config->name,
                            "gprrct_username",
                            username,
                            "gprrct_enabled",
                            1,
                            "gprrct_expires_at",
                              "operator",
                              "raw",
                              "value",
                              expires_at_clause);
      o_free(expires_at_clause);
      res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (rand_string(token, GLEWLWYD_TOKEN_LENGTH) != NULL) {
          if ((token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token)) != NULL) {
            if ((body = str_replace(get_template_reset_credentials_property(config->j_parameters, lang, "body-pattern"), "{TOKEN}", token)) != NULL) {
              if (ulfius_send_smtp_rich_email(json_string_value(json_object_get(config->j_parameters, "host")),
                                             json_integer_value(json_object_get(config->j_parameters, "port")),
                                             json_object_get(config->j_parameters, "use-tls")==json_true()?1:0,
                                             json_object_get(config->j_parameters, "verify-certificate")==json_false()?0:1,
                                             !json_string_null_or_empty(json_object_get(config->j_parameters, "user"))?json_string_value(json_object_get(config->j_parameters, "user")):NULL,
                                             !json_string_null_or_empty(json_object_get(config->j_parameters, "password"))?json_string_value(json_object_get(config->j_parameters, "password")):NULL,
                                             json_string_value(json_object_get(config->j_parameters, "reset-credentials-from")),
                                             email,
                                             NULL,
                                             NULL,
                                             !json_string_null_or_empty(json_object_get(config->j_parameters, "reset-credentials-content-type"))?json_string_value(json_object_get(config->j_parameters, "reset-credentials-content-type")):"text/plain; charset=utf-8",
                                             get_template_reset_credentials_property(config->j_parameters, lang, "subject"),
                                             body) == U_OK) {
                y_log_message(Y_LOG_LEVEL_WARNING, "Security - Reset credentials - token sent to email %s at IP Address %s", email, ip_source);
                if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
                  expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "reset-credentials-token-duration"))));
                } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
                  expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "reset-credentials-token-duration"))));
                } else { // HOEL_DB_TYPE_SQLITE
                  expires_at_clause = msprintf("%u", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "reset-credentials-token-duration"))));
                }
                j_query = json_pack("{sss{ssssssss?s{ss}ssss}}",
                                    "table",
                                    GLEWLWYD_PLUGIN_REGISTER_TABLE_RESET_CREDENTIALS_EMAIL,
                                    "values",
                                      "gprrct_plugin_name", config->name,
                                      "gprrct_username", username,
                                      "gprrct_token_hash", token_hash,
                                      "gprrct_callback_url", callback_url,
                                      "gprrct_expires_at",
                                        "raw",
                                        expires_at_clause,
                                      "gprrct_issued_for", issued_for,
                                      "gprrct_user_agent", user_agent!=NULL?user_agent:"");
                o_free(expires_at_clause);
                res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
                json_decref(j_query);
                if (res == H_OK) {
                  if ((j_last_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn)) != NULL) {
                    config->glewlwyd_config->glewlwyd_callback_update_issued_for(config->glewlwyd_config, NULL, GLEWLWYD_PLUGIN_REGISTER_TABLE_RESET_CREDENTIALS_EMAIL, "gprrct_issued_for", issued_for, "gprrct_id", json_integer_value(j_last_id));
                    ret = G_OK;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "register_reset_credentials_trigger - Error h_last_insert_id");
                    ret = G_ERROR;
                  }
                  json_decref(j_last_id);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "register_reset_credentials_trigger - Error executing j_query (2)");
                  config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
                  ret = G_ERROR_DB;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "register_reset_credentials_trigger - Error ulfius_send_smtp_rich_email");
                ret = G_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "register_reset_credentials_trigger - Error get_template_email_update_property");
              ret = G_ERROR;
            }
            o_free(body);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "register_reset_credentials_trigger - Error glewlwyd_callback_generate_hash");
            ret = G_ERROR;
          }
          o_free(token_hash);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_reset_credentials_trigger - Error rand_string");
          ret = G_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "register_reset_credentials_trigger - Error executing j_query (1)");
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        ret = G_ERROR_DB;
      }
    } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
      y_log_message(Y_LOG_LEVEL_WARNING, "Security - Reset credentials - user '%s' not found at IP Address %s", email, ip_source);
      ret = G_ERROR_NOT_FOUND;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_reset_credentials_trigger - Error glewlwyd_plugin_callback_get_user");
      ret = G_ERROR;
    }
    pthread_mutex_unlock(&config->insert_lock);
  }
  json_decref(j_user);
  return ret;
}

static json_t * register_reset_credentials_check_token(struct _register_config * config, const char * token) {
  json_t * j_return, * j_query, * j_result = NULL;
  int res;
  char * token_hash = NULL, * expires_at_clause = NULL;
  time_t now;
  
  if ((token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token)) != NULL) {
    time(&now);
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
    } else { // HOEL_DB_TYPE_SQLITE
      expires_at_clause = msprintf("> %u", (now));
    }
    j_query = json_pack("{sss[sss]s{sssss{ssss}si}}",
                        "table",
                        GLEWLWYD_PLUGIN_REGISTER_TABLE_RESET_CREDENTIALS_EMAIL,
                        "columns",
                          "gprrct_id",
                          "gprrct_username AS username",
                          "gprrct_callback_url AS callback_url",
                        "where",
                          "gprrct_plugin_name", config->name,
                          "gprrct_token_hash", token_hash,
                          "gprrct_expires_at",
                            "operator",
                            "raw",
                            "value",
                            expires_at_clause,
                          "gprrct_enabled", 1);
    o_free(expires_at_clause);
    res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        j_query = json_pack("{sss{si}s{sO}}",
                            "table",
                            GLEWLWYD_PLUGIN_REGISTER_TABLE_RESET_CREDENTIALS_EMAIL,
                            "set",
                              "gprrct_enabled",
                              0,
                            "where",
                              "gprrct_id",
                              json_object_get(json_array_get(j_result, 0), "gprrct_id"));
        res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          j_return = json_pack("{sisO}", "result", G_OK, "username", json_object_get(json_array_get(j_result, 0), "username"));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "register_reset_credentials_check_token - Error executing j_query (2)");
          config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_reset_credentials_check_token - Error executing j_query (1)");
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "register_reset_credentials_check_token - Error glewlwyd_callback_generate_hash");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  o_free(token_hash);
  return j_return;
}

static json_t * reset_credentials_create_session(struct _register_config * config, const char * username, const char * callback_url, const char * issued_for, const char * user_agent) {
  json_t * j_return, * j_query, * j_last_id;
  int res;
  char token[GLEWLWYD_TOKEN_LENGTH+1] = {}, * token_hash = NULL, * expires_at_clause;
  time_t now;
  
  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_create_session - Error pthread_mutex_lock");
    j_return = json_pack("{si}", "result", G_ERROR);
  } else {
    pthread_mutex_unlock(&config->insert_lock);
  }
  if (rand_string_nonce(token, GLEWLWYD_TOKEN_LENGTH)) {
    if ((token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token)) != NULL) {
      time(&now);
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "reset-credentials-session-duration"))));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "reset-credentials-session-duration"))));
      } else { // HOEL_DB_TYPE_SQLITE
        expires_at_clause = msprintf("%u", (now + (unsigned int)json_integer_value(json_object_get(config->j_parameters, "reset-credentials-session-duration"))));
      }
      j_query = json_pack("{sss{ssssssss?s{ss}ssss}}",
                          "table",
                          GLEWLWYD_PLUGIN_REGISTER_TABLE_RESET_CREDENTIALS_SESSION,
                          "values",
                            "gprrcs_plugin_name", config->name,
                            "gprrcs_username", username,
                            "gprrcs_session_hash", token_hash,
                            "gprrcs_callback_url", callback_url,
                            "gprrcs_expires_at",
                              "raw",
                              expires_at_clause,
                            "gprrcs_issued_for", issued_for,
                            "gprrcs_user_agent", user_agent!=NULL?user_agent:"");
      o_free(expires_at_clause);
      res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if ((j_last_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn)) != NULL) {
          config->glewlwyd_config->glewlwyd_callback_update_issued_for(config->glewlwyd_config, NULL, GLEWLWYD_PLUGIN_REGISTER_TABLE_RESET_CREDENTIALS_SESSION, "gprrcs_issued_for", issued_for, "gprrcs_id", json_integer_value(j_last_id));
          j_return = json_pack("{siss}", "result", G_OK, "session", token);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_create_session - Error h_last_insert_id");
          config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        json_decref(j_last_id);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_create_session - Error executing j_query");
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_create_session - Error glewlwyd_callback_generate_hash");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(token_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_create_session - Error rand_string_nonce");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

static json_t * reset_credentials_code_generate(struct _register_config * config, const char * username) {
  json_t * j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, username), * j_return, * j_code_list;
  char code[GLEWLWYD_RESET_CREDENTIALS_CODE_LENGTH+1] = {}, code_formatted[GLEWLWYD_RESET_CREDENTIALS_CODE_LENGTH+(GLEWLWYD_RESET_CREDENTIALS_CODE_LENGTH/4)+1] = {}, * code_hash = NULL, * code_formatted_offset;
  json_int_t i;
  int res, j;
  
  if (check_result_value(j_user, G_OK)) {
    res = G_OK;
    if ((j_code_list = json_array()) != NULL) {
      if (!json_is_array(json_object_get(json_object_get(j_user, "user"), json_string_value(json_object_get(config->j_parameters, "reset-credentials-code-property"))))) {
        json_object_set_new(json_object_get(j_user, "user"), json_string_value(json_object_get(config->j_parameters, "reset-credentials-code-property")), json_array());
      }
      for (i=0; res == G_OK && i<json_integer_value(json_object_get(config->j_parameters, "reset-credentials-code-list-size")); i++) {
        if (rand_string_from_charset(code, GLEWLWYD_RESET_CREDENTIALS_CODE_LENGTH, "abcdefghijklmnopqrstuvwxyz0123456789") != NULL) {
          code_formatted_offset = code_formatted;
          for (j=0; j<GLEWLWYD_RESET_CREDENTIALS_CODE_LENGTH; j++) {
            if (j && !(j%4)) {
              *code_formatted_offset = '-';
              code_formatted_offset++;
            }
            *code_formatted_offset = code[j];
            code_formatted_offset++;
          }
          *code_formatted_offset = '\0';
          if ((code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code)) != NULL) {
            json_array_append_new(json_object_get(json_object_get(j_user, "user"), json_string_value(json_object_get(config->j_parameters, "reset-credentials-code-property"))), json_string(code_hash));
            json_array_append_new(j_code_list, json_string(code_formatted));
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_code_generate - Error glewlwyd_callback_generate_hash");
            res = G_ERROR;
          }
          o_free(code_hash);
          code_hash = NULL;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_code_generate - Error rand_string_from_charset");
          res = G_ERROR;
        }
      }
      if (res == G_OK) {
        if (config->glewlwyd_config->glewlwyd_plugin_callback_set_user(config->glewlwyd_config, username, json_object_get(j_user, "user")) == G_OK) {
          j_return = json_pack("{sisO}", "result", G_OK, "code", j_code_list);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_code_generate - Error glewlwyd_plugin_callback_set_user");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_code_generate - Error generating or storing code");
        j_return = json_pack("{si}", "result", res);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_code_generate - Error allocating resources for j_code_list");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_code_list);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_code_generate - Error glewlwyd_plugin_callback_get_user");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_user);
  
  return j_return;
}

static int reset_credentials_code_verify(struct _register_config * config, const char * username, const char * code) {
  int ret, found = 0;
  json_t * j_user;
  char * code_deformatted = NULL, * code_deformatted_offset, * code_hash = NULL;
  size_t i, array_size;
  const char * code_property = json_string_value(json_object_get(config->j_parameters, "reset-credentials-code-property"));
  
  if (!o_strnullempty(username) && !o_strnullempty(code)) {
    j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, username);
    if (check_result_value(j_user, G_OK) && (array_size = json_array_size(json_object_get(json_object_get(j_user, "user"), code_property))) >= (size_t)json_integer_value(json_object_get(config->j_parameters, "reset-credentials-code-list-size"))) {
      if ((code_deformatted = str_replace(code, "-", "")) != NULL) {
        if (o_strlen(code_deformatted) == GLEWLWYD_RESET_CREDENTIALS_CODE_LENGTH) {
          code_deformatted_offset = code_deformatted;
          while (*code_deformatted_offset != '\0') {
            *code_deformatted_offset = tolower(*code_deformatted_offset);
            code_deformatted_offset++;
          }
          if ((code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code_deformatted)) != NULL) {
            for (i=(array_size - json_integer_value(json_object_get(config->j_parameters, "reset-credentials-code-list-size"))); !found && i<array_size; i++) {
              if (0 == o_strcmp(json_string_value(json_array_get(json_object_get(json_object_get(j_user, "user"), code_property), i)), code_hash)) {
                json_array_set_new(json_object_get(json_object_get(j_user, "user"), code_property), i, json_pack("s+", "**USED**", json_string_value(json_array_get(json_object_get(json_object_get(j_user, "user"), code_property), i))));
                found = 1;
              }
            }
            if (found) {
              if (config->glewlwyd_config->glewlwyd_plugin_callback_set_user(config->glewlwyd_config, username, json_object_get(j_user, "user")) == G_OK) {
                ret = G_OK;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_code_verify - Error glewlwyd_plugin_callback_set_user");
                ret = G_ERROR;
              }
            } else {
              ret = G_ERROR_UNAUTHORIZED;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_code_verify - Error glewlwyd_callback_generate_hash");
            ret = G_ERROR;
          }
          o_free(code_hash);
        } else {
          ret = G_ERROR_UNAUTHORIZED;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "reset_credentials_code_verify - Error str_replace");
        ret = G_ERROR;
      }
      o_free(code_deformatted);
    } else {
      ret = G_ERROR_UNAUTHORIZED;
    }
    json_decref(j_user);
  } else {
    ret = G_ERROR_UNAUTHORIZED;
  }
  return ret;
}

static int callback_register_config(const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_config, * j_template = NULL, * j_config_register;
  const char * lang = NULL;
  
  if (json_object_get(config->j_parameters, "registration") != json_false()) {
    j_config_register = json_pack("{sOsOsOsOs[]}",
                                  "set-password", json_object_get(config->j_parameters, "set-password"), 
                                  "schemes", json_object_get(config->j_parameters, "schemes")!=NULL?json_object_get(config->j_parameters, "schemes"):json_null(),
                                  "verify-email", json_object_get(config->j_parameters, "verify-email")!=NULL?json_object_get(config->j_parameters, "verify-email"):json_false(),
                                  "email-is-username", json_object_get(config->j_parameters, "email-is-username")!=NULL?json_object_get(config->j_parameters, "email-is-username"):json_false(),
                                  "languages");
    // Add default lang on top of the list
    json_object_foreach(json_object_get(config->j_parameters, "templates"), lang, j_template) {
      if (json_object_get(j_template, "defaultLang") == json_true()) {
        json_array_append_new(json_object_get(j_config_register, "languages"), json_string(lang));
      }
    }
    json_object_foreach(json_object_get(config->j_parameters, "templates"), lang, j_template) {
      if (json_object_get(j_template, "defaultLang") != json_true()) {
        json_array_append_new(json_object_get(j_config_register, "languages"), json_string(lang));
      }
    }
  } else {
    j_config_register = json_false();
  }
  j_config = json_pack("{sosOs{sOsO}}", 
                       "registration", j_config_register,
                       "update-email", json_object_get(config->j_parameters, "update-email")==json_true()?json_true():json_false(),
                       "reset-credentials",
                         "email", json_object_get(config->j_parameters, "reset-credentials")==json_true()&&json_object_get(config->j_parameters, "reset-credentials-email")==json_true()?json_true():json_false(),
                         "code", json_object_get(config->j_parameters, "reset-credentials")==json_true()&&json_object_get(config->j_parameters, "reset-credentials-code")==json_true()?json_true():json_false());
  if (ulfius_set_json_body_response(response, 200, j_config) != U_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_config - Error ulfius_set_json_body_response");
    response->status = 500;
  }
  json_decref(j_config);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_update_email_check_session(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  int ret = U_CALLBACK_CONTINUE;
  
  json_t * j_session = register_check_session(config, u_map_get(request->map_cookie, json_string_value(json_object_get(config->j_parameters, "session-key"))));
  if (check_result_value(j_session, G_OK)) {
    if (ulfius_set_response_shared_data(response, json_deep_copy(json_object_get(j_session, "user")), (void (*)(void *))&json_decref) != U_OK) {
      ret = U_CALLBACK_ERROR;
    }
  } else if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
    ret = U_CALLBACK_UNAUTHORIZED;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_update_email_check_session - Error register_check_session");
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

  if (j_params != NULL && !json_string_null_or_empty(json_object_get(j_params, "username")) && is_username_valid(json_string_value(json_object_get(j_params, "username"))) && (json_object_get(config->j_parameters, "email-is-username") != json_true() || is_email_valid(json_string_value(json_object_get(j_params, "username"))))) {
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
  gmtime_r(&now, &ts);
  strftime(expires, GLEWLWYD_DATE_BUFFER, "%a, %d %b %Y %T %Z", &ts);
  
  if (json_object_get(config->j_parameters, "verify-email") != json_true()) {
    if (is_username_valid(json_string_value(json_object_get(j_parameters, "username")))) {
      issued_for = get_client_hostname(request);
      if (issued_for != NULL) {
        j_result = register_new_user(config, json_string_value(json_object_get(j_parameters, "username")), issued_for, u_map_get_case(request->map_header, "user-agent"));
        if (check_result_value(j_result, G_OK)) {
          ulfius_add_same_site_cookie_to_response(response, 
                                        json_string_value(json_object_get(config->j_parameters, "session-key")), 
                                        json_string_value(json_object_get(j_result, "session")), 
                                        expires, 
                                        0, 
                                        config->glewlwyd_config->glewlwyd_config->cookie_domain, 
                                        "/", 
                                        config->glewlwyd_config->glewlwyd_config->cookie_secure, 
                                        0,
                                        config->glewlwyd_config->glewlwyd_config->cookie_same_site);
          config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_REGISTRATION_STARTED, 1, "plugin", config->name, NULL);
          y_log_message(Y_LOG_LEVEL_INFO, "Event register - Plugin '%s' - user '%s' started registration, origin: %s", config->name, json_string_value(json_object_get(j_parameters, "username")), get_ip_source(request));
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
    if (!o_strnullempty(email) && is_username_valid(username) && is_email_valid(email)) {
      issued_for = get_client_hostname(request);
      if (issued_for != NULL) {
        j_result = register_generate_email_verification_code(config, username, email, json_string_value(json_object_get(j_parameters, "lang")), json_string_value(json_object_get(j_parameters, "callback_url")), issued_for, u_map_get_case(request->map_header, "user-agent"), get_ip_source(request));
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

static int callback_register_check_email(const struct _u_request * request, struct _u_response * response, void * user_data) {
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
    if (json_string_length(json_object_get(j_parameters, "token")) == GLEWLWYD_TOKEN_LENGTH) {
      j_result = register_verify_email_token(config,
                                             json_string_value(json_object_get(j_parameters, "token")),
                                             get_ip_source(request));
      if (check_result_value(j_result, G_OK)) {
        time(&now);
        now += json_integer_value(json_object_get(config->j_parameters, "session-duration"));
        gmtime_r(&now, &ts);
        strftime(expires, GLEWLWYD_DATE_BUFFER, "%a, %d %b %Y %T %Z", &ts);
        ulfius_add_same_site_cookie_to_response(response, 
                                      json_string_value(json_object_get(config->j_parameters, "session-key")),
                                      json_string_value(json_object_get(j_result, "session")),
                                      expires,
                                      0,
                                      config->glewlwyd_config->glewlwyd_config->cookie_domain,
                                      "/",
                                      config->glewlwyd_config->glewlwyd_config->cookie_secure,
                                      0,
                                      config->glewlwyd_config->glewlwyd_config->cookie_same_site);
      } else if (check_result_value(j_result, G_ERROR_PARAM)) {
        response->status = 401;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_check_email - Error register_verify_email_token");
        response->status = 500;
      }
      json_decref(j_result);
    } else if (!o_strnullempty(email) && !o_strnullempty(username)) {
      if ((json_int_t)json_string_length(json_object_get(j_parameters, "code")) == json_integer_value(json_object_get(config->j_parameters, "verification-code-length"))) {
        j_result = register_verify_email_code(config,
                                               username,
                                               email,
                                               json_string_value(json_object_get(j_parameters, "code")),
                                               get_ip_source(request));
        if (check_result_value(j_result, G_OK)) {
          time(&now);
          now += json_integer_value(json_object_get(config->j_parameters, "session-duration"));
          gmtime_r(&now, &ts);
          strftime(expires, GLEWLWYD_DATE_BUFFER, "%a, %d %b %Y %T %Z", &ts);
          ulfius_add_same_site_cookie_to_response(response, 
                                        json_string_value(json_object_get(config->j_parameters, "session-key")),
                                        json_string_value(json_object_get(j_result, "session")),
                                        expires,
                                        0,
                                        config->glewlwyd_config->glewlwyd_config->cookie_domain,
                                        "/",
                                        config->glewlwyd_config->glewlwyd_config->cookie_secure,
                                        0,
                                        config->glewlwyd_config->glewlwyd_config->cookie_same_site);
        } else if (check_result_value(j_result, G_ERROR_PARAM)) {
          response->status = 401;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_check_email - Error register_verify_email_code");
          response->status = 500;
        }
        json_decref(j_result);
      } else {
        response->status = 401;
      }
    } else {
      response->status = 403;
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
    if (!json_string_null_or_empty(json_object_get(j_parameters, "password"))) {
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
    response->status = 403;
  }
  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_update_data(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL), * j_user = NULL, * j_result;
  
  if (json_is_string(json_object_get(j_parameters, "name")) || json_object_get(j_parameters, "name") == json_null()) {
    j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "username")));
    if (check_result_value(j_user, G_OK)) {
      json_object_del(json_object_get(j_user, "user"), "password");
      json_object_set_new(json_object_get(j_user, "user"), "name", json_is_string(json_object_get(j_parameters, "name"))?json_incref(json_object_get(j_parameters, "name")):json_string(""));
      j_result = config->glewlwyd_config->glewlwyd_plugin_callback_is_user_valid(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), json_object_get(j_user, "user"), 0);
      if (check_result_value(j_result, G_OK)) {
        if (config->glewlwyd_config->glewlwyd_plugin_callback_set_user(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), json_object_get(j_user, "user")) == G_OK) {
          if (register_user_set(config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), json_object_get(j_user, "user")) != G_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_update_data - Error register_user_set");
            response->status = 500;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_update_data - Error glewlwyd_plugin_callback_set_user");
          response->status = 500;
        }
      } else if (check_result_value(j_result, G_ERROR_PARAM)) {
        response->status = 400;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_update_data - Error glewlwyd_plugin_callback_is_user_valid");
        response->status = 500;
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_update_data - Error glewlwyd_plugin_callback_get_user");
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
    y_log_message(Y_LOG_LEVEL_INFO, "Event register - Plugin '%s' - user '%s' cancel registration, origin: %s", config->name, json_string_value(json_object_get((json_t *)response->shared_data, "username")), get_ip_source(request));
    ulfius_add_same_site_cookie_to_response(response, 
                                  json_string_value(json_object_get(config->j_parameters, "session-key")), 
                                  "", 
                                  0, 
                                  0, 
                                  config->glewlwyd_config->glewlwyd_config->cookie_domain, 
                                  "/", 
                                  config->glewlwyd_config->glewlwyd_config->cookie_secure, 
                                  0,
                                  config->glewlwyd_config->glewlwyd_config->cookie_same_site);
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_REGISTRATION_CANCELLED, 1, "plugin", config->name, NULL);
  }
  
  return U_CALLBACK_CONTINUE;
}

static int callback_register_get_scheme_registration(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL), * j_response;
  
  if (!json_string_null_or_empty(json_object_get(j_parameters, "scheme_name")) && 
      !json_string_null_or_empty(json_object_get(j_parameters, "username")) && 
      0 == o_strcmp(json_string_value(json_object_get(j_parameters, "username")), json_string_value(json_object_get((json_t *)response->shared_data, "username"))) && 
      can_register_scheme(config, request, json_string_value(json_object_get(j_parameters, "scheme_name")))) {
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
    y_log_message(Y_LOG_LEVEL_DEBUG, "callback_register_get_scheme_registration - Invalid input parameters");
    response->status = 400;
  }
  
  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_check_forbid_reset_credential(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL),
         * j_result = config->glewlwyd_config->glewlwyd_plugin_callback_get_scheme_module(config->glewlwyd_config, json_string_value(json_object_get(j_parameters, "scheme_name")));
  int ret = U_CALLBACK_CONTINUE;
  
  if (check_result_value(j_result, G_OK)) {
    if (json_object_get(json_object_get(j_result, "module"), "forbid_user_reset_credential") == json_true()) {
      response->status = 403;
      ret = U_CALLBACK_COMPLETE;
    }
  } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_check_forbid_reset_credential - Error auth_register_get_user_scheme");
    response->status = 500;
  }
  json_decref(j_parameters);
  json_decref(j_result);
  return ret;
}

static int callback_register_update_scheme_registration(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL), * j_response;
  
  if (!json_string_null_or_empty(json_object_get(j_parameters, "scheme_name")) &&
      json_is_object(json_object_get(j_parameters, "value")) &&
      !json_string_null_or_empty(json_object_get(j_parameters, "username")) &&
      0 == o_strcmp(json_string_value(json_object_get(j_parameters, "username")), json_string_value(json_object_get((json_t *)response->shared_data, "username"))) && 
      can_register_scheme(config, request, json_string_value(json_object_get(j_parameters, "scheme_name")))) {
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
  
  if (!json_string_null_or_empty(json_object_get(j_parameters, "scheme_name")) &&
      !json_string_null_or_empty(json_object_get(j_parameters, "username")) &&
      0 == o_strcmp(json_string_value(json_object_get(j_parameters, "username")), json_string_value(json_object_get((json_t *)response->shared_data, "username"))) &&
      can_register_scheme(config, request, json_string_value(json_object_get(j_parameters, "scheme_name")))) {
    ret = config->glewlwyd_config->glewlwyd_plugin_callback_scheme_can_use(config->glewlwyd_config, json_string_value(json_object_get(j_parameters, "scheme_name")), json_string_value(json_object_get((json_t *)response->shared_data, "username")));
    if (ret == GLEWLWYD_IS_NOT_AVAILABLE) {
      response->status = 403;
    } else if (ret == GLEWLWYD_IS_AVAILABLE) {
      response->status = 402;
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
      j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "username")));
      if (check_result_value(j_user, G_OK)) {
        json_object_set(json_object_get(j_user, "user"), "enabled", json_true());
        if (config->glewlwyd_config->glewlwyd_plugin_callback_set_user(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), json_object_get(j_user, "user")) == G_OK) {
          if (register_user_complete(config, json_string_value(json_object_get((json_t *)response->shared_data, "username"))) == G_OK) {
            ulfius_add_same_site_cookie_to_response(response, 
                                          json_string_value(json_object_get(config->j_parameters, "session-key")), 
                                          "", 
                                          0, 
                                          0, 
                                          config->glewlwyd_config->glewlwyd_config->cookie_domain, 
                                          "/", 
                                          config->glewlwyd_config->glewlwyd_config->cookie_secure, 
                                          0,
                                          config->glewlwyd_config->glewlwyd_config->cookie_same_site);
            y_log_message(Y_LOG_LEVEL_INFO, "Event register - Plugin '%s' - user '%s' registered, origin: %s", config->name, json_string_value(json_object_get((json_t *)response->shared_data, "username")), get_ip_source(request));
            config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_REGISTRATION_COMPLETED, 1, "plugin", config->name, NULL);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_complete_registration - Error register_user_set");
            response->status = 500;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_complete_registration - Error glewlwyd_plugin_callback_set_user");
          response->status = 500;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_complete_registration - Error glewlwyd_plugin_callback_get_user");
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

/**
 * verify that the http request is authorized based on the session
 */
static int callback_check_glewlwyd_session(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_session;
  int ret = U_CALLBACK_UNAUTHORIZED;
  
  j_session = config->glewlwyd_config->glewlwyd_callback_check_session_valid(config->glewlwyd_config, request, NULL);
  if (check_result_value(j_session, G_OK)) {
    if (ulfius_set_response_shared_data(response, json_pack("{ss}", "username", json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username"))), (void (*)(void *))&json_decref) != U_OK) {
      ret = U_CALLBACK_ERROR;
    } else {
      ret = U_CALLBACK_CONTINUE;
    }
  }
  json_decref(j_session);
  return ret;
}

static int callback_register_update_email_trigger(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL);
  char * issued_for = NULL;
  
  if (!json_string_null_or_empty(json_object_get(j_parameters, "email"))) {
    issued_for = get_client_hostname(request);
    if (issued_for != NULL) {
      if (register_update_email_trigger(config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), json_string_value(json_object_get(j_parameters, "email")), json_string_value(json_object_get(j_parameters, "lang")), issued_for, u_map_get_case(request->map_header, "user-agent"), get_ip_source(request)) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_update_email_trigger - Error register_update_email_trigger");
        response->status = 500;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_update_email_trigger - Error get_client_hostname");
      response->status = 500;
    }
    o_free(issued_for);
  } else {
    response->status = 400;
  }
  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_update_email_verify(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  int ret;
  
  if ((ret = register_update_email_verify(config, u_map_get_case(request->map_url, "token"), get_ip_source(request))) == G_ERROR_PARAM) {
    response->status = 400;
  } else if (ret != G_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_update_email_verify - Error register_update_email_verify");
    response->status = 500;
  } else {
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_EMAIL_UPDATED, 1, "plugin", config->name, NULL);
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_register_reset_credentials_check_session(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  int ret = U_CALLBACK_CONTINUE;
  
  json_t * j_session = reset_credentials_check_session(config, u_map_get(request->map_cookie, json_string_value(json_object_get(config->j_parameters, "reset-credentials-session-key"))));
  if (check_result_value(j_session, G_OK)) {
    if (ulfius_set_response_shared_data(response, json_deep_copy(json_object_get(j_session, "user")), (void (*)(void *))&json_decref) != U_OK) {
      ret = U_CALLBACK_ERROR;
    }
  } else if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
    ret = U_CALLBACK_UNAUTHORIZED;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_reset_credentials_check_session - Error reset_credentials_check_session");
    ret = U_CALLBACK_ERROR;
  }
  json_decref(j_session);
  return ret;
}

static int callback_reset_credentials_update_password(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL);
  
  if (!json_string_null_or_empty(json_object_get(j_parameters, "password"))) {
    if (config->glewlwyd_config->glewlwyd_plugin_callback_user_update_password(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), json_string_value(json_object_get(j_parameters, "password"))) == G_OK) {
      if (register_user_password_set(config, json_string_value(json_object_get((json_t *)response->shared_data, "username"))) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_reset_credentials_update_password - Error register_user_password_set");
        response->status = 500;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_reset_credentials_update_password - Error glewlwyd_plugin_callback_user_update_password");
      response->status = 500;
    }
  } else {
    response->status = 400;
  }
  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_get_profile(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_result = config->glewlwyd_config->glewlwyd_plugin_callback_get_scheme_list(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "username"))), * j_return;
  UNUSED(request);
  
  if (check_result_value(j_result, G_OK)) {
    j_return = json_pack("{s{ss}sO}", "user", "username", json_string_value(json_object_get((json_t *)response->shared_data, "username")), "scheme", json_object_get(j_result, "scheme"));
    ulfius_set_response_properties(response, U_OPT_JSON_BODY, j_return);
    json_decref(j_return);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_get_profile - Error glewlwyd_plugin_callback_get_scheme_list");
    response->status = 500;
  }
  json_decref(j_result);
  return U_CALLBACK_CONTINUE;
}

static int callback_reset_credentials_complete_registration(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  int res;
  char expires[GLEWLWYD_DATE_BUFFER+1];
  time_t now;
  struct tm ts;
  UNUSED(request);
  
  if ((res = reset_credentials_remove_session(config, u_map_get(request->map_cookie, json_string_value(json_object_get(config->j_parameters, "reset-credentials-session-key"))))) == G_OK) {
    time(&now);
    now -= 3600;
    gmtime_r(&now, &ts);
    strftime(expires, GLEWLWYD_DATE_BUFFER, "%a, %d %b %Y %T %Z", &ts);
    ulfius_add_same_site_cookie_to_response(response, 
                                  json_string_value(json_object_get(config->j_parameters, "reset-credentials-session-key")),
                                  "disabled",
                                  expires,
                                  0,
                                  config->glewlwyd_config->glewlwyd_config->cookie_domain,
                                  "/",
                                  config->glewlwyd_config->glewlwyd_config->cookie_secure,
                                  0,
                                  config->glewlwyd_config->glewlwyd_config->cookie_same_site);
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_RESET_CREDENTIALS_COMPLETED, 1, "plugin", config->name, NULL);
  } else if (res == G_ERROR_PARAM) {
    response->status = 400;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_reset_credentials_complete_registration - Error reset_credentials_remove_session");
    response->status = 500;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_register_reset_credentials_email_trigger(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL);
  char * issued_for = NULL;
  
  if (!json_string_null_or_empty(json_object_get(j_parameters, "username"))) {
    issued_for = get_client_hostname(request);
    if (issued_for != NULL) {
      if (register_reset_credentials_trigger(config, json_string_value(json_object_get(j_parameters, "username")), json_string_value(json_object_get(j_parameters, "lang")), json_string_value(json_object_get(j_parameters, "callback_url")), issued_for, u_map_get_case(request->map_header, "user-agent"), get_ip_source(request)) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_reset_credentials_email_trigger - Error register_reset_credentials_trigger");
        response->status = 500;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_reset_credentials_email_trigger - Error get_client_hostname");
      response->status = 500;
    }
    o_free(issued_for);
  } else {
    response->status = 400;
  }
  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_reset_credentials_email_verify(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_result = register_reset_credentials_check_token(config, u_map_get(request->map_url, "token")), * j_session;
  time_t now;
  struct tm ts;
  char expires[GLEWLWYD_DATE_BUFFER+1], * issued_for;
  
  if (check_result_value(j_result, G_OK)) {
    issued_for = get_client_hostname(request);
    j_session = reset_credentials_create_session(config, json_string_value(json_object_get(j_result, "username")), json_string_value(json_object_get(j_result, "callback_url")), issued_for, u_map_get_case(request->map_header, "user-agent"));
    if (check_result_value(j_session, G_OK)) {
      time(&now);
      now += json_integer_value(json_object_get(config->j_parameters, "reset-credentials-session-duration"));
      gmtime_r(&now, &ts);
      strftime(expires, GLEWLWYD_DATE_BUFFER, "%a, %d %b %Y %T %Z", &ts);
      ulfius_add_same_site_cookie_to_response(response, 
                                    json_string_value(json_object_get(config->j_parameters, "reset-credentials-session-key")), 
                                    json_string_value(json_object_get(j_session, "session")), 
                                    expires, 
                                    0, 
                                    config->glewlwyd_config->glewlwyd_config->cookie_domain, 
                                    "/", 
                                    config->glewlwyd_config->glewlwyd_config->cookie_secure, 
                                    0,
                                    config->glewlwyd_config->glewlwyd_config->cookie_same_site);
      y_log_message(Y_LOG_LEVEL_INFO, "Event register - Plugin '%s' - user '%s' opened a reset credential session with e-mail token, origin: %s", config->name, json_string_value(json_object_get(j_result, "username")), get_ip_source(request));
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_RESET_CREDENTIALS_STARTED, 1, "plugin", config->name, "verification", "email", NULL);
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_RESET_CREDENTIALS_STARTED, 1, "plugin", config->name, NULL);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_reset_credentials_email_verify - Error reset_credentials_create_session");
      response->status = 500;
    }
    json_decref(j_session);
    o_free(issued_for);
  } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
    y_log_message(Y_LOG_LEVEL_WARNING, "Security - Reset credentials - token invalid at IP Address %s", get_ip_source(request));
    response->status = 403;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_reset_credentials_email_verify - Error register_reset_credentials_check_token");
    response->status = 500;
  }
  json_decref(j_result);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_reset_credentials_code_verify(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_parameters = ulfius_get_json_body_request(request, NULL), * j_session;
  time_t now;
  struct tm ts;
  char expires[GLEWLWYD_DATE_BUFFER+1], * issued_for;
  int res;

  if ((res = reset_credentials_code_verify(config, json_string_value(json_object_get(j_parameters, "username")), json_string_value(json_object_get(j_parameters, "code")))) == G_OK) {
    issued_for = get_client_hostname(request);
    j_session = reset_credentials_create_session(config, json_string_value(json_object_get(j_parameters, "username")), NULL, issued_for, u_map_get_case(request->map_header, "user-agent"));
    if (check_result_value(j_session, G_OK)) {
      time(&now);
      now += json_integer_value(json_object_get(config->j_parameters, "reset-credentials-session-duration"));
      gmtime_r(&now, &ts);
      strftime(expires, GLEWLWYD_DATE_BUFFER, "%a, %d %b %Y %T %Z", &ts);
      ulfius_add_same_site_cookie_to_response(response, 
                                    json_string_value(json_object_get(config->j_parameters, "reset-credentials-session-key")), 
                                    json_string_value(json_object_get(j_session, "session")), 
                                    expires, 
                                    0, 
                                    config->glewlwyd_config->glewlwyd_config->cookie_domain, 
                                    "/", 
                                    config->glewlwyd_config->glewlwyd_config->cookie_secure, 
                                    0,
                                    config->glewlwyd_config->glewlwyd_config->cookie_same_site);
      y_log_message(Y_LOG_LEVEL_INFO, "Event register - Plugin '%s' - user '%s' opened a reset credential session with code, origin: %s", config->name, json_string_value(json_object_get(j_parameters, "username")), get_ip_source(request));
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_RESET_CREDENTIALS_STARTED, 1, "plugin", config->name, "verification", "code", NULL);
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_RESET_CREDENTIALS_STARTED, 1, "plugin", config->name, NULL);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_reset_credentials_code_verify - Error reset_credentials_create_session");
      response->status = 500;
    }
    json_decref(j_session);
    o_free(issued_for);
  } else if (res == G_ERROR_UNAUTHORIZED) {
    y_log_message(Y_LOG_LEVEL_WARNING, "Security - Reset credentials - code invalid at IP Address %s", get_ip_source(request));
    response->status = 403;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_reset_credentials_code_verify - Error reset_credentials_code_verify");
    response->status = 500;
  }
  json_decref(j_parameters);
  return U_CALLBACK_CONTINUE;
}

static int callback_register_reset_credentials_code_generate(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _register_config * config = (struct _register_config *)user_data;
  json_t * j_result = reset_credentials_code_generate(config, json_string_value(json_object_get((json_t *)response->shared_data, "username")));
  UNUSED(request);
  
  if (check_result_value(j_result, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_result, "code"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_register_reset_credentials_code_generate - Error reset_credentials_code_generate");
    response->status = 500;
  }
  json_decref(j_result);
  return U_CALLBACK_CONTINUE;
}

json_t * is_plugin_parameters_valid(json_t * j_params) {
  json_t * j_return, * j_errors = json_array(), * j_element = NULL, * j_template = NULL;
  size_t index = 0, has_mandatory = 0;
  const char * lang = NULL;
  int nb_default_lang = 0;

  if (j_errors != NULL) {
    if (!json_is_object(j_params)) {
      json_array_append_new(j_errors, json_string("parameters must be a JSON object"));
    } else {
      if (json_object_get(j_params, "registration") == json_true() || json_object_get(j_params, "registration") == NULL) {
        if (json_string_null_or_empty(json_object_get(j_params, "session-key"))) {
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
            if (json_string_null_or_empty(j_element)) {
              json_array_append_new(j_errors, json_string("scope is mandatory and must be a non empty array of non empty strings"));
            }
          }
        }
        if (json_object_get(j_params, "schemes") != NULL && !json_is_array(json_object_get(j_params, "schemes"))) {
          json_array_append_new(j_errors, json_string("schemes is optional and must be an array of objects"));
        } else {
          json_array_foreach(json_object_get(j_params, "schemes"), index, j_element) {
            if (json_string_null_or_empty(json_object_get(j_element, "module"))) {
              json_array_append_new(j_errors, json_string("scheme object must have a attribute 'module' with a non empty string value"));
            }
            if (json_string_null_or_empty(json_object_get(j_element, "name"))) {
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
      }
      if (json_object_get(j_params, "update-email") != NULL && !json_is_boolean(json_object_get(j_params, "update-email"))) {
        json_array_append_new(j_errors, json_string("update-email is optional and must be a boolean"));
      }
      if (json_object_get(j_params, "update-email") == json_true()) {
        if (json_integer_value(json_object_get(j_params, "update-email-token-duration")) <= 0) {
          json_array_append_new(j_errors, json_string("update-email-token-duration is mandatory and must be a positive integer"));
        }
        if (json_object_get(j_params, "update-email-from") != NULL && json_string_null_or_empty(json_object_get(j_params, "update-email-from"))) {
          json_array_append_new(j_errors, json_string("update-email-from is mandatory and must be a non empty string"));
        }
        if (json_object_get(j_params, "update-email-content-type") != NULL && json_string_null_or_empty(json_object_get(j_params, "update-email-content-type"))) {
          json_array_append_new(j_errors, json_string("update-email-content-type is optional and must be a string"));
        }
        if (!json_is_object(json_object_get(j_params, "templatesUpdateEmail"))) {
          json_array_append_new(j_errors, json_string("templatesUpdateEmail is mandatory and must be a JSON object"));
        } else {
          nb_default_lang = 0;
          json_object_foreach(json_object_get(j_params, "templatesUpdateEmail"), lang, j_template) {
            if (!json_is_object(j_template)) {
              json_array_append_new(j_errors, json_string("templatesUpdateEmail content must be a JSON object"));
            } else {
              if (!json_is_boolean(json_object_get(j_template, "defaultLang"))) {
                json_array_append_new(j_errors, json_string("defaultLang is madatory in a templatesUpdateEmail and must be a JSON object"));
              }
              if (json_object_get(j_template, "defaultLang") == json_true()) {
                nb_default_lang++;
                if (json_string_null_or_empty(json_object_get(j_template, "subject"))) {
                  json_array_append_new(j_errors, json_string("subject is mandatory for default lang and must be a non empty string"));
                }
                if (json_object_get(j_template, "body") != NULL && json_string_null_or_empty(json_object_get(j_template, "body"))) {
                  json_array_append_new(j_errors, json_string("body is mandatory for default lang and must be a non empty string"));
                }
              }
            }
          }
          if (nb_default_lang != 1) {
            json_array_append_new(j_errors, json_string("templatesUpdateEmail list must have only one defaultLang set to true"));
          }
        }
      }
      if (json_object_get(j_params, "verify-email") == json_true()) {
        if (json_integer_value(json_object_get(j_params, "verification-code-duration")) <= 0) {
          json_array_append_new(j_errors, json_string("verification-code-duration is mandatory and must be a positive integer"));
        }
        if (json_integer_value(json_object_get(j_params, "verification-code-length")) <= 0) {
          json_array_append_new(j_errors, json_string("verification-code-length is mandatory and must be a positive integer"));
        }
        if (!json_is_boolean(json_object_get(j_params, "email-is-username"))) {
          json_array_append_new(j_errors, json_string("email-is-username is optional and must be boolean"));
        }
        if (json_object_get(j_params, "content-type") != NULL && json_string_null_or_empty(json_object_get(j_params, "content-type"))) {
          json_array_append_new(j_errors, json_string("content-type is optional and must be a string"));
        }
        if (json_object_get(j_params, "from") != NULL && json_string_null_or_empty(json_object_get(j_params, "from"))) {
          json_array_append_new(j_errors, json_string("from is mandatory and must be a non empty string"));
        }
        if (json_object_get(j_params, "templates") == NULL) {
          if (json_object_get(j_params, "subject") != NULL && json_string_null_or_empty(json_object_get(j_params, "subject"))) {
            json_array_append_new(j_errors, json_string("subject is mandatory and must be a non empty string"));
          }
          if (json_object_get(j_params, "body-pattern") != NULL && json_string_null_or_empty(json_object_get(j_params, "body-pattern"))) {
            json_array_append_new(j_errors, json_string("body-pattern is mandatory and must be a non empty string"));
          }
        } else {
          if (!json_is_object(json_object_get(j_params, "templates"))) {
            json_array_append_new(j_errors, json_string("templates is mandatory and must be a JSON object"));
          } else {
            nb_default_lang = 0;
            json_object_foreach(json_object_get(j_params, "templates"), lang, j_template) {
              if (!json_is_object(j_template)) {
                json_array_append_new(j_errors, json_string("template content must be a JSON object"));
              } else {
                if (!json_is_boolean(json_object_get(j_template, "defaultLang"))) {
                  json_array_append_new(j_errors, json_string("defaultLang is madatory in a template and must be a JSON object"));
                }
                if (json_object_get(j_template, "defaultLang") == json_true()) {
                  nb_default_lang++;
                  if (json_string_null_or_empty(json_object_get(j_template, "subject"))) {
                    json_array_append_new(j_errors, json_string("subject is mandatory for default lang and must be a non empty string"));
                  }
                  if (json_object_get(j_template, "body") != NULL && json_string_null_or_empty(json_object_get(j_template, "body"))) {
                    json_array_append_new(j_errors, json_string("body is mandatory for default lang and must be a non empty string"));
                  }
                }
              }
            }
            if (nb_default_lang != 1) {
              json_array_append_new(j_errors, json_string("template list must have only one defaultLang set to true"));
            }
          }
        }
      }
      if (json_object_get(j_params, "reset-credentials") != NULL && !json_is_boolean(json_object_get(j_params, "reset-credentials"))) {
        json_array_append_new(j_errors, json_string("reset-credentials is optional and must be a boolean"));
      }
      if (json_object_get(j_params, "reset-credentials") == json_true()) {
        if (json_string_null_or_empty(json_object_get(j_params, "reset-credentials-session-key"))) {
          json_array_append_new(j_errors, json_string("reset-credentials-session-key is mandatory and must be a non empty string"));
        }
        if (json_integer_value(json_object_get(j_params, "reset-credentials-session-duration")) <= 0) {
          json_array_append_new(j_errors, json_string("reset-credentials-session-duration is optional and must be a positive integer"));
        }
        if (json_object_get(j_params, "reset-credentials-email") != NULL && !json_is_boolean(json_object_get(j_params, "reset-credentials-email"))) {
          json_array_append_new(j_errors, json_string("reset-credentials-email is optional and must be a boolean"));
        }
        if (json_object_get(j_params, "reset-credentials-email") == json_true()) {
          if (json_integer_value(json_object_get(j_params, "reset-credentials-token-duration")) <= 0) {
            json_array_append_new(j_errors, json_string("reset-credentials-token-duration is mandatory and must be a positive integer"));
          }
          if (json_object_get(j_params, "reset-credentials-from") != NULL && json_string_null_or_empty(json_object_get(j_params, "reset-credentials-from"))) {
            json_array_append_new(j_errors, json_string("reset-credentials-from is mandatory and must be a non empty string"));
          }
          if (json_object_get(j_params, "reset-credentials-content-type") != NULL && json_string_null_or_empty(json_object_get(j_params, "reset-credentials-content-type"))) {
            json_array_append_new(j_errors, json_string("reset-credentials-content-type is optional and must be a string"));
          }
          if (!json_is_object(json_object_get(j_params, "templatesResetCredentials"))) {
            json_array_append_new(j_errors, json_string("templatesResetCredentials is mandatory and must be a JSON object"));
          } else {
            nb_default_lang = 0;
            json_object_foreach(json_object_get(j_params, "templatesResetCredentials"), lang, j_template) {
              if (!json_is_object(j_template)) {
                json_array_append_new(j_errors, json_string("templatesResetCredentials content must be a JSON object"));
              } else {
                if (!json_is_boolean(json_object_get(j_template, "defaultLang"))) {
                  json_array_append_new(j_errors, json_string("defaultLang is madatory in a templatesResetCredentials and must be a JSON object"));
                }
                if (json_object_get(j_template, "defaultLang") == json_true()) {
                  nb_default_lang++;
                  if (json_string_null_or_empty(json_object_get(j_template, "subject"))) {
                    json_array_append_new(j_errors, json_string("subject is mandatory for default lang and must be a non empty string"));
                  }
                  if (json_object_get(j_template, "body") != NULL && json_string_null_or_empty(json_object_get(j_template, "body"))) {
                    json_array_append_new(j_errors, json_string("body is mandatory for default lang and must be a non empty string"));
                  }
                }
              }
            }
            if (nb_default_lang != 1) {
              json_array_append_new(j_errors, json_string("templatesUpdateEmail list must have only one defaultLang set to true"));
            }
          }
        }
        if (json_object_get(j_params, "reset-credentials-code") != NULL && !json_is_boolean(json_object_get(j_params, "reset-credentials-code"))) {
          json_array_append_new(j_errors, json_string("reset-credentials-code is optional and must be a boolean"));
        }
        if (json_object_get(j_params, "reset-credentials-code") == json_true()) {
          if (json_string_null_or_empty(json_object_get(j_params, "reset-credentials-code-property"))) {
            json_array_append_new(j_errors, json_string("reset-credentials-code-property is mandatory and must be a non empty string"));
          }
          if (json_integer_value(json_object_get(j_params, "reset-credentials-code-list-size")) <= 0) {
            json_array_append_new(j_errors, json_string("reset-credentials-code-list-size is optional and must be a positive integer"));
          }
        }
        if (json_object_get(j_params, "reset-credentials-email") != json_true() && json_object_get(j_params, "reset-credentials-code") != json_true()) {
          json_array_append_new(j_errors, json_string("At least one reset-credentials action must be enabled"));
        }
      }
      if (json_object_get(j_params, "update-email") == json_true() || json_object_get(j_params, "verify-email") == json_true() || (json_object_get(j_params, "reset-credentials") == json_true() && json_object_get(j_params, "reset-credentials-email") == json_true())) {
        if (json_string_null_or_empty(json_object_get(j_params, "host"))) {
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
      }
      if (json_object_get(j_params, "update-email") != json_true() && json_object_get(j_params, "reset-credentials") != json_true() && json_object_get(j_params, "registration") == json_false()) {
        json_array_append_new(j_errors, json_string("At least one action must be enabled"));
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

json_t * plugin_module_load(struct config_plugin * config) {
  UNUSED(config);
  return json_pack("{sissssss}",
                   "result",
                   G_OK,
                   "name",
                   "register",
                   "display_name",
                   "Register/Update e-mail/Reset credentials plugin",
                   "description",
                   "Adds self registered users in the user backend");
}

int plugin_module_unload(struct config_plugin * config) {
  UNUSED(config);
  return G_OK;
}

json_t * plugin_module_init(struct config_plugin * config, const char * name, json_t * j_parameters, void ** cls) {
  json_t * j_return, * j_result;
  struct _register_config * register_config;
  pthread_mutexattr_t mutexattr;
  int registration_ok = 1, update_email_ok = 1, reset_credentials_ok = 1;
  
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
        if (config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "config", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_config, (void*)register_config) == G_OK) {
          if (json_object_get(j_parameters, "registration") == json_true() || json_object_get(j_parameters, "registration") == NULL) {
            y_log_message(Y_LOG_LEVEL_INFO, "Add registration endpoints with plugin prefix %s", name);
            config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_REGISTRATION_STARTED, "Total number of registration started");
            config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_REGISTRATION_COMPLETED, "Total number of registration completed");
            config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_REGISTRATION_CANCELLED, "Total number of registration cancelled");
            config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_REGISTRATION_STARTED, 0, "plugin", name, NULL);
            config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_REGISTRATION_COMPLETED, 0, "plugin", name, NULL);
            config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_REGISTRATION_CANCELLED, 0, "plugin", name, NULL);
            if (config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "username", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_check_username, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "register", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_register_user, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "verify", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_send_email_verification, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "verify", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_check_email, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "*", name, "profile/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_register_update_email_check_session, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "profile/password", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_update_password, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_get_data, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_update_data, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "DELETE", name, "profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_cancel, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "profile/scheme/register", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_get_scheme_registration, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "profile/scheme/register", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_update_scheme_registration, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "profile/scheme/register/canuse", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_canuse_scheme_registration, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "profile/complete", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_complete_registration, (void*)register_config) == G_OK) {
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init register - Error glewlwyd_callback_add_plugin_endpoint");
              registration_ok = 0;
            }
          }
          if (json_object_get(j_parameters, "update-email") == json_true()) {
            config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_EMAIL_UPDATED, "Total number of e-mails updated");
            config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_EMAIL_UPDATED, 0, "plugin", name, NULL);
            if (config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "update-email", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_glewlwyd_session, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "update-email", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_update_email_trigger, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "update-email/:token", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_update_email_verify, (void*)register_config) == G_OK) {
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init update-email - Error glewlwyd_callback_add_plugin_endpoint");
              update_email_ok = 0;
            }
          }
          if (json_object_get(j_parameters, "reset-credentials") == json_true()) {
            config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_RESET_CREDENTIALS_STARTED, "Total number of reset credentials started");
            config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_RESET_CREDENTIALS_COMPLETED, "Total number of reset credentials completed");
            config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_RESET_CREDENTIALS_COMPLETED, 0, "plugin", name, NULL);
            if (config->glewlwyd_callback_add_plugin_endpoint(config, "*", name, "reset-credentials/profile/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_register_reset_credentials_check_session, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "reset-credentials/profile/password", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_reset_credentials_update_password, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "reset-credentials/profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_get_profile, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "*", name, "reset-credentials/profile/scheme/register/*", GLEWLWYD_CALLBACK_PRIORITY_PRE_APPLICATION, &callback_register_check_forbid_reset_credential, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "reset-credentials/profile/scheme/register", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_get_scheme_registration, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "reset-credentials/profile/scheme/register", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_update_scheme_registration, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "reset-credentials/profile/scheme/register/canuse", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_canuse_scheme_registration, (void*)register_config) == G_OK &&
                config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "reset-credentials/profile/complete", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_reset_credentials_complete_registration, (void*)register_config) != G_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init reset-credentials - Error glewlwyd_callback_add_plugin_endpoint");
              reset_credentials_ok = 0;
            }
            if (json_object_get(j_parameters, "reset-credentials-email") == json_true()) {
              config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_RESET_CREDENTIALS_STARTED, 0, "plugin", name, "verification", "email", NULL);
              if (config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "reset-credentials-email", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_reset_credentials_email_trigger, (void*)register_config) == G_OK &&
                  config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "reset-credentials-email/:token", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_reset_credentials_email_verify, (void*)register_config) != G_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init reset-credentials-email - Error glewlwyd_callback_add_plugin_endpoint");
                reset_credentials_ok = 0;
              }
            }
            if (json_object_get(j_parameters, "reset-credentials-code") == json_true()) {
              config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_RESET_CREDENTIALS_STARTED, 0, "plugin", name, "verification", "code", NULL);
              if (config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "reset-credentials-code", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_reset_credentials_code_verify, (void*)register_config) == G_OK &&
                  config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "reset-credentials-code", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_glewlwyd_session, (void*)register_config) == G_OK &&
                  config->glewlwyd_callback_add_plugin_endpoint(config, "PUT", name, "reset-credentials-code", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_register_reset_credentials_code_generate, (void*)register_config) != G_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init reset-credentials-code - Error glewlwyd_callback_add_plugin_endpoint");
                reset_credentials_ok = 0;
              }
            }
          }
          if (registration_ok && update_email_ok && reset_credentials_ok) {
            j_return = json_pack("{si}", "result", G_OK);
          } else {
            j_return = json_pack("{si}", "result", G_ERROR);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init register - Error setting config endpoint");
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

int plugin_module_close(struct config_plugin * config, const char * name, void * cls) {
  y_log_message(Y_LOG_LEVEL_INFO, "Close plugin Glewlwyd register '%s'", name);
  if (cls != NULL) {
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "config");
    if (json_object_get(((struct _register_config *)cls)->j_parameters, "registration") == json_true() || json_object_get(((struct _register_config *)cls)->j_parameters, "registration") == NULL) {
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
      config->glewlwyd_callback_remove_plugin_endpoint(config, "PUT", name, "profile/scheme/register");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "PUT", name, "profile/scheme/register/canuse");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "profile/complete");
    }
    if (json_object_get(((struct _register_config *)cls)->j_parameters, "update-email") == json_true()) {
      config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "update-email");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "PUT", name, "update-email/:token");
    }
    if (json_object_get(((struct _register_config *)cls)->j_parameters, "reset-credentials") == json_true()) {
      config->glewlwyd_callback_remove_plugin_endpoint(config, "*", name, "reset-credentials/profile/scheme/register/*");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "*", name, "reset-credentials/profile/*");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "reset-credentials/profile/password");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "reset-credentials/profile/");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "PUT", name, "reset-credentials/profile/scheme/register");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "reset-credentials/profile/scheme/register");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "PUT", name, "reset-credentials/profile/scheme/register/canuse");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "reset-credentials/profile/complete");
      if (json_object_get(((struct _register_config *)cls)->j_parameters, "reset-credentials-email") == json_true()) {
        config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "reset-credentials-email");
        config->glewlwyd_callback_remove_plugin_endpoint(config, "PUT", name, "reset-credentials-email/:token");
      }
      if (json_object_get(((struct _register_config *)cls)->j_parameters, "reset-credentials-code") == json_true()) {
        config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "reset-credentials-code");
        config->glewlwyd_callback_remove_plugin_endpoint(config, "PUT", name, "reset-credentials-code");
      }
    }
    o_free(((struct _register_config *)cls)->name);
    pthread_mutex_destroy(&((struct _register_config *)cls)->insert_lock);
    json_decref(((struct _register_config *)cls)->j_parameters);
    ((struct _register_config *)cls)->j_parameters = NULL;
    ((struct _register_config *)cls)->name = NULL;
    o_free(cls);
  }
  return G_OK;
}

int plugin_user_revoke(struct config_plugin * config, const char * username, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  return G_OK;
}

/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * OAuth2 authentication scheme module
 * 
 * Copyright 2020 Nicolas Mora <mail@babelouest.org>
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
#include <rhonabwy.h>
#include <iddawc.h>
#include "../glewlwyd-common.h"

#define GLEWLWYD_SCHEME_OAUTH2_REGISTRATION_TABLE "gs_oauth2_registration"
#define GLEWLWYD_SCHEME_OAUTH2_SESSION_TABLE "gs_oauth2_session"

#define GLEWLWYD_SCHEME_OAUTH2_STATE_LENGTH 32
#define GLEWLWYD_SCHEME_OAUTH2_STATE_PREFIX_REGISTRATION 'R'
#define GLEWLWYD_SCHEME_OAUTH2_STATE_PREFIX_SESSION 'S'

static int get_response_type(const char * str_type) {
  if (0 == o_strcmp("code", str_type)) {
    return I_RESPONSE_TYPE_CODE;
  } else if (o_strcmp("token", str_type)) {
    return I_RESPONSE_TYPE_TOKEN;
  } else if (o_strcmp("id_token", str_type)) {
    return I_RESPONSE_TYPE_ID_TOKEN;
  } else {
    return I_RESPONSE_TYPE_NONE;
  }
}

static json_t * is_scheme_parameters_valid(json_t * j_params) {
  json_t * j_errors = json_array(), * j_return, * j_element = NULL, * j_value = NULL;
  size_t index = 0;
  char * message;
  const char * name, * key = NULL;
  
  if (j_errors != NULL) {
    if (json_is_object(j_params)) {
      if (!json_string_length(json_object_get(j_params, "redirect_uri"))) {
        json_array_append_new(j_errors, json_string("redirect_uri is mandatory and must be a non empty string"));
      }
      if (json_integer_value(json_object_get(j_params, "session_expiration")) <= 0) {
        json_array_append_new(j_errors, json_string("session_expiration is mandatory and must be a non null positive integer"));
      }
      if (!json_is_array(json_object_get(j_params, "provider_list"))) {
        json_array_append_new(j_errors, json_string("provider_list is mandatory and must be a JSON array"));
      } else {
        json_array_foreach(json_object_get(j_params, "provider_list"), index, j_element) {
          if (!json_string_length(json_object_get(j_element, "name"))) {
            message = msprintf("name value is missing for provider at index %zu", index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
            name = NULL;
          } else if (json_string_length(json_object_get(j_element, "name")) > 128) {
            message = msprintf("name value must be 128 charcters maximum for provider at index %zu", index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          } else {
            name = json_string_value(json_object_get(j_element, "name"));
          }
          if (json_object_get(j_element, "logo_uri") != NULL && !json_string_length(json_object_get(j_element, "logo_uri"))) {
            message = msprintf("logo_uri is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "logo_fa") != NULL && !json_string_length(json_object_get(j_element, "logo_fa"))) {
            message = msprintf("logo_fa is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (!json_string_length(json_object_get(j_element, "client_id"))) {
            message = msprintf("client_id string is missing for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "response_type") != NULL && 0 != o_strcmp("code", json_string_value(json_object_get(j_element, "response_type"))) && 0 != o_strcmp("token", json_string_value(json_object_get(j_element, "response_type"))) && 0 != o_strcmp("id_token", json_string_value(json_object_get(j_element, "response_type")))) {
            message = msprintf("response_type string value for provider '%s' at index %zu is optional and must have one of the following values: 'code', 'token' or 'id_token'", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (!json_string_length(json_object_get(j_element, "userinfo_endpoint")) && !json_string_length(json_object_get(j_element, "userid_property"))) {
            message = msprintf("userid_property string is missing for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "client_secret") != NULL && !json_string_length(json_object_get(j_element, "client_secret"))) {
            message = msprintf("client_secret is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "config_endpoint") != NULL && !json_string_length(json_object_get(j_element, "config_endpoint"))) {
            message = msprintf("config_endpoint is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "auth_endpoint") != NULL && !json_string_length(json_object_get(j_element, "auth_endpoint"))) {
            message = msprintf("auth_endpoint is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "token_endpoint") != NULL && !json_string_length(json_object_get(j_element, "token_endpoint"))) {
            message = msprintf("token_endpoint is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "userinfo_endpoint") != NULL && !json_string_length(json_object_get(j_element, "userinfo_endpoint"))) {
            message = msprintf("userinfo_endpoint is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "scope") != NULL && !json_string_length(json_object_get(j_element, "scope"))) {
            message = msprintf("scope is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (!json_string_length(json_object_get(j_element, "config_endpoint")) && (!json_string_length(json_object_get(j_element, "auth_endpoint")) || !json_string_length(json_object_get(j_element, "userinfo_endpoint")))) {
            message = msprintf("You must set config_endpoint or auth_endpoint is mandatory for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "additional_parameters") != NULL) {
            if (!json_is_object(json_object_get(j_element, "additional_parameters"))) {
              message = msprintf("additional_parameters is optional and must be a JSON array for provider '%s' at index %zu", name, index);
              json_array_append_new(j_errors, json_string(message));
              o_free(message);
            } else {
              json_object_foreach(json_object_get(j_element, "additional_parameters"), key, j_value) {
                if (!json_string_length(j_value)) {
                  message = msprintf("additional_parameters value for key '%s' must be a non empty string for provider '%s' at index %zu", key, name, index);
                  json_array_append_new(j_errors, json_string(message));
                  o_free(message);
                }
              }
            }
          }
          if (json_object_get(j_element, "enabled") != NULL && !json_is_boolean(json_object_get(j_element, "enabled"))) {
            message = msprintf("enabled is optional and must be a boolean for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
        }
      }
    } else {
      json_array_append_new(j_errors, json_string("parameters must be a JSON object"));
    }
    if (json_array_size(j_errors)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_errors);
    } else {
      j_return = json_pack("{si}", "result", G_OK);
    }
    json_decref(j_errors);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_scheme_parameters_valid oauth2 - Error allocating resources for j_errors");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

static json_t * get_registration_for_user(struct config_module * config, json_t * j_params, const char * username, const char * provider) {
  json_t * j_query, * j_result = NULL, * j_return, * j_element = NULL;
  int res;
  size_t index = 0;
  
  j_query = json_pack("{sss[sss]s{sOss}}",
                      "table",
                      GLEWLWYD_SCHEME_OAUTH2_REGISTRATION_TABLE,
                      "columns",
                        "gsor_provider AS provider",
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gsor_created_at) AS created_at", "strftime('%s', gsor_created_at) AS created_at", "EXTRACT(EPOCH FROM gsor_created_at)::integer AS created_at"),
                        "gsor_enabled",
                      "where",
                        "gsor_mod_name",
                        json_object_get(j_params, "name"),
                        "gsor_username",
                        username);
  if (provider != NULL) {
    json_object_set_new(json_object_get(j_query, "where"), "gsor_provider", json_string(provider));
    json_array_append_new(json_object_get(j_query, "columns"), json_string("gsor_id"));
  }
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      json_object_set(j_element, "enabled", json_integer_value(json_object_get(j_element, "gsor_enabled"))?json_true():json_false());
      json_object_del(j_element, "gsor_enabled");
    }
    j_return = json_pack("{siso}", "result", G_OK, "registration", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_registration_for_user - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static json_t * add_registration_for_user(struct config_module * config, json_t * j_params, const char * username, const char * provider, json_t * j_provider) {
  json_t * j_query, * j_return;
  int res;
  time_t now;
  char * expires_at_clause, state[GLEWLWYD_SCHEME_OAUTH2_STATE_LENGTH+1], * i_export;
  struct _i_session i_session;
  
  if (i_init_session(&i_session) == I_OK) {
    if (i_import_session_json_t(&i_session, json_object_get(j_provider, "export")) == I_OK) {
      if (i_set_int_parameter(&i_session, I_OPT_STATE_GENERATE, GLEWLWYD_SCHEME_OAUTH2_STATE_LENGTH) == I_OK) {
        o_strncpy(state, i_get_str_parameter(&i_session, I_OPT_STATE), GLEWLWYD_SCHEME_OAUTH2_STATE_LENGTH);
        state[0] = GLEWLWYD_SCHEME_OAUTH2_STATE_PREFIX_REGISTRATION;
        i_set_str_parameter(&i_session, I_OPT_STATE, state);
        if (i_build_auth_url_get(&i_session) == I_OK) {
          i_export = i_export_session_str(&i_session);
          j_query = json_pack("{sss{sOsssssssi}}",
                              "table",
                              GLEWLWYD_SCHEME_OAUTH2_REGISTRATION_TABLE,
                              "values",
                                "gsor_mod_name",
                                json_object_get(j_params, "name"),
                                "gsor_provider",
                                provider,
                                "gsor_username",
                                username,
                                "gsor_userinfo_sub",
                                "",
                                "gsor_enabled",
                                1);
          res = h_insert(config->conn, j_query, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            time(&now);
            if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
              expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)json_integer_value(json_object_get(j_params, "session_expiration"))));
            } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
              expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)json_integer_value(json_object_get(j_params, "session_expiration"))));
            } else { // HOEL_DB_TYPE_SQLITE
              expires_at_clause = msprintf("%u", (now + (unsigned int)json_integer_value(json_object_get(j_params, "session_expiration"))));
            }
            j_query = json_pack("{sss{sOs{ss}sssi}}",
                                "table",
                                GLEWLWYD_SCHEME_OAUTH2_SESSION_TABLE,
                                "values",
                                  "gsor_id",
                                  json_object_get(json_object_get(j_provider, "provider"), "gsor_id"),
                                  "gsos_expires_at",
                                    "raw",
                                    expires_at_clause,
                                  "gsos_state",
                                  state,
                                  "gsos_session_export",
                                  i_export,
                                  "gsos_status",
                                  1);
            o_free(expires_at_clause);
            res = h_insert(config->conn, j_query, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              j_return = json_pack("{siss}", "result", G_OK, "registration", i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "add_registration_for_user - Error executing j_query (2)");
              j_return = json_pack("{si}", "result", G_ERROR_DB);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "add_registration_for_user - Error executing j_query (1)");
            j_return = json_pack("{si}", "result", G_ERROR_DB);
          }
          o_free(i_export);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "add_registration_for_user - Error i_build_auth_url_get");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_registration_for_user - Error i_set_int_parameter I_OPT_STATE_GENERATE");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_registration_for_user - Error i_import_session_json_t");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    i_clean_session(&i_session);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_registration_for_user - Error i_init_session");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

static int complete_registration_for_user(struct config_module * config, json_t * j_params, json_t * j_provider, const char * redirect_to, const char * state) {
  UNUSED(j_params);
  json_t * j_query, * j_result = NULL;
  int res, ret;
  time_t now;
  char * expires_at_clause;
  struct _i_session i_session;
  const char * sub = NULL;
  
  time(&now);
  if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
    expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
  } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
    expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
  } else { // HOEL_DB_TYPE_SQLITE
    expires_at_clause = msprintf("> %u", (now));
  }
  j_query = json_pack("{sss[ss]s{sss{ssss}sisO}}",
                      "table",
                      GLEWLWYD_SCHEME_OAUTH2_SESSION_TABLE,
                      "columns",
                        "gsos_id",
                        "gsos_session_export",
                      "where",
                        "gsos_state",
                        state,
                        "gsos_expires_at",
                          "operator",
                          "raw",
                          "value",
                          expires_at_clause,
                        "gsos_status",
                        1,
                        "gsor_id",
                        json_object_get(j_provider, "gsor_id"));
  o_free(expires_at_clause);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      if (i_init_session(&i_session) == I_OK) {
        if (i_import_session_json_t(&i_session, json_object_get(json_array_get(j_result, 0), "gsos_session_export")) == I_OK) {
          i_set_str_parameter(&i_session, I_OPT_REDIRECT_TO, redirect_to);
          if (i_parse_redirect_to(&i_session) == I_OK) {
            switch (i_get_response_type(&i_session)) {
              case I_RESPONSE_TYPE_CODE:
                if (i_run_token_request(&i_session) == I_OK) {
                  ret = G_OK;
                  if (json_string_length(json_object_get(i_session.id_token_payload, "sub"))) {
                    sub = json_string_value(json_object_get(i_session.id_token_payload, "sub"));
                  } else {
                    if (i_load_userinfo(&i_session) == I_OK) {
                      sub = json_string_value(json_object_get(i_session.j_userinfo, json_string_value(json_object_get(j_provider, "userid_property"))));
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error i_load_userinfo (1)");
                      ret = G_ERROR;
                    }
                  }
                  if (ret == G_OK) {
                    if (sub != NULL) {
                      j_query = json_pack("{sss{ss}s{sO}}",
                                          "table",
                                          GLEWLWYD_SCHEME_OAUTH2_REGISTRATION_TABLE,
                                          "set",
                                            "gsor_userinfo_sub",
                                            sub,
                                          "where",
                                            "gsor_id",
                                            json_object_get(j_provider, "gsor_id"));
                      res = h_update(config->conn, j_query, NULL);
                      json_decref(j_query);
                      if (res != H_OK) {
                        y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error executing j_query (2)");
                        ret = G_ERROR_DB;
                      }
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error getting userid value");
                      ret = G_ERROR_PARAM;
                    }
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error i_run_token_request");
                  ret = G_ERROR;
                }
                break;
              case I_RESPONSE_TYPE_TOKEN:
                if (i_load_userinfo(&i_session) == I_OK) {
                  sub = json_string_value(json_object_get(i_session.j_userinfo, json_string_value(json_object_get(j_provider, "userid_property"))));
                  if (sub != NULL) {
                    j_query = json_pack("{sss{ss}s{sO}}",
                                        "table",
                                        GLEWLWYD_SCHEME_OAUTH2_REGISTRATION_TABLE,
                                        "set",
                                          "gsor_userinfo_sub",
                                          sub,
                                        "where",
                                          "gsor_id",
                                          json_object_get(j_provider, "gsor_id"));
                    res = h_update(config->conn, j_query, NULL);
                    json_decref(j_query);
                    if (res != H_OK) {
                      y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error executing j_query (2)");
                      ret = G_ERROR_DB;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error getting userid value");
                    ret = G_ERROR_PARAM;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error i_load_userinfo (2)");
                  ret = G_ERROR;
                }
                break;
              case I_RESPONSE_TYPE_ID_TOKEN:
                if (json_string_length(json_object_get(i_session.id_token_payload, "sub"))) {
                  j_query = json_pack("{sss{ss}s{sO}}",
                                      "table",
                                      GLEWLWYD_SCHEME_OAUTH2_REGISTRATION_TABLE,
                                      "set",
                                        "gsor_userinfo_sub",
                                        json_string_value(json_object_get(i_session.id_token_payload, "sub")),
                                      "where",
                                        "gsor_id",
                                        json_object_get(j_provider, "gsor_id"));
                  res = h_update(config->conn, j_query, NULL);
                  json_decref(j_query);
                  if (res != H_OK) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error executing j_query (2)");
                    ret = G_ERROR_DB;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error getting userid value");
                  ret = G_ERROR_PARAM;
                }
                break;
            }
            j_query = json_pack("{sss{si}s{sO}}",
                                "table",
                                GLEWLWYD_SCHEME_OAUTH2_SESSION_TABLE,
                                "set",
                                  "gsos_status",
                                  0,
                                "where",
                                  "gsos_id",
                                  json_object_get(json_array_get(j_result, 0), "gsos_session_export"));
            res = h_update(config->conn, j_query, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              ret = G_OK;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error executing j_query (3)");
              ret = G_ERROR_DB;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error i_parse_redirect_to");
            ret = G_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error i_import_session_json_t");
          ret = G_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error i_init_session");
        ret = G_ERROR;
      }
      i_clean_session(&i_session);
    } else {
      ret = G_ERROR_NOT_FOUND;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "complete_registration_for_user - Error executing j_query (1)");
    ret = G_ERROR_DB;
  }
  return ret;
}

static json_t * get_provider(json_t * j_params, const char * provider_name) {
  json_t * j_element = NULL, * j_return = NULL;
  size_t index = 0;
  
  json_array_foreach(json_object_get(j_params, "provider_list"), index, j_element) {
    if (j_return == NULL && 0 == o_strcmp(json_string_value(json_object_get(j_element, "name")), provider_name) && json_object_get(j_element, "enabled") != json_false()) {
      j_return = json_pack("{sisO}", "result", G_OK, "provider", j_element);
    }
  }
  if (j_return == NULL) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

/**
 * 
 * user_auth_scheme_module_load
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
json_t * user_auth_scheme_module_load(struct config_module * config) {
  UNUSED(config);
  return json_pack("{sisssssss{s{ssso}s[{s{ssso}s{sss[sss]so}s{ssso}s{ssso}s{ssso}s{ssso}s{ssso}s{ssso}s{ssso}s{ssso}s{ssso}}]}}",
                   "result",
                   G_OK,
                   "name",
                   "oauth2",
                   "display_name",
                   "OAuth2 Client",
                   "description",
                   "OAuth2 Client scheme",
                   "parameters",
                     "redirect_uri",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                     "provider_list",
                       "name",
                         "type",
                         "string",
                         "mandatory",
                         json_true(),
                       "response_type",
                         "type",
                         "list",
                         "values",
                           "code",
                           "token",
                           "id_token",
                         "mandatory",
                         json_false(),
                       "client_id",
                         "type",
                         "string",
                         "mandatory",
                         json_true(),
                       "client_secret",
                         "type",
                         "string",
                         "mandatory",
                         json_false(),
                       "config_endpoint",
                         "type",
                         "string",
                         "mandatory",
                         json_false(),
                       "auth_endpoint",
                         "type",
                         "string",
                         "mandatory",
                         json_false(),
                       "token_endpoint",
                         "type",
                         "string",
                         "mandatory",
                         json_false(),
                       "userinfo_endpoint",
                         "type",
                         "string",
                         "mandatory",
                         json_false(),
                       "scope",
                         "type",
                         "string",
                         "mandatory",
                         json_false(),
                       "userid_property",
                         "type",
                         "string",
                         "mandatory",
                         json_true(),
                       "enabled",
                         "type",
                         "boolean",
                         "mandatory",
                         json_false());
}

/**
 * 
 * user_auth_scheme_module_unload
 * 
 * Executed once when Glewlwyd service is stopped
 * You can also use it to release resources that are required once for all
 * instance modules for example
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * 
 */
int user_auth_scheme_module_unload(struct config_module * config) {
  UNUSED(config);
  return G_OK;
}

/**
 * 
 * user_auth_scheme_module_init
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
 * @parameter mod_name: module name in glewlwyd service
 * @parameter cls: will contain an allocated void * pointer that will be sent back
 *                 as void * in all module functions
 * 
 */
json_t * user_auth_scheme_module_init(struct config_module * config, json_t * j_parameters, const char * mod_name, void ** cls) {
  UNUSED(config);
  UNUSED(mod_name);
  UNUSED(config);
  json_t * j_result, * j_return, * j_element = NULL, * j_export;
  const char * key = NULL;
  char * str_error;
  size_t index = 0;
  struct _i_session i_session;
  
  j_result = is_scheme_parameters_valid(j_parameters);
  if (check_result_value(j_result, G_OK)) {
    *cls = json_pack("{sssOs[]}", "name", mod_name, "redirect_uri", json_object_get(j_parameters, "redirect_uri"), "provider_list");
    if (*cls != NULL) {
      json_array_foreach(json_object_get(j_parameters, "provider_list"), index, j_element) {
        if (json_object_get(j_element, "enabled") != json_false()) {
          if (i_init_session(&i_session) == I_OK) {
            json_object_foreach(json_object_get(j_element, "additional_parameters"), key, j_element) {
              i_set_additional_parameter(&i_session, key, json_string_value(j_element));
            }
            if (json_string_length(json_object_get(j_element, "config_endpoint"))) {
              if (i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, get_response_type,
                                                                    I_OPT_OPENID_CONFIG_ENDPOINT, json_string_value(json_object_get(j_element, "config_endpoint")),
                                                                    I_OPT_CLIENT_ID, json_string_value(json_object_get(j_element, "client_id")),
                                                                    I_OPT_CLIENT_SECRET, json_string_value(json_object_get(j_element, "client_secret")),
                                                                    I_OPT_REDIRECT_URI, json_string_value(json_object_get(j_element, "redirect_uri")),
                                                                    I_OPT_SCOPE, json_string_value(json_object_get(j_element, "scope")),
                                                                    I_OPT_STATE_GENERATE, 16,
                                                                    I_OPT_NONCE_GENERATE, 32,
                                                                    I_OPT_NONE) != I_OK) {
                y_log_message(Y_LOG_LEVEL_DEBUG, "user_auth_scheme_module_init oauth2 - Error setting parameters for provider %s", json_string_value(json_object_get(j_element, "name")));
              } else if (i_load_openid_config(&i_session) != I_OK) {
                y_log_message(Y_LOG_LEVEL_DEBUG, "user_auth_scheme_module_init oauth2 - Error loading openid-configuration for provider %s", json_string_value(json_object_get(j_element, "name")));
              } else if ((j_export = i_export_session_json_t(&i_session)) == NULL) {
                y_log_message(Y_LOG_LEVEL_DEBUG, "user_auth_scheme_module_init oauth2 - Error exporting session for provider %s", json_string_value(json_object_get(j_element, "name")));
              } else {
                json_object_set(j_element, "export", j_export);
                json_array_append_new(json_object_get(((json_t *)*cls), "provider_list"), j_element);
              }
              json_decref(j_export);
            } else {
              if (i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                                    I_OPT_AUTH_ENDPOINT, json_string_value(json_object_get(j_element, "auth_endpoint")),
                                                                    I_OPT_TOKEN_ENDPOINT, json_string_value(json_object_get(j_element, "token_endpoint")),
                                                                    I_OPT_USERINFO_ENDPOINT, json_string_value(json_object_get(j_element, "userinfo_endpoint")),
                                                                    I_OPT_CLIENT_ID, json_string_value(json_object_get(j_element, "client_id")),
                                                                    I_OPT_CLIENT_SECRET, json_string_value(json_object_get(j_element, "client_secret")),
                                                                    I_OPT_REDIRECT_URI, json_string_value(json_object_get(j_element, "redirect_uri")),
                                                                    I_OPT_SCOPE, json_string_value(json_object_get(j_element, "scope")),
                                                                    I_OPT_STATE_GENERATE, 16,
                                                                    I_OPT_NONE) != I_OK) {
                y_log_message(Y_LOG_LEVEL_DEBUG, "user_auth_scheme_module_init oauth2 - Error setting parameters for provider %s", json_string_value(json_object_get(j_element, "name")));
              } else if ((j_export = i_export_session_json_t(&i_session)) == NULL) {
                y_log_message(Y_LOG_LEVEL_DEBUG, "user_auth_scheme_module_init oauth2 - Error exporting session for provider %s", json_string_value(json_object_get(j_element, "name")));
              } else {
                json_object_set(j_element, "export", j_export);
                json_array_append_new(json_object_get(((json_t *)*cls), "provider_list"), j_element);
              }
              json_decref(j_export);
            }
            i_clean_session(&i_session);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init oauth2 - Error i_init_session");
          }
        }
      }
      j_return = json_pack("{si}", "result", G_OK);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init oauth2 - Error allocating resources for *cls");
      j_return = json_pack("{si}", "result", G_OK);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init oauth2 - Error in parameters");
    str_error = json_dumps(json_object_get(j_result, "error"), JSON_ENCODE_ANY);
    y_log_message(Y_LOG_LEVEL_ERROR, str_error);
    o_free(str_error);
    j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", json_object_get(j_result, "error"));
  }
  return j_return;
}

/**
 * 
 * user_auth_scheme_module_close
 * 
 * Close an instance of this module declared in Glewlwyd service.
 * You must free the memory previously allocated in
 * the user_auth_scheme_module_init function as void * cls
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_close(struct config_module * config, void * cls) {
  UNUSED(config);
  json_decref((json_t *)cls);
  return G_OK;
}

/**
 * 
 * user_auth_scheme_module_can_use
 * 
 * Validate if the user is allowed to use this scheme prior to the
 * authentication or registration
 * 
 * @return value: GLEWLWYD_IS_REGISTERED - User can use scheme and has registered
 *                GLEWLWYD_IS_AVAILABLE - User can use scheme but hasn't registered
 *                GLEWLWYD_IS_NOT_AVAILABLE - User can't use scheme
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: username to identify the user
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_can_use(struct config_module * config, const char * username, void * cls) {
  int ret;
  json_t * j_registration = get_registration_for_user(config, (json_t *)cls, username, NULL), * j_element = NULL;
  size_t index = 0;
  
  if (check_result_value(j_registration, G_OK)) {
    ret = GLEWLWYD_IS_AVAILABLE;
    json_array_foreach(json_object_get(j_registration, "registration"), index, j_element) {
      if (json_object_get(j_element, "enabled") == json_true()) {
        ret = GLEWLWYD_IS_REGISTERED;
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_can_use - Error get_registration_for_user");
    ret = GLEWLWYD_IS_NOT_AVAILABLE;
  }
  return ret;
}

/**
 * 
 * user_auth_scheme_module_register
 * 
 * Register the scheme for a user
 * Ex: add a certificate, add new TOTP values, etc.
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  response: JSON object, optional
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the HTTP API
 * @parameter username: username to identify the user
 * @parameter j_scheme_data: additional data used to register the scheme for the user
 *                           in JSON format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
json_t * user_auth_scheme_module_register(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls) {
  UNUSED(http_request);
  json_t * j_return, * j_result, * j_provider, * j_register;
  int res;
  
  if (json_is_object(j_scheme_data)) {
    j_provider = get_provider((json_t *)cls, json_string_value(json_object_get(j_scheme_data, "provider")));
    if (check_result_value(j_provider, G_OK)) {
      if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "action")), "new")) {
        j_result = get_registration_for_user(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "provider")));
        if (check_result_value(j_result, G_OK)) {
          if (!json_array_size(json_object_get(j_result, "registration"))) {
            j_register = add_registration_for_user(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "provider")), json_array_get(json_object_get(j_result, "registration"), 0));
            if (check_result_value(j_register, G_OK)) {
              j_return = json_pack("{sisO}", "result", G_OK, "response", json_object_get(j_register, "registration"));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register oauth2 - Error add_registration_for_user");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
            json_decref(j_register);
          } else {
            j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "provider already registered");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register oauth2 - Error get_registration_for_user");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_result);
      } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "action")), "callback")) {
        j_result = get_registration_for_user(config, (json_t *)cls, username, json_string_value(json_object_get(j_scheme_data, "provider")));
        if (check_result_value(j_result, G_OK)) {
          if (json_string_length(json_object_get(j_scheme_data, "redirect_to")) && json_string_length(json_object_get(j_scheme_data, "state")) && json_string_value(json_object_get(j_scheme_data, "state"))[0] == GLEWLWYD_SCHEME_OAUTH2_STATE_PREFIX_REGISTRATION) {
            if ((res = complete_registration_for_user(config, (json_t *)cls, json_array_get(json_object_get(j_result, "registration"), 0), json_string_value(json_object_get(j_scheme_data, "redirect_to")), json_string_value(json_object_get(j_scheme_data, "state")))) == G_OK) {
              j_return = json_pack("{si}", "result", G_OK);
            } else if (res == G_ERROR_PARAM || res == G_ERROR_UNAUTHORIZED) {
              j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "Registration completion invalid");
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register oauth2 - Error complete_registration_for_user");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
          } else {
            j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "input parameters invalid");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register oauth2 - Error get_registration_for_user");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_result);
      } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "action")), "test")) {
      } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "action")), "test-callback")) {
      } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "action")), "delete")) {
      } else {
        j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "action invalid");
      }
    } else {
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "provider invalid");
    }
    json_decref(j_provider);
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "data must be a JSON object");
  }

  return j_return;
}

/**
 * 
 * user_auth_scheme_module_deregister
 * 
 * Deregister all the scheme data for a user
 * Ex: remove certificates, TOTP values, etc.
 * 
 * @return value: G_OK on success, even if no data has been removed
 *                G_ERROR on another error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: username to identify the user
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_deregister(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  
  return G_ERROR;
}

/**
 * 
 * user_auth_scheme_module_register_get
 * 
 * Get the registration value(s) of the scheme for a user
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  response: JSON object, optional
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
json_t * user_auth_scheme_module_register_get(struct config_module * config, const struct _u_request * http_request, const char * username, void * cls) {
  UNUSED(config);
  UNUSED(http_request);
  UNUSED(username);
  UNUSED(cls);

  return json_pack("{si}", "result", G_ERROR);
}

/**
 * 
 * user_auth_scheme_module_trigger
 * 
 * Trigger the scheme for a user
 * Ex: send the code to a device, generate a challenge, etc.
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  response: JSON object, optional
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter scheme_trigger: data sent to trigger the scheme for the user
 *                           in JSON format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
json_t * user_auth_scheme_module_trigger(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_trigger, void * cls) {
  UNUSED(config);
  UNUSED(http_request);
  UNUSED(username);
  UNUSED(j_scheme_trigger);
  UNUSED(cls);

  return json_pack("{si}", "result", G_ERROR);
}

/**
 * 
 * user_auth_scheme_module_validate
 * 
 * Validate the scheme for a user
 * Ex: check the code sent to a device, verify the challenge, etc.
 * 
 * @return value: G_OK on success
 *                G_ERROR_UNAUTHORIZED if validation fails
 *                G_ERROR_PARAM if error in parameters
 *                G_ERROR on another error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter j_scheme_data: data sent to validate the scheme for the user
 *                           in JSON format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_validate(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls) {
  UNUSED(config);
  UNUSED(http_request);
  UNUSED(username);
  UNUSED(j_scheme_data);
  UNUSED(cls);
  
  return G_ERROR;
}

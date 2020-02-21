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

#define GLEWLWYD_SCHEME_OAUTH2_STATE_ID_LENGTH    32
#define GLEWLWYD_SCHEME_OAUTH2_NONCE_LENGTH       16
#define GLEWLWYD_SCHEME_OAUTH2_STATE_REGISTRATION   "registration"
#define GLEWLWYD_SCHEME_OAUTH2_STATE_AUTHENTICATION "authentication"

#define GLEWLWYD_SCHEME_OAUTH2_SESSION_REGISTRATION   0
#define GLEWLWYD_SCHEME_OAUTH2_SESSION_AUTHENTICATION 1
#define GLEWLWYD_SCHEME_OAUTH2_SESSION_VERIFIED       2
#define GLEWLWYD_SCHEME_OAUTH2_SESSION_CANCELLED      3

struct _oauth2_config {
  pthread_mutex_t insert_lock;
  json_t * j_parameters;
};

static int get_response_type(const char * str_type) {
  if (0 == o_strcmp("code", str_type)) {
    return I_RESPONSE_TYPE_CODE;
  } else if (0 == o_strcmp("token", str_type)) {
    return I_RESPONSE_TYPE_TOKEN;
  } else if (0 == o_strcmp("id_token", str_type)) {
    return I_RESPONSE_TYPE_ID_TOKEN;
  } else {
    return I_RESPONSE_TYPE_NONE;
  }
}

static json_t * is_scheme_parameters_valid(json_t * j_params) {
  json_t * j_errors = json_array(), * j_return, * j_element = NULL, * j_param = NULL;
  size_t index = 0, indexParam = 0;
  char * message;
  const char * name;
  int is_oidc = 0;
  
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
          if (0 != o_strcmp("oauth2", json_string_value(json_object_get(j_element, "provider_type"))) && 0 != o_strcmp("oidc", json_string_value(json_object_get(j_element, "provider_type")))) {
            message = msprintf("provider_type string value for provider '%s' at index %zu is mandatory and must have one of the following values: 'oauth2' or 'oidc'", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          is_oidc = o_strcmp("oauth2", json_string_value(json_object_get(j_element, "provider_type")));
          if (json_object_get(j_element, "logo_uri") != NULL && !json_is_string(json_object_get(j_element, "logo_uri"))) {
            message = msprintf("logo_uri is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "logo_fa") != NULL && !json_is_string(json_object_get(j_element, "logo_fa"))) {
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
          if (!is_oidc && !json_string_length(json_object_get(j_element, "userid_property"))) {
            message = msprintf("userid_property string is missing for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "client_secret") != NULL && !json_is_string(json_object_get(j_element, "client_secret"))) {
            message = msprintf("client_secret is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (is_oidc && json_object_get(j_element, "config_endpoint") != NULL && !json_is_string(json_object_get(j_element, "config_endpoint"))) {
            message = msprintf("config_endpoint is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "auth_endpoint") != NULL && !json_is_string(json_object_get(j_element, "auth_endpoint"))) {
            message = msprintf("auth_endpoint is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "token_endpoint") != NULL && !json_is_string(json_object_get(j_element, "token_endpoint"))) {
            message = msprintf("token_endpoint is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "userinfo_endpoint") != NULL && !json_is_string(json_object_get(j_element, "userinfo_endpoint"))) {
            message = msprintf("userinfo_endpoint is optional and must be a string for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (json_object_get(j_element, "scope") != NULL && !json_is_string(json_object_get(j_element, "scope"))) {
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
            if (!json_is_array(json_object_get(j_element, "additional_parameters"))) {
              message = msprintf("additional_parameters is optional and must be a JSON array for provider '%s' at index %zu", name, index);
              json_array_append_new(j_errors, json_string(message));
              o_free(message);
            } else {
              json_array_foreach(json_object_get(j_element, "additional_parameters"), indexParam, j_param) {
                if (!json_string_length(json_object_get(j_param, "key"))) {
                  message = msprintf("additional_parameters key must be a non empty string for provider '%s' at index %zu", name, index);
                  json_array_append_new(j_errors, json_string(message));
                  o_free(message);
                }
                if (!json_string_length(json_object_get(j_param, "value"))) {
                  message = msprintf("additional_parameters value must be a non empty string for provider '%s' at index %zu", name, index);
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

static json_t * add_session_for_user(struct config_module * config, struct _oauth2_config * oauth2_config, const char * username, json_t * j_registration, json_t * j_provider, const char * callback_url) {
  json_t * j_query, * j_state = NULL, * j_return;
  int res;
  time_t now;
  char * expires_at_clause, * i_export, * state_export = NULL, * state_export_b64 = NULL;
  struct _i_session i_session;
  size_t state_export_b64_len = 0;
  
  time(&now);
  if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
    expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
  } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
    expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
  } else { // HOEL_DB_TYPE_SQLITE
    expires_at_clause = msprintf("> %u", (now));
  }
  j_query = json_pack("{sss{si}s{sOsis{ssss}}}",
                      "table",
                      GLEWLWYD_SCHEME_OAUTH2_SESSION_TABLE,
                      "set",
                        "gsos_status",
                        GLEWLWYD_SCHEME_OAUTH2_SESSION_CANCELLED,
                      "where",
                        "gsor_id",
                        json_object_get(j_registration, "gsor_id"),
                        "gsos_status",
                        GLEWLWYD_SCHEME_OAUTH2_SESSION_AUTHENTICATION,
                        "gsos_expires_at",
                          "operator",
                          "raw",
                          "value",
                          expires_at_clause);
  o_free(expires_at_clause);
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (i_init_session(&i_session) == I_OK) {
      if (i_import_session_json_t(&i_session, json_object_get(j_provider, "export")) == I_OK) {
        if (i_set_int_parameter(&i_session, I_OPT_STATE_GENERATE, GLEWLWYD_SCHEME_OAUTH2_STATE_ID_LENGTH) == I_OK && i_set_int_parameter(&i_session, I_OPT_NONCE_GENERATE, GLEWLWYD_SCHEME_OAUTH2_NONCE_LENGTH) == I_OK) {
          j_state = json_pack("{sssssOsOssss*}", "id", i_get_str_parameter(&i_session, I_OPT_STATE), "type", GLEWLWYD_SCHEME_OAUTH2_STATE_AUTHENTICATION, "module", json_object_get(oauth2_config->j_parameters, "name"), "provider", json_object_get(j_provider, "name"), "username", username, "callback_url", callback_url);
          state_export = json_dumps(j_state, JSON_COMPACT);
          if ((state_export_b64 = o_malloc(2*o_strlen(state_export))) != NULL) {
            if (o_base64url_encode((const unsigned char *)state_export, o_strlen(state_export), (unsigned char *)state_export_b64, &state_export_b64_len)) {
              i_set_str_parameter(&i_session, I_OPT_STATE, state_export_b64);
              if (i_build_auth_url_get(&i_session) == I_OK) {
                time(&now);
                if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
                  expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)json_integer_value(json_object_get(oauth2_config->j_parameters, "session_expiration"))));
                } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
                  expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)json_integer_value(json_object_get(oauth2_config->j_parameters, "session_expiration"))));
                } else { // HOEL_DB_TYPE_SQLITE
                  expires_at_clause = msprintf("%u", (now + (unsigned int)json_integer_value(json_object_get(oauth2_config->j_parameters, "session_expiration"))));
                }
                i_export = i_export_session_str(&i_session);
                j_query = json_pack("{sss{sOs{ss}sssssi}}",
                                    "table",
                                    GLEWLWYD_SCHEME_OAUTH2_SESSION_TABLE,
                                    "values",
                                      "gsor_id",
                                       json_object_get(j_registration, "gsor_id"),
                                      "gsos_expires_at",
                                        "raw",
                                        expires_at_clause,
                                      "gsos_state",
                                      state_export_b64,
                                      "gsos_session_export",
                                      i_export,
                                      "gsos_status",
                                      GLEWLWYD_SCHEME_OAUTH2_SESSION_AUTHENTICATION);
                o_free(expires_at_clause);
                res = h_insert(config->conn, j_query, NULL);
                json_decref(j_query);
                o_free(i_export);
                if (res == H_OK) {
                  j_return = json_pack("{siss}", "result", G_OK, "session", i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO));
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "add_session_for_user - Error executing j_query (2)");
                  j_return = json_pack("{si}", "result", G_ERROR_DB);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "add_session_for_user - Error i_build_auth_url_get");
                j_return = json_pack("{si}", "result", G_ERROR);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "add_session_for_user - Error o_base64url_encode");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "add_session_for_user - Error o_malloc state_export_b64");
            j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
          }
          o_free(state_export);
          o_free(state_export_b64);
          json_decref(j_state);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "add_session_for_user - Error i_set_int_parameter I_OPT_STATE_GENERATE");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_session_for_user - Error i_import_session_json_t");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      i_clean_session(&i_session);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_session_for_user - Error i_init_session");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_session_for_user - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static json_t * get_last_session_for_registration(struct config_module * config, json_int_t gsor_id) {
  json_t * j_query, * j_result = NULL, * j_return;
  int res;
  
  j_query = json_pack("{sss[s]s{sIsi}sssi}",
                      "table",
                      GLEWLWYD_SCHEME_OAUTH2_SESSION_TABLE,
                      "columns",
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gsos_created_at) AS last_session", "strftime('%s', gsos_created_at) AS last_session", "EXTRACT(EPOCH FROM gsos_created_at)::integer AS last_session"),
                      "where",
                        "gsor_id",
                        gsor_id,
                        "gsos_status",
                        GLEWLWYD_SCHEME_OAUTH2_SESSION_VERIFIED,
                      "order_by",
                        "gsos_created_at DESC",
                      "limit",
                        1);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      j_return = json_pack("{sisO}", "result", G_OK, "last_session", json_object_get(json_array_get(j_result, 0), "last_session"));
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_last_session_for_registration - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static json_t * get_registration_for_user(struct config_module * config, struct _oauth2_config * oauth2_config, const char * username, const char * provider) {
  json_t * j_query, * j_result = NULL, * j_return, * j_element = NULL, * j_session;
  int res;
  size_t index = 0;
  
  j_query = json_pack("{sss[ssss]s{sOss}}",
                      "table",
                      GLEWLWYD_SCHEME_OAUTH2_REGISTRATION_TABLE,
                      "columns",
                        "gsor_id",
                        "gsor_provider AS provider",
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gsor_created_at) AS created_at", "strftime('%s', gsor_created_at) AS created_at", "EXTRACT(EPOCH FROM gsor_created_at)::integer AS created_at"),
                        "gsor_userinfo_sub AS sub",
                      "where",
                        "gsor_mod_name",
                        json_object_get(oauth2_config->j_parameters, "name"),
                        "gsor_username",
                        username);
  if (provider != NULL) {
    json_object_set_new(json_object_get(j_query, "where"), "gsor_provider", json_string(provider));
  }
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      json_array_foreach(j_result, index, j_element) {
        j_session = get_last_session_for_registration(config, json_integer_value(json_object_get(j_element, "gsor_id")));
        if (check_result_value(j_session, G_OK)) {
          json_object_set(j_element, "last_session", json_object_get(j_session, "last_session"));
        } else {
          if (!check_result_value(j_session, G_ERROR_NOT_FOUND)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_registration_for_user - Error get_last_session_for_registration for provider %s", json_string_value(json_object_get(j_element, "provider")));
          }
          json_object_set(j_element, "last_session", json_null());
        }
        json_decref(j_session);
        if (provider == NULL) {
          json_object_del(j_element, "gsor_id");
          json_object_del(j_element, "sub");
        }
      }
      j_return = json_pack("{sisO}", "result", G_OK, "registration", j_result);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_registration_for_user - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static json_t * add_registration_for_user(struct config_module * config, struct _oauth2_config * oauth2_config, const char * username, json_t * j_provider, const char * register_url, const char * complete_url) {
  json_t * j_query, * j_return, * j_state = NULL, * j_last_id = NULL;
  int res;
  time_t now;
  char * expires_at_clause, * i_export, * state_export = NULL, * state_export_b64 = NULL;
  struct _i_session i_session;
  size_t state_export_b64_len = 0;
  
  if (!pthread_mutex_lock(&oauth2_config->insert_lock)) {
    if (i_init_session(&i_session) == I_OK) {
      if (i_import_session_json_t(&i_session, json_object_get(j_provider, "export")) == I_OK) {
        if (i_set_int_parameter(&i_session, I_OPT_STATE_GENERATE, GLEWLWYD_SCHEME_OAUTH2_STATE_ID_LENGTH) == I_OK && i_set_int_parameter(&i_session, I_OPT_NONCE_GENERATE, GLEWLWYD_SCHEME_OAUTH2_NONCE_LENGTH) == I_OK) {
          j_state = json_pack("{sssssOsOssss*ss*}", "id", i_get_str_parameter(&i_session, I_OPT_STATE), "type", GLEWLWYD_SCHEME_OAUTH2_STATE_REGISTRATION, "module", json_object_get(oauth2_config->j_parameters, "name"), "provider", json_object_get(j_provider, "name"), "username", username, "register_url", register_url, "complete_url", complete_url);
          state_export = json_dumps(j_state, JSON_COMPACT);
          if ((state_export_b64 = o_malloc(2*o_strlen(state_export))) != NULL) {
            if (o_base64url_encode((const unsigned char *)state_export, o_strlen(state_export), (unsigned char *)state_export_b64, &state_export_b64_len)) {
              i_set_str_parameter(&i_session, I_OPT_STATE, state_export_b64);
              if (i_build_auth_url_get(&i_session) == I_OK) {
                j_query = json_pack("{sss{sOsOssss}}",
                                    "table",
                                    GLEWLWYD_SCHEME_OAUTH2_REGISTRATION_TABLE,
                                    "values",
                                      "gsor_mod_name",
                                      json_object_get(oauth2_config->j_parameters, "name"),
                                      "gsor_provider",
                                      json_object_get(j_provider, "name"),
                                      "gsor_username",
                                      username,
                                      "gsor_userinfo_sub",
                                      "");
                res = h_insert(config->conn, j_query, NULL);
                json_decref(j_query);
                if (res == H_OK) {
                  time(&now);
                  if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
                    expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)json_integer_value(json_object_get(oauth2_config->j_parameters, "session_expiration"))));
                  } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
                    expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)json_integer_value(json_object_get(oauth2_config->j_parameters, "session_expiration"))));
                  } else { // HOEL_DB_TYPE_SQLITE
                    expires_at_clause = msprintf("%u", (now + (unsigned int)json_integer_value(json_object_get(oauth2_config->j_parameters, "session_expiration"))));
                  }
                  j_last_id = h_last_insert_id(config->conn);
                  i_export = i_export_session_str(&i_session);
                  j_query = json_pack("{sss{sOs{ss}sssssi}}",
                                      "table",
                                      GLEWLWYD_SCHEME_OAUTH2_SESSION_TABLE,
                                      "values",
                                        "gsor_id",
                                         j_last_id,
                                        "gsos_expires_at",
                                          "raw",
                                          expires_at_clause,
                                        "gsos_state",
                                        state_export_b64,
                                        "gsos_session_export",
                                        i_export,
                                        "gsos_status",
                                        GLEWLWYD_SCHEME_OAUTH2_SESSION_REGISTRATION);
                  o_free(expires_at_clause);
                  res = h_insert(config->conn, j_query, NULL);
                  json_decref(j_query);
                  json_decref(j_last_id);
                  o_free(i_export);
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
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "add_registration_for_user - Error i_build_auth_url_get");
                j_return = json_pack("{si}", "result", G_ERROR);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "add_registration_for_user - Error o_base64url_encode");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "add_registration_for_user - Error o_malloc state_export_b64");
            j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
          }
          o_free(state_export);
          o_free(state_export_b64);
          json_decref(j_state);
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
    pthread_mutex_unlock(&oauth2_config->insert_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_registration_for_user - Error pthread_mutex_lock");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

static int delete_registration_for_user(struct config_module * config, struct _oauth2_config * oauth2_config, const char * username, const char * provider) {
  json_t * j_query;
  int res, ret;
  
  j_query = json_pack("{sss{sOss}}",
                      "table",
                      GLEWLWYD_SCHEME_OAUTH2_REGISTRATION_TABLE,
                      "where",
                        "gsor_mod_name",
                        json_object_get(oauth2_config->j_parameters, "name"),
                        "gsor_username",
                        username);
  if (provider != NULL) {
    json_object_set_new(json_object_get(j_query, "where"), "gsor_provider", json_string(provider));
  }
  res = h_delete(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "delete_registration_for_user - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static int complete_session_for_user(struct config_module * config, const char * redirect_uri, json_t * j_registration, json_t * j_provider, const char * redirect_to, const char * state, int status) {
  json_t * j_query, * j_result = NULL;
  int res, ret;
  time_t now;
  char * expires_at_clause, * sub = NULL;
  struct _i_session i_session;
  
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
                        status,
                        "gsor_id",
                        json_object_get(j_registration, "gsor_id"));
  o_free(expires_at_clause);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      if (i_init_session(&i_session) == I_OK) {
        if (i_import_session_str(&i_session, json_string_value(json_object_get(json_array_get(j_result, 0), "gsos_session_export"))) == I_OK) {
          i_set_str_parameter(&i_session, I_OPT_REDIRECT_TO, redirect_to);
          if ((res = i_parse_redirect_to(&i_session) == I_OK)) {
            switch (i_get_response_type(&i_session)) {
              case I_RESPONSE_TYPE_CODE:
                if ((res = i_run_token_request(&i_session)) == I_OK) {
                  ret = G_OK;
                  if (0 == o_strcmp("oidc", json_string_value(json_object_get(j_provider, "provider_type")))) {
                    if (json_string_length(json_object_get(i_session.id_token_payload, "sub"))) {
                      sub = o_strdup(json_string_value(json_object_get(i_session.id_token_payload, "sub")));
                      ret = o_strlen(sub)?G_OK:G_ERROR_PARAM;
                    } else if (json_is_integer(json_object_get(i_session.id_token_payload, "sub"))) {
                      sub = msprintf("%"JSON_INTEGER_FORMAT, json_integer_value(json_object_get(i_session.id_token_payload, "sub")));
                      ret = o_strlen(sub)?G_OK:G_ERROR_PARAM;
                    }                    
                  } else {
                    if ((res = i_load_userinfo(&i_session)) == I_OK && i_session.j_userinfo != NULL) {
                      if (json_string_length((json_object_get(i_session.j_userinfo, json_string_value(json_object_get(j_provider, "userid_property")))))) {
                        sub = o_strdup(json_string_value(json_object_get(i_session.j_userinfo, json_string_value(json_object_get(j_provider, "userid_property")))));
                        ret = o_strlen(sub)?G_OK:G_ERROR_PARAM;
                      } else if (json_is_integer(json_object_get(i_session.j_userinfo, json_string_value(json_object_get(j_provider, "userid_property"))))) {
                        sub = msprintf("%"JSON_INTEGER_FORMAT, json_integer_value(json_object_get(i_session.j_userinfo, json_string_value(json_object_get(j_provider, "userid_property")))));
                        ret = o_strlen(sub)?G_OK:G_ERROR_PARAM;
                      }
                    } else if (res == I_ERROR_PARAM || res == I_ERROR_SERVER || res == I_ERROR_UNAUTHORIZED || i_session.j_userinfo == NULL) {
                      ret = G_ERROR_PARAM;
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "complete_session_for_user - Error i_load_userinfo (1)");
                      ret = G_ERROR;
                    }
                  }
                } else if (res == I_ERROR_PARAM || I_ERROR_SERVER) {
                  ret = G_ERROR_PARAM;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "complete_session_for_user - Error i_run_token_request");
                  ret = G_ERROR;
                }
                break;
              case I_RESPONSE_TYPE_TOKEN:
                if ((res = i_load_userinfo(&i_session)) == I_OK && i_session.j_userinfo != NULL) {
                  if (json_string_length(json_object_get(i_session.j_userinfo, json_string_value(json_object_get(j_provider, "userid_property"))))) {
                    sub = o_strdup(json_string_value(json_object_get(i_session.j_userinfo, json_string_value(json_object_get(j_provider, "userid_property")))));
                    ret = o_strlen(sub)?G_OK:G_ERROR_PARAM;
                  } else if (json_is_integer(json_object_get(i_session.j_userinfo, json_string_value(json_object_get(j_provider, "userid_property"))))) {
                    sub = msprintf("%"JSON_INTEGER_FORMAT, json_integer_value(json_object_get(i_session.j_userinfo, json_string_value(json_object_get(j_provider, "userid_property")))));
                    ret = o_strlen(sub)?G_OK:G_ERROR_PARAM;
                  }
                } else if (res == I_ERROR_PARAM || res == I_ERROR_SERVER || res == I_ERROR_UNAUTHORIZED || i_session.j_userinfo == NULL) {
                  ret = G_ERROR_PARAM;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "complete_session_for_user - Error i_load_userinfo (2)");
                  ret = G_ERROR;
                }
                break;
              case I_RESPONSE_TYPE_ID_TOKEN:
                if (json_string_length(json_object_get(i_session.id_token_payload, "sub"))) {
                  sub = o_strdup(json_string_value(json_object_get(i_session.id_token_payload, "sub")));
                  ret = o_strlen(sub)?G_OK:G_ERROR_PARAM;
                } else if (json_is_integer(json_object_get(i_session.id_token_payload, "sub"))) {
                  sub = msprintf("%"JSON_INTEGER_FORMAT, json_integer_value(json_object_get(i_session.id_token_payload, "sub")));
                  ret = o_strlen(sub)?G_OK:G_ERROR_PARAM;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "complete_session_for_user - Error getting userid value");
                  ret = G_ERROR_PARAM;
                }
                break;
              default:
                y_log_message(Y_LOG_LEVEL_ERROR, "complete_session_for_user - unsupported response_type");
                ret = G_ERROR_PARAM;
                break;
            }
            if (ret == G_OK && sub != NULL && 0 == o_strncmp(redirect_to, redirect_uri, o_strlen(redirect_uri))) {
              if (status == GLEWLWYD_SCHEME_OAUTH2_SESSION_REGISTRATION) {
                j_query = json_pack("{sss{ss}s{sO}}",
                                    "table",
                                    GLEWLWYD_SCHEME_OAUTH2_REGISTRATION_TABLE,
                                    "set",
                                      "gsor_userinfo_sub",
                                      sub,
                                    "where",
                                      "gsor_id",
                                      json_object_get(j_registration, "gsor_id"));
                res = h_update(config->conn, j_query, NULL);
                json_decref(j_query);
                if (res != H_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "complete_session_for_user - Error executing j_query (2)");
                  ret = G_ERROR_DB;
                }
              } else {
                if (0 != o_strcmp(sub, json_string_value(json_object_get(j_registration, "sub")))) {
                  ret = G_ERROR_UNAUTHORIZED;
                }
              }
              j_query = json_pack("{sss{si}s{sO}}",
                                  "table",
                                  GLEWLWYD_SCHEME_OAUTH2_SESSION_TABLE,
                                  "set",
                                    "gsos_status",
                                    GLEWLWYD_SCHEME_OAUTH2_SESSION_VERIFIED,
                                  "where",
                                    "gsos_id",
                                    json_object_get(json_array_get(j_result, 0), "gsos_id"));
              res = h_update(config->conn, j_query, NULL);
              json_decref(j_query);
              if (res != H_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "complete_session_for_user - Error executing j_query (3)");
                ret = G_ERROR_DB;
              }
            } else {
              j_query = json_pack("{sss{si}s{sO}}",
                                  "table",
                                  GLEWLWYD_SCHEME_OAUTH2_SESSION_TABLE,
                                  "set",
                                    "gsos_status",
                                    GLEWLWYD_SCHEME_OAUTH2_SESSION_CANCELLED,
                                  "where",
                                    "gsos_id",
                                    json_object_get(json_array_get(j_result, 0), "gsos_id"));
              res = h_update(config->conn, j_query, NULL);
              json_decref(j_query);
              if (res != H_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "complete_session_for_user - Error executing j_query (3)");
                ret = G_ERROR_DB;
              }
            }
            o_free(sub);
          } else if (res == I_ERROR_PARAM || I_ERROR_SERVER) {
            ret = G_ERROR_PARAM;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "complete_session_for_user - Error i_parse_redirect_to");
            ret = G_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "complete_session_for_user - Error i_import_session_json_t");
          ret = G_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "complete_session_for_user - Error i_init_session");
        ret = G_ERROR;
      }
      i_clean_session(&i_session);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "complete_session_for_user - state not found");
      ret = G_ERROR_NOT_FOUND;
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "complete_session_for_user - Error executing j_query (1)");
    ret = G_ERROR_DB;
  }
  return ret;
}

static json_t * get_provider(struct _oauth2_config * oauth2_config, const char * provider_name) {
  json_t * j_element = NULL, * j_return = NULL;
  size_t index = 0;
  
  json_array_foreach(json_object_get(oauth2_config->j_parameters, "provider_list"), index, j_element) {
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
  json_t * j_result, * j_return, * j_element = NULL, * j_export = NULL, * j_param;
  char * str_error;
  size_t index = 0, indexParam = 0;
  struct _i_session i_session;
  pthread_mutexattr_t mutexattr;
  
  j_result = is_scheme_parameters_valid(j_parameters);
  if (check_result_value(j_result, G_OK)) {
    *cls = o_malloc(sizeof(struct _oauth2_config));
    if (*cls != NULL) {
      ((struct _oauth2_config *)*cls)->j_parameters = json_pack("{sssOsOs[]}", "name", mod_name, "redirect_uri", json_object_get(j_parameters, "redirect_uri"), "session_expiration", json_object_get(j_parameters, "session_expiration"), "provider_list");
      pthread_mutexattr_init ( &mutexattr );
      pthread_mutexattr_settype( &mutexattr, PTHREAD_MUTEX_RECURSIVE );
      if (!pthread_mutex_init(&((struct _oauth2_config *)*cls)->insert_lock, &mutexattr) != 0) {
        json_array_foreach(json_object_get(j_parameters, "provider_list"), index, j_element) {
          if (json_object_get(j_element, "enabled") != json_false()) {
            if (i_init_session(&i_session) == I_OK) {
              json_array_foreach(json_object_get(j_element, "additional_parameters"), indexParam, j_param) {
                i_set_additional_parameter(&i_session, json_string_value(json_object_get(j_param, "key")), json_string_value(json_object_get(j_param, "value")));
              }
              if (json_string_length(json_object_get(j_element, "config_endpoint"))) {
                if (i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, get_response_type(json_string_value(json_object_get(j_element, "response_type"))),
                                                                      I_OPT_OPENID_CONFIG_ENDPOINT, json_string_value(json_object_get(j_element, "config_endpoint")),
                                                                      I_OPT_CLIENT_ID, json_string_value(json_object_get(j_element, "client_id")),
                                                                      I_OPT_CLIENT_SECRET, json_string_value(json_object_get(j_element, "client_secret")),
                                                                      I_OPT_REDIRECT_URI, json_string_value(json_object_get(j_parameters, "redirect_uri")),
                                                                      I_OPT_SCOPE, json_string_value(json_object_get(j_element, "scope")),
                                                                      I_OPT_NONE) != I_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init oauth2 - Error setting parameters for provider %s", json_string_value(json_object_get(j_element, "name")));
                } else if (i_load_openid_config(&i_session) != I_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init oauth2 - Error loading openid-configuration for provider %s", json_string_value(json_object_get(j_element, "name")));
                } else if ((j_export = i_export_session_json_t(&i_session)) == NULL) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init oauth2 - Error exporting session for provider %s", json_string_value(json_object_get(j_element, "name")));
                } else {
                  // Overwrite endpoints if specified
                  if (json_object_get(j_element, "auth_endpoint") != NULL) {
                    i_set_str_parameter(&i_session, I_OPT_AUTH_ENDPOINT, json_string_value(json_object_get(j_element, "auth_endpoint")));
                  }
                  if (json_object_get(j_element, "token_endpoint") != NULL) {
                    i_set_str_parameter(&i_session, I_OPT_TOKEN_ENDPOINT, json_string_value(json_object_get(j_element, "token_endpoint")));
                  }
                  if (json_object_get(j_element, "userinfo_endpoint") != NULL) {
                    i_set_str_parameter(&i_session, I_OPT_USERINFO_ENDPOINT, json_string_value(json_object_get(j_element, "userinfo_endpoint")));
                  }
                  json_object_set(j_element, "export", j_export);
                  json_array_append(json_object_get(((struct _oauth2_config *)*cls)->j_parameters, "provider_list"), j_element);
                }
                json_decref(j_export);
              } else {
                if (i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, get_response_type(json_string_value(json_object_get(j_element, "response_type"))),
                                                                      I_OPT_AUTH_ENDPOINT, json_string_value(json_object_get(j_element, "auth_endpoint")),
                                                                      I_OPT_TOKEN_ENDPOINT, json_string_value(json_object_get(j_element, "token_endpoint")),
                                                                      I_OPT_USERINFO_ENDPOINT, json_string_value(json_object_get(j_element, "userinfo_endpoint")),
                                                                      I_OPT_CLIENT_ID, json_string_value(json_object_get(j_element, "client_id")),
                                                                      I_OPT_CLIENT_SECRET, json_string_value(json_object_get(j_element, "client_secret")),
                                                                      I_OPT_REDIRECT_URI, json_string_value(json_object_get(j_parameters, "redirect_uri")),
                                                                      I_OPT_SCOPE, json_string_value(json_object_get(j_element, "scope")),
                                                                      I_OPT_NONE) != I_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init oauth2 - Error setting parameters for provider %s", json_string_value(json_object_get(j_element, "name")));
                } else if ((j_export = i_export_session_json_t(&i_session)) == NULL) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init oauth2 - Error exporting session for provider %s", json_string_value(json_object_get(j_element, "name")));
                } else {
                  json_object_set(j_element, "export", j_export);
                  json_array_append(json_object_get(((struct _oauth2_config *)*cls)->j_parameters, "provider_list"), j_element);
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
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init oauth2 - Error pthread_mutex_init");
        j_return = json_pack("{si}", "result", G_ERROR);
        json_decref(((struct _oauth2_config *)*cls)->j_parameters);
        o_free(*cls);
        *cls = NULL;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init oauth2 - Error allocating resources for *cls");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init oauth2 - Error in parameters");
    str_error = json_dumps(json_object_get(j_result, "error"), JSON_ENCODE_ANY);
    y_log_message(Y_LOG_LEVEL_ERROR, str_error);
    o_free(str_error);
    j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", json_object_get(j_result, "error"));
  }
  json_decref(j_result);
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
  json_decref(((struct _oauth2_config *)cls)->j_parameters);
  pthread_mutex_destroy(&((struct _oauth2_config *)cls)->insert_lock);
  o_free(cls);
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
  json_t * j_registration = get_registration_for_user(config, (struct _oauth2_config *)cls, username, NULL);
  
  if (check_result_value(j_registration, G_OK)) {
    ret = GLEWLWYD_IS_REGISTERED;
  } else if (check_result_value(j_registration, G_ERROR_NOT_FOUND)) {
    ret = GLEWLWYD_IS_AVAILABLE;
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
  struct _oauth2_config * oauth2_config = (struct _oauth2_config *)cls;
  
  if (json_is_object(j_scheme_data)) {
    j_provider = get_provider(oauth2_config, json_string_value(json_object_get(j_scheme_data, "provider")));
    if (check_result_value(j_provider, G_OK)) {
      if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "action")), "new")) {
        j_result = get_registration_for_user(config, oauth2_config, username, json_string_value(json_object_get(j_scheme_data, "provider")));
        if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
          j_register = add_registration_for_user(config, oauth2_config, username, json_object_get(j_provider, "provider"), json_string_value(json_object_get(j_scheme_data, "register_url")), json_string_value(json_object_get(j_scheme_data, "complete_url")));
          if (check_result_value(j_register, G_OK)) {
            j_return = json_pack("{sis{sO}}", "result", G_OK, "response", "redirect_to", json_object_get(j_register, "registration"));
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register oauth2 - Error add_registration_for_user");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          json_decref(j_register);
        } else if (check_result_value(j_result, G_OK)) {
          j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "provider already registered");
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register oauth2 - Error get_registration_for_user");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_result);
      } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "action")), "callback")) {
        j_result = get_registration_for_user(config, oauth2_config, username, json_string_value(json_object_get(j_scheme_data, "provider")));
        if (check_result_value(j_result, G_OK)) {
          if ((res = complete_session_for_user(config, json_string_value(json_object_get(oauth2_config->j_parameters, "redirect_uri")), json_array_get(json_object_get(j_result, "registration"), 0), json_object_get(j_provider, "provider"), json_string_value(json_object_get(j_scheme_data, "redirect_to")), json_string_value(json_object_get(j_scheme_data, "state")), GLEWLWYD_SCHEME_OAUTH2_SESSION_REGISTRATION)) == G_OK) {
            j_return = json_pack("{si}", "result", G_OK);
          } else if (res == G_ERROR_PARAM || res == G_ERROR_UNAUTHORIZED || res == G_ERROR_NOT_FOUND) {
            j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "Registration completion invalid");
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register oauth2 - Error complete_session_for_user");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
        } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
          j_return = json_pack("{si}", "result", G_ERROR_PARAM);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register oauth2 - Error get_registration_for_user");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_result);
      } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "action")), "delete")) {
        j_result = get_registration_for_user(config, oauth2_config, username, json_string_value(json_object_get(j_scheme_data, "provider")));
        if (check_result_value(j_result, G_OK)) {
          if (delete_registration_for_user(config, oauth2_config, username, json_string_value(json_object_get(j_scheme_data, "provider"))) == G_OK) {
            j_return = json_pack("{si}", "result", G_OK);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register oauth2 - Error delete_registration_for_user");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
        } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
          j_return = json_pack("{si}", "result", G_ERROR_PARAM);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register oauth2 - Error get_registration_for_user");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_result);
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
  int ret;
  struct _oauth2_config * oauth2_config = (struct _oauth2_config *)cls;
  
  if (delete_registration_for_user(config, oauth2_config, username, NULL) == G_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_deregister oauth2 - Error delete_registration_for_user");
    ret = G_ERROR;
  }
  return ret;
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
  UNUSED(http_request);
  struct _oauth2_config * oauth2_config = (struct _oauth2_config *)cls;
  json_t * j_result, * j_return, * j_element = NULL, * j_register = NULL;
  size_t index = 0, index_r = 0;
  int found;

  j_result = get_registration_for_user(config, oauth2_config, username, NULL);
  if (check_result_value(j_result, G_OK)) {
    j_return = json_pack("{sis[]}", "result", G_OK, "response");
    json_array_foreach(json_object_get(oauth2_config->j_parameters, "provider_list"), index, j_element) {
      found = 0;
      json_array_foreach(json_object_get(j_result, "registration"), index_r, j_register) {
        if (0 == o_strcmp(json_string_value(json_object_get(j_element, "name")), json_string_value(json_object_get(j_register, "provider")))) {
          json_object_set(j_register, "logo_uri", json_object_get(j_element, "logo_uri"));
          json_object_set(j_register, "logo_fa", json_object_get(j_element, "logo_fa"));
          json_array_append(json_object_get(j_return, "response"), j_register);
          found = 1;
        }
      }
      if (!found) {
        json_array_append_new(json_object_get(j_return, "response"), json_pack("{sOsOsOsoso}", "provider", json_object_get(j_element, "name"), "logo_uri", json_object_get(j_element, "logo_uri"), "logo_fa", json_object_get(j_element, "logo_fa"), "enabled", json_false(), "created_at", json_null()));
      }
    }
  } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
    j_return = json_pack("{sis[]}", "result", G_OK, "response");
    json_array_foreach(json_object_get(oauth2_config->j_parameters, "provider_list"), index, j_element) {
      json_array_append_new(json_object_get(j_return, "response"), json_pack("{sOsOsOsoso}", "provider", json_object_get(j_element, "name"), "logo_uri", json_object_get(j_element, "logo_uri"), "logo_fa", json_object_get(j_element, "logo_fa"), "enabled", json_false(), "created_at", json_null()));
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register_get oauth2 - Error get_registration_for_user");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_result);
  return j_return;
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
  json_t * j_return = NULL, * j_session = NULL, * j_result, * j_element = NULL, * j_register = NULL, * j_provider;
  size_t index = 0, index_r = 0;
  struct _oauth2_config * oauth2_config = (struct _oauth2_config *)cls;

  if (json_object_get(j_scheme_trigger, "provider_list") == json_true()) {
    j_session = config->glewlwyd_module_callback_check_user_session(config, http_request, username);
    if (check_result_value(j_session, G_OK)) {
      j_result = get_registration_for_user(config, oauth2_config, username, NULL);
      if (check_result_value(j_result, G_OK)) {
        j_return = json_pack("{sis[]}", "result", G_OK, "response");
        json_array_foreach(json_object_get(oauth2_config->j_parameters, "provider_list"), index, j_element) {
          json_array_foreach(json_object_get(j_result, "registration"), index_r, j_register) {
            if (0 == o_strcmp(json_string_value(json_object_get(j_element, "name")), json_string_value(json_object_get(j_register, "provider")))) {
              json_array_append_new(json_object_get(j_return, "response"), json_pack("{sOsOsOsO}", "provider", json_object_get(j_register, "provider"), "logo_uri", json_object_get(j_element, "logo_uri"), "logo_fa", json_object_get(j_element, "logo_fa"), "created_at", json_object_get(j_register, "created_at")));
            }
          }
        }
      } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger oauth2 - Error get_registration_for_user");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_result);
    } else {
      j_return = json_pack("{sis[]}", "result", G_OK, "response");
      json_array_foreach(json_object_get(oauth2_config->j_parameters, "provider_list"), index, j_element) {
        json_array_append_new(json_object_get(j_return, "response"), json_pack("{sOsOsOso}", "provider", json_object_get(j_element, "name"), "logo_uri", json_object_get(j_element, "logo_uri"), "logo_fa", json_object_get(j_element, "logo_fa"), "created_at", json_null()));
      }
    }
    json_decref(j_session);
  } else {
    j_register = get_registration_for_user(config, oauth2_config, username, json_string_value(json_object_get(j_scheme_trigger, "provider")));
    if (check_result_value(j_register, G_OK)) {
      j_provider = get_provider(oauth2_config, json_string_value(json_object_get(j_scheme_trigger, "provider")));
      if (check_result_value(j_provider, G_OK)) {
        j_result = add_session_for_user(config, oauth2_config, username, json_array_get(json_object_get(j_register, "registration"), 0), json_object_get(j_provider, "provider"), json_string_value(json_object_get(j_scheme_trigger, "callback_url")));
        if (check_result_value(j_result, G_OK)) {
          j_return = json_pack("{sis{sO}}", "result", G_OK, "response", "redirect_to", json_object_get(j_result, "session"));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger oauth2 - Error add_session_for_user");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_result);
        
      } else {
        j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "provider invalid");
      }
      json_decref(j_provider);
    } else {
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "provider invalid");
    }
    json_decref(j_register);
  }
  return j_return;
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
  UNUSED(http_request);
  json_t * j_result, * j_provider;
  int res, ret;
  struct _oauth2_config * oauth2_config = (struct _oauth2_config *)cls;

  j_result = get_registration_for_user(config, oauth2_config, username, json_string_value(json_object_get(j_scheme_data, "provider")));
  if (check_result_value(j_result, G_OK)) {
    j_provider = get_provider(oauth2_config, json_string_value(json_object_get(j_scheme_data, "provider")));
    if (check_result_value(j_provider, G_OK)) {
      if ((res = complete_session_for_user(config, json_string_value(json_object_get(oauth2_config->j_parameters, "redirect_uri")), json_array_get(json_object_get(j_result, "registration"), 0), json_object_get(j_provider, "provider"), json_string_value(json_object_get(j_scheme_data, "redirect_to")), json_string_value(json_object_get(j_scheme_data, "state")), GLEWLWYD_SCHEME_OAUTH2_SESSION_AUTHENTICATION)) == G_OK) {
        ret = G_OK;
      } else if (res == G_ERROR_PARAM || res == G_ERROR_UNAUTHORIZED || res == G_ERROR_NOT_FOUND) {
        ret = G_ERROR_UNAUTHORIZED;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate oauth2 - Error complete_session_for_user");
        ret = G_ERROR;
      }
    } else {
      ret = G_ERROR_UNAUTHORIZED;
    }
    json_decref(j_provider);
  } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
    ret = G_ERROR_UNAUTHORIZED;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate oauth2 - Error get_registration_for_user");
    ret = G_ERROR;
  }
  json_decref(j_result);
  return ret;
}

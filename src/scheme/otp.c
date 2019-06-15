/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * HOTP/TOTP authentication scheme module
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
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <liboath/oath.h>
#include <yder.h>
#include <orcania.h>
#include "../glewlwyd-common.h"

#define GLEWLWYD_TABLE_OTP "gs_otp"

#define G_TOTP_DEFAULT_TIME_STEP_SIZE 30
#define G_TOTP_DEFAULT_START_OFFSET 0

static json_t * is_scheme_parameters_valid(json_t * j_params) {
  json_t * j_return, * j_error;
  
  if (json_is_object(j_params)) {
    j_error = json_array();
    if (j_error != NULL) {
      if (json_integer_value(json_object_get(j_params, "otp-length")) != 6 && json_integer_value(json_object_get(j_params, "otp-length")) != 7 && json_integer_value(json_object_get(j_params, "otp-length")) != 8) {
        json_array_append_new(j_error, json_string("otp-length is mandatory and must be 6, 7 or 8"));
      }
      if (!json_string_length(json_object_get(j_params, "issuer"))) {
        json_array_append_new(j_error, json_string("issuer is mandatory and must be a non empty string"));
      }
      if (json_integer_value(json_object_get(j_params, "secret-minimum-size")) <= 0 || json_integer_value(json_object_get(j_params, "secret-minimum-size")) > 128) {
        json_array_append_new(j_error, json_string("secret-minimum-size is mandatory and must be between 0 and 128"));
      }
      if (json_object_get(j_params, "hotp-allow") != NULL && !json_is_boolean(json_object_get(j_params, "hotp-allow"))) {
        json_array_append_new(j_error, json_string("hotp-allow is optional and must be a boolean"));
      }
      if (json_object_get(j_params, "hotp-window") != NULL && json_integer_value(json_object_get(j_params, "hotp-window")) < 0) {
        json_array_append_new(j_error, json_string("hotp-window is optional and must be a positive integer"));
      }
      if (json_object_get(j_params, "totp-allow") != NULL && !json_is_boolean(json_object_get(j_params, "totp-allow"))) {
        json_array_append_new(j_error, json_string("totp-allow is optional and must be a boolean"));
      }
      if (json_object_get(j_params, "totp-window") != NULL && json_integer_value(json_object_get(j_params, "totp-window")) < 0) {
        json_array_append_new(j_error, json_string("totp-window is optional and must be a positive integer"));
      }
      if (json_object_get(j_params, "totp-start-offset") != NULL && json_integer_value(json_object_get(j_params, "totp-start-offset")) < 0) {
        json_array_append_new(j_error, json_string("totp-start-offset is optional and must be a positive integer"));
      }
      if (json_array_size(j_error)) {
        j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
      } else {
        j_return = json_pack("{si}", "result", G_OK);
      }
      json_decref(j_error);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_scheme_parameters_valid - Error allocating resources for j_error");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "parameters must be a JSON object");
  }
  return j_return;
}

static json_t * get_otp(struct config_module * config, json_t * j_params, const char * username) {
  json_t * j_query, * j_result, * j_return;
  int res;
  char * username_escaped, * username_clause;
  
  username_escaped = h_escape_string(config->conn, username);
  username_clause = msprintf(" = UPPER('%s')", username_escaped);
  j_query = json_pack("{sss[sssss]s{s{ssss}sO}}",
                      "table",
                      GLEWLWYD_TABLE_OTP,
                      "columns",
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gso_issued_at) AS issued_at", "gso_issued_at AS issued_at", "EXTRACT(EPOCH FROM gso_issued_at) AS issued_at"),
                        "gso_otp_type",
                        "gso_secret AS secret",
                        "gso_hotp_moving_factor AS moving_factor",
                        "gso_totp_time_step_size AS time_step_size",
                      "where",
                        "UPPER(gso_username)",
                          "operator",
                          "raw",
                          "value",
                          username_clause,
                        "gso_mod_name",
                        json_object_get(j_params, "mod_name"));
  o_free(username_clause);
  o_free(username_escaped);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gso_otp_type")) == 0) {
        json_object_set_new(json_array_get(j_result, 0), "type", json_string("HOTP"));
        json_object_del(json_array_get(j_result, 0), "time_step_size");
        json_object_del(json_array_get(j_result, 0), "start_offset");
      } else {
        json_object_set_new(json_array_get(j_result, 0), "type", json_string("TOTP"));
        json_object_del(json_array_get(j_result, 0), "moving_factor");
      }
      json_object_del(json_array_get(j_result, 0), "gso_otp_type");
      j_return = json_pack("{sisO}", "result", G_OK, "otp", json_array_get(j_result, 0));
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_otp - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static int update_otp(struct config_module * config, json_t * j_params, const char * username, int increment_moving_factor) {
  char * username_escaped, * username_clause, * last_login_clause;
  json_t * j_query;
  int ret;
  
  username_escaped = h_escape_string(config->conn, username);
  username_clause = msprintf(" = UPPER('%s')", username_escaped);
  if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
    last_login_clause = msprintf("FROM_UNIXTIME(%u)", (time(NULL)));
  } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
    last_login_clause = msprintf("TO_TIMESTAMP(%u)", (time(NULL)));
  } else { // HOEL_DB_TYPE_SQLITE
    last_login_clause = msprintf("%u", (time(NULL)));
  }
  j_query = json_pack("{sss{s{ss}}s{s{ssss}sO}}",
                      "table",
                      GLEWLWYD_TABLE_OTP,
                      "set",
                        "gso_last_used",
                          "raw",
                          last_login_clause,
                      "where",
                        "UPPER(gso_username)",
                          "operator",
                          "raw",
                          "value",
                          username_clause,
                        "gso_mod_name",
                        json_object_get(j_params, "mod_name"));
  o_free(username_clause);
  o_free(username_escaped);
  o_free(last_login_clause);
  if (increment_moving_factor) {
    json_object_set_new(json_object_get(j_query, "set"), "gso_hotp_moving_factor", json_pack("{ss}", "raw", "gso_hotp_moving_factor+1"));
  }
  if (h_update(config->conn, j_query, NULL) == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "update_otp - Error executing j_query");
    ret = G_ERROR_DB;
  }
  json_decref(j_query);
  return ret;
}

static int set_otp(struct config_module * config, json_t * j_params, const char * username, json_t * j_scheme_data) {
  json_t * j_query, * j_otp;
  int ret, res, type = (0==o_strcmp(json_string_value(json_object_get(j_scheme_data, "type")), "HOTP")?0:1);
  char * username_escaped, * username_clause;
  
  if (0 != o_strcmp(json_string_value(json_object_get(j_scheme_data, "type")), "NONE")) {
    j_otp = get_otp(config, j_params, username);
    if (check_result_value(j_otp, G_OK)) {
      username_escaped = h_escape_string(config->conn, username);
      username_clause = msprintf(" = UPPER('%s')", username_escaped);
      j_query = json_pack("{sss{sisOsOso}s{s{ssss}sO}}",
                          "table",
                          GLEWLWYD_TABLE_OTP,
                          "set",
                            "gso_otp_type",
                            type,
                            "gso_secret",
                            json_object_get(j_scheme_data, "secret"),
                            "gso_hotp_moving_factor",
                            type==0?(json_object_get(j_scheme_data, "moving_factor")!=NULL?json_object_get(j_scheme_data, "moving_factor"):0):json_null(),
                            "gso_totp_time_step_size",
                            type==1?(json_object_get(j_scheme_data, "time_step_size")!=NULL?json_integer(json_integer_value(json_object_get(j_scheme_data, "time_step_size"))):json_integer(G_TOTP_DEFAULT_TIME_STEP_SIZE)):json_null(),
                          "where",
                            "UPPER(gso_username)",
                              "operator",
                              "raw",
                              "value",
                              username_clause,
                            "gso_mod_name",
                            json_object_get(j_params, "mod_name"));
      o_free(username_clause);
      o_free(username_escaped);
      res = h_update(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_otp - Error h_update");
        ret = G_ERROR_NOT_FOUND;
      }
    } else if (check_result_value(j_otp, G_ERROR_NOT_FOUND)) {
      j_query = json_pack("{sss{sisOsOsosssO}}",
                          "table",
                          GLEWLWYD_TABLE_OTP,
                          "values",
                            "gso_otp_type",
                            type,
                            "gso_secret",
                            json_object_get(j_scheme_data, "secret"),
                            "gso_hotp_moving_factor",
                            type==0?(json_object_get(j_scheme_data, "moving_factor")!=NULL?json_object_get(j_scheme_data, "moving_factor"):0):json_null(),
                            "gso_totp_time_step_size",
                            type==1?(json_object_get(j_scheme_data, "time_step_size")!=NULL?json_integer(json_integer_value(json_object_get(j_scheme_data, "time_step_size"))):json_integer(G_TOTP_DEFAULT_TIME_STEP_SIZE)):json_null(),
                            "gso_username",
                            username,
                            "gso_mod_name",
                            json_object_get(j_params, "mod_name"));
      res = h_insert(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_otp - Error h_insert");
        ret = G_ERROR_NOT_FOUND;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "set_otp - Error get_otp");
      ret = G_ERROR;
    }
    json_decref(j_otp);
  } else {
    username_escaped = h_escape_string(config->conn, username);
    username_clause = msprintf(" = UPPER('%s')", username_escaped);
    j_query = json_pack("{sss{s{ssss}sO}}",
                        "table",
                        GLEWLWYD_TABLE_OTP,
                        "where",
                          "UPPER(gso_username)",
                            "operator",
                            "raw",
                            "value",
                            username_clause,
                          "gso_mod_name",
                          json_object_get(j_params, "mod_name"));
    o_free(username_clause);
    o_free(username_escaped);
    res = h_delete(config->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      ret = G_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "set_otp - Error h_delete");
      ret = G_ERROR_NOT_FOUND;
    }
  }
  return ret;
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
  return json_pack("{sisssssss{s{ssso}s{ssso}s{ssso}s{ssso}s{ssso}}}",
                   "result",
                   G_OK,
                   "name",
                   "otp",
                   "display_name",
                   "HOTP/TOTP",
                   "description",
                   "HOTP/TOTP scheme module for glewlwyd",
                   "parameters",
                     "otp-length",
                       "type",
                       "number",
                       "mandatory",
                       json_true(),
                     "hotp-allow",
                       "type",
                       "boolean",
                       "mandatory",
                       json_false(),
                     "hotp-window",
                       "type",
                       "number",
                       "mandatory",
                       json_false(),
                     "totp-allow",
                       "type",
                       "boolean",
                       "mandatory",
                       json_false(),
                     "totp-window",
                       "type",
                       "number",
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
 * @return value: G_OK on success, another value on error
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
int user_auth_scheme_module_init(struct config_module * config, json_t * j_parameters, const char * mod_name, void ** cls) {
  UNUSED(config);
  json_t * j_result = is_scheme_parameters_valid(j_parameters);
  int ret;
  char * message;
  
  if (check_result_value(j_result, G_OK)) {
    json_object_set_new(j_parameters, "mod_name", json_string(mod_name));
    *cls = json_incref(j_parameters);
    ret = G_OK;
  } else if (check_result_value(j_result, G_ERROR_PARAM)) {
    message = json_dumps(json_object_get(j_result, "error"), JSON_COMPACT);
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init otp - Error input parameters: %s", message);
    o_free(message);
    ret = G_ERROR_PARAM;
  } else {
    ret = G_ERROR;
  }
  json_decref(j_result);
  return ret;
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
  json_t * j_otp;
  int ret;
  
  j_otp = get_otp(config, (json_t *)cls, username);
  if (check_result_value(j_otp, G_OK)) {
    ret = GLEWLWYD_IS_REGISTERED;
  } else if (check_result_value(j_otp, G_ERROR_NOT_FOUND)) {
    ret = GLEWLWYD_IS_AVAILABLE;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_can_use otp - Error get_otp");
    ret = GLEWLWYD_IS_NOT_AVAILABLE;
  }
  json_decref(j_otp);
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
  UNUSED(config);
  UNUSED(http_request);
  json_t * j_return = NULL;
  char * secret = NULL, * secret_b32 = NULL;
  size_t secret_len = 0, secret_b32_len = 0;
  
  if (json_is_object(j_scheme_data)) {
    if (json_object_get(j_scheme_data, "generate-secret") == json_true()) {
      secret_len = json_integer_value(json_object_get((json_t *)cls, "secret-minimum-size"))*sizeof(unsigned char);
      if ((secret = o_malloc(secret_len)) != NULL) {
        if (!gnutls_rnd(GNUTLS_RND_KEY, secret, secret_len)) {
          if (oath_base32_encode(secret, secret_len, &secret_b32, &secret_b32_len) == OATH_OK) {
            j_return = json_pack("{sis{ss%}}", "result", G_OK, "response", "secret", secret_b32, secret_b32_len);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register otp - Error oath_base32_encode");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          o_free(secret_b32);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register otp - Error gnutls_rnd");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register otp - Error allocating resources for secret");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      o_free(secret);
    } else {
      if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "type")), "NONE") || 0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "type")), "HOTP") || 0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "type")), "TOTP")) {
        if (0 != o_strcmp(json_string_value(json_object_get(j_scheme_data, "type")), "NONE")) {
          if (oath_base32_decode(json_string_value(json_object_get(j_scheme_data, "secret")), json_string_length(json_object_get(j_scheme_data, "secret")), &secret, &secret_len) == OATH_OK) {
            if (secret_len >= (size_t)json_integer_value(json_object_get((json_t *)cls, "secret_minimum_size")) && json_string_length(json_object_get(j_scheme_data, "secret")) < 256) {
              if (json_string_length(json_object_get(j_scheme_data, "secret")) >= 8) {
                if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "type")), "HOTP")) {
                  if (json_object_get((json_t *)cls, "hotp-allow") == json_false()) {
                    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "HOTP Type not allowed");
                  } else if (!json_is_integer(json_object_get(j_scheme_data, "moving_factor")) || json_integer_value(json_object_get(j_scheme_data, "moving_factor")) < 0) {
                    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "moving_factor is optional and must be a positive integer or zero");
                  }
                } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "type")), "TOTP")) {
                  if (json_object_get((json_t *)cls, "totp-allow") == json_false()) {
                    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "TOTP Type not allowed");
                  } else if (json_integer_value(json_object_get(j_scheme_data, "time_step_size")) <= 0 || json_integer_value(json_object_get(j_scheme_data, "time_step_size")) > 120) {
                    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "time_step_size is optional and must be a positive integer up to 120");
                  }
                }
              } else {
                j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "secret is mandatory and must be at least 8 characters");
              }
            } else {
              j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "shared secret invalid size");
            }
          } else {
            j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "shared secret must be base32 encoded");
          }
          o_free(secret);
        }
      } else {
        j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "invaid type, type must be 'HOTP' 'TOTP' or 'NONE'");
      }
    }
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "data must be a JSON object");
  }
  
  if (j_return == NULL) {
    return json_pack("{si}", "result", set_otp(config, (json_t *)cls, username, j_scheme_data)==G_OK?G_OK:G_ERROR);
  }
  return j_return;
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
  json_t * j_otp, * j_return;
  
  j_otp = get_otp(config, (json_t *)cls, username);
  if (check_result_value(j_otp, G_OK)) {
    json_object_set(json_object_get(j_otp, "otp"), "digits", json_object_get((json_t *)cls, "otp-length"));
    json_object_set(json_object_get(j_otp, "otp"), "issuer", json_object_get((json_t *)cls, "issuer"));
    j_return = json_pack("{sisO}", "result", G_OK, "response", json_object_get(j_otp, "otp"));
  } else if (check_result_value(j_otp, G_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_register_get otp - Error get_otp");
  }
  json_decref(j_otp);
  
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
  UNUSED(config);
  UNUSED(http_request);
  UNUSED(username);
  UNUSED(j_scheme_trigger);
  UNUSED(cls);

  return json_pack("{si}", "result", G_OK);
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
  int ret;
  json_t * j_otp;
  char * secret_decoded = NULL;
  size_t secret_decoded_len;
  
  if (!json_string_length(json_object_get(j_scheme_data, "value")) || json_string_length(json_object_get(j_scheme_data, "value")) != (size_t)json_integer_value(json_object_get((json_t *)cls, "otp-length"))) {
    ret = G_ERROR_UNAUTHORIZED;
  } else if (user_auth_scheme_module_can_use(config, username, cls) == GLEWLWYD_IS_REGISTERED) {
    j_otp = get_otp(config, (json_t *)cls, username);
    if (check_result_value(j_otp, G_OK)) {
      if (oath_base32_decode(json_string_value(json_object_get(json_object_get(j_otp, "otp"), "secret")), json_string_length(json_object_get(json_object_get(j_otp, "otp"), "secret")), &secret_decoded, &secret_decoded_len) == OATH_OK) {
        if (0 == o_strcmp(json_string_value(json_object_get(json_object_get(j_otp, "otp"), "type")), "HOTP")) {
          if ((ret = oath_hotp_validate(secret_decoded,
                                        secret_decoded_len,
                                        json_integer_value(json_object_get(json_object_get(j_otp, "otp"), "moving_factor")),
                                        json_integer_value(json_object_get((json_t *)cls, "window")),
                                        json_string_value(json_object_get(j_scheme_data, "value")))) >= 0) {
            if (update_otp(config, (json_t *)cls, username, 1) == G_OK) {
              ret = G_OK;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate otp - Error update_otp (1)");
              ret = G_ERROR;
            }
          } else if (ret == OATH_INVALID_OTP) {
            ret = G_ERROR_UNAUTHORIZED;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate otp - Error oath_hotp_validate: '%s'", oath_strerror(ret));
            ret = G_ERROR;
          }
        } else {
          if ((ret = oath_totp_validate(secret_decoded,
                                        secret_decoded_len,
                                        time(NULL),
                                        json_integer_value(json_object_get(json_object_get(j_otp, "otp"), "time_step_size")),
                                        json_integer_value(json_object_get((json_t *)cls, "totp-start-offset")),
                                        json_integer_value(json_object_get((json_t *)cls, "window")),
                                        json_string_value(json_object_get(j_scheme_data, "value")))) >= 0) {
            if (update_otp(config, (json_t *)cls, username, 0) == G_OK) {
              ret = G_OK;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate otp - Error update_otp (1)");
              ret = G_ERROR;
            }
          } else if (ret == OATH_INVALID_OTP) {
            ret = G_ERROR_UNAUTHORIZED;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate otp - Error oath_hotp_validate: '%s'", oath_strerror(ret));
            ret = G_ERROR;
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate otp - Error oath_base32_decode");
        ret = G_ERROR;
      }
      o_free(secret_decoded);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate otp - Error get_otp");
      ret = G_ERROR;
    }
    json_decref(j_otp);
  } else {
    ret = G_ERROR_UNAUTHORIZED;
  }
  return ret;
}

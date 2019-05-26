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
      if (json_object_get(j_params, "hotp-allow") != NULL && !json_is_boolean(json_object_get(j_params, "hotp-allow"))) {
        json_array_append_new(j_error, json_string("hotp-allow is optional and must be a boolean"));
      }
      if (json_object_get(j_params, "hotp-window") != NULL && json_integer_value(json_object_get(j_params, "hotp-window")) <= 0) {
        json_array_append_new(j_error, json_string("hotp-window is optional and must be a positive integer"));
      }
      if (json_object_get(j_params, "totp-allow") != NULL && !json_is_boolean(json_object_get(j_params, "totp-allow"))) {
        json_array_append_new(j_error, json_string("totp-allow is optional and must be a boolean"));
      }
      if (json_object_get(j_params, "totp-window") != NULL && json_integer_value(json_object_get(j_params, "totp-window")) <= 0) {
        json_array_append_new(j_error, json_string("totp-window is optional and must be a positive integer"));
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

static json_t * get_otp(struct config_module * config, const char * username) {
  json_t * j_query, * j_result, * j_return;
  int res;
  char * username_escaped, * username_clause;
  
  username_escaped = h_escape_string(config->conn, username);
  username_clause = msprintf(" = UPPER('%s')", username_escaped);
  j_query = json_pack("{sss[ssssssss]s{s{ssss}}}",
                      "table",
                      GLEWLWYD_TABLE_OTP,
                      "columns",
                        "gso_name",
                        SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(gso_issued_at) AS issued_at", "gso_issued_at AS issued_at", "EXTRACT(EPOCH FROM gso_issued_at) AS issued_at"),
                        "gso_enabled",
                        "gso_otp_type",
                        "gso_secret AS secret",
                        "gso_hotp_moving_factor AS moving_factor",
                        "gso_totp_time_step_size AS time_step_size",
                        "gso_totp_start_offset AS start_offset",
                      "where",
                        "UPPER(gso_username)",
                          "operator",
                          "raw",
                          "value",
                          username_clause);
  o_free(username_clause);
  o_free(username_escaped);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      json_object_set(json_array_get(j_result, 0), "enabled", json_integer_value(json_object_get(json_array_get(j_result, 0), "gso_enabled"))?json_true():json_false());
      json_object_del(json_array_get(j_result, 0), "gso_enabled");
      if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gso_otp_type")) == 0) {
        json_object_set_new(json_array_get(j_result, 0), "type", json_string("HOTP"));
        json_object_del(json_array_get(j_result, 0), "time_step_size");
        json_object_del(json_array_get(j_result, 0), "start_offset");
      } else {
        json_object_set_new(json_array_get(j_result, 0), "type", json_string("HOTP"));
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

static int set_otp(struct config_module * config, json_t * j_params, const char * username, json_t * j_scheme_data) {
  json_t * j_query, * j_otp;
  int ret, res, type = 0==o_strcmp(json_string_value(json_object_get(j_scheme_data, "type")), "HOTP")?0:1;
  char * username_escaped, * username_clause;
  
  if (0 != o_strcmp(json_string_value(json_object_get(j_scheme_data, "type")), "NONE")) {
    j_otp = get_otp(config, username);
    if (check_result_value(j_otp, G_OK)) {
      username_escaped = h_escape_string(config->conn, username);
      username_clause = msprintf(" = UPPER('%s')", username_escaped);
      j_query = json_pack("{sss{sOsOsisOsOsOsOsoso}s{s{ssss}}}",
                          "table",
                          GLEWLWYD_TABLE_OTP,
                          "set",
                            "gso_name",
                            json_object_get(j_scheme_data, "name"),
                            "gso_enabled",
                            json_object_get(j_scheme_data, "enabled")==json_false()?json_false():json_true(),
                            "gso_otp_type",
                            type,
                            "gso_secret",
                            json_object_get(j_scheme_data, "secret"),
                            "gso_otp_window",
                            json_object_get(j_scheme_data, "window")!=NULL?json_object_get(j_scheme_data, "window"):json_null(),
                            "gso_hotp_moving_factor",
                            type==0?(json_object_get(j_scheme_data, "moving_factor")!=NULL?json_object_get(j_scheme_data, "moving_factor"):0):json_null(),
                            "gso_totp_time_step_size",
                            type==1?(json_object_get(j_scheme_data, "time_step_size")!=NULL?json_integer(json_integer_value(json_object_get(j_scheme_data, "time_step_size"))):json_integer(G_TOTP_DEFAULT_TIME_STEP_SIZE)):json_null(),
                            "gso_totp_start_offset",
                            type==1?(json_object_get(j_scheme_data, "start_offset")!=NULL?json_integer(json_integer_value(json_object_get(j_scheme_data, "start_offset"))):json_integer(G_TOTP_DEFAULT_START_OFFSET)):json_null(),
                          "where",
                            "UPPER(gso_username)",
                              "operator",
                              "raw",
                              "value",
                              username_clause);
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
      j_query = json_pack("{sss{sOsOsisOsOsOsososs}}",
                          "table",
                          GLEWLWYD_TABLE_OTP,
                          "values",
                            "gso_name",
                            json_object_get(j_scheme_data, "name"),
                            "gso_enabled",
                            json_object_get(j_scheme_data, "enabled")==json_false()?json_false():json_true(),
                            "gso_otp_type",
                            type,
                            "gso_secret",
                            json_object_get(j_scheme_data, "secret"),
                            "gso_otp_window",
                            json_object_get(j_scheme_data, "window")!=NULL?json_object_get(j_scheme_data, "window"):json_null(),
                            "gso_hotp_moving_factor",
                            type==0?(json_object_get(j_scheme_data, "moving_factor")!=NULL?json_object_get(j_scheme_data, "moving_factor"):0):json_null(),
                            "gso_totp_time_step_size",
                            type==1?(json_object_get(j_scheme_data, "time_step_size")!=NULL?json_integer(json_integer_value(json_object_get(j_scheme_data, "time_step_size"))):json_integer(G_TOTP_DEFAULT_TIME_STEP_SIZE)):json_null(),
                            "gso_totp_start_offset",
                            type==1?(json_object_get(j_scheme_data, "start_offset")!=NULL?json_integer(json_integer_value(json_object_get(j_scheme_data, "start_offset"))):json_integer(G_TOTP_DEFAULT_START_OFFSET)):json_null(),
                            "gso_username",
                            username);
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
    j_query = json_pack("{sss{s{ssss}}}",
                        "table",
                        GLEWLWYD_TABLE_OTP,
                        "where",
                          "UPPER(gso_username)",
                            "operator",
                            "raw",
                            "value",
                            username_clause);
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
  if (!oath_init()) {
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
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_load otp - Error oath_init");
    return json_pack("{si}", "result", G_ERROR);
  }
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
  if (!oath_done()) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_unload otp - Error oath_done");
    return G_ERROR;
  }
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
 * @parameter cls: will contain an allocated void * pointer that will be sent back
 *                 as void * in all module functions
 * 
 */
int user_auth_scheme_module_init(struct config_module * config, json_t * j_parameters, void ** cls) {
  UNUSED(config);
  json_t * j_result = is_scheme_parameters_valid(j_parameters);
  int ret;
  char * message;
  
  if (check_result_value(j_result, G_OK)) {
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
  UNUSED(cls);
  json_t * j_otp;
  int ret;
  
  j_otp = get_otp(config, username);
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
json_t * user_auth_scheme_module_register(struct config_module * config, const struct _u_request * http_request, int from_admin, const char * username, json_t * j_scheme_data, void * cls) {
  UNUSED(config);
  UNUSED(http_request);
  UNUSED(from_admin);
  json_t * j_return = NULL;
  
  if (json_is_object(j_scheme_data)) {
    if (json_string_length(json_object_get(j_scheme_data, "secret")) >= 8) {
      if (json_string_length(json_object_get(j_scheme_data, "name"))) {
        if (json_integer_value(json_object_get(j_scheme_data, "window")) < 0) {
          j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "window is optional and must be a positive integer");
        } else {
          if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "type")), "HOTP")) {
            if (json_integer_value(json_object_get(j_scheme_data, "moving_factor")) < 0) {
              j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "moving_factor is optional and must be a positive integer or zero");
            }
          } else if (0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "type")), "TOTP")) {
            if (json_integer_value(json_object_get(j_scheme_data, "time_step_size")) <= 0) {
              j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "time_step_size is optional and must be a positive integer");
            } else if (json_integer_value(json_object_get(j_scheme_data, "start_offset")) < 0) {
              j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "start_offset is optional and must be a positive integer or zero");
            }
          } else if (0 != o_strcmp(json_string_value(json_object_get(j_scheme_data, "type")), "NONE")) {
            j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "type is mandatory and must have on of the following values: 'HOTP' or 'TOTP' or 'NONE'");
          }
        }
      } else {
        j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "name is mandatory and must be non empty string");
      }
    } else {
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "secret is mandatory and must be at least 8 characters");
    }
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "response", "data must be a JSON object");
  }
  
  if (j_return == NULL) {
    return json_pack("{si}", "result", set_otp(config, (json_t *)cls, username, j_scheme_data));
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
json_t * user_auth_scheme_module_register_get(struct config_module * config, const struct _u_request * http_request, int from_admin, const char * username, void * cls) {
  UNUSED(config);
  UNUSED(http_request);
  UNUSED(from_admin);
  json_t * j_otp, * j_return;
  
  j_otp = get_otp(config, username);
  if (check_result_value(j_otp, G_OK)) {
    j_return = json_pack("{sisO}", "result", G_OK, "response", json_object_get(j_otp, "otp"));
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
  time_t now;
  
  if (user_auth_scheme_module_can_use(config, username, cls) == GLEWLWYD_IS_REGISTERED) {
    j_otp = get_otp(config, username);
    if (0 == o_strcmp(json_string_value(json_object_get(json_object_get(j_otp, "otp"), "type")), "HOTP")) {
      if ((ret = oath_hotp_validate(json_string_value(json_object_get(json_object_get(j_otp, "otp"), "secret")),
                                    json_string_length(json_object_get(json_object_get(j_otp, "otp"), "secret")),
                                    json_integer_value(json_object_get(json_object_get(j_otp, "otp"), "moving_factor")),
                                    json_integer_value(json_object_get(json_object_get(j_otp, "otp"), "window")),
                                    json_string_value(json_object_get(j_scheme_data, "value")))) >= 0) {
        ret = G_OK;
      } else if (ret == OATH_INVALID_OTP) {
        ret = G_ERROR_UNAUTHORIZED;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate otp - Error oath_hotp_validate: '%s'", oath_strerror(ret));
        ret = G_ERROR;
      }
    } else {
      time(&now);
      if ((ret = oath_totp_validate(json_string_value(json_object_get(json_object_get(j_otp, "otp"), "secret")),
                                    json_string_length(json_object_get(json_object_get(j_otp, "otp"), "secret")),
                                    now,
                                    json_integer_value(json_object_get(json_object_get(j_otp, "otp"), "time_step_size")),
                                    json_integer_value(json_object_get(json_object_get(j_otp, "otp"), "start_offset")),
                                    json_integer_value(json_object_get(json_object_get(j_otp, "otp"), "window")),
                                    json_string_value(json_object_get(j_scheme_data, "value")))) >= 0) {
        ret = G_OK;
      } else if (ret == OATH_INVALID_OTP) {
        ret = G_ERROR_UNAUTHORIZED;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate otp - Error oath_hotp_validate: '%s'", oath_strerror(ret));
        ret = G_ERROR;
      }
    }
    json_decref(j_otp);
  } else {
    ret = G_ERROR_UNAUTHORIZED;
  }
  return ret;
}

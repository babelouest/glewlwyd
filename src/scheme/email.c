/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Random code sent by e-mail authentication scheme module
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
#include <yder.h>
#include <orcania.h>
#include <ulfius.h>
#include "../glewlwyd-common.h"

#define GLEWLWYD_SCHEME_CODE_TABLE "gss_code"

#define GLEWLWYD_SCHEME_CODE_DEFAULT_LENGTH 6
#define GLEWLWYD_SCHEME_CODE_DURATION 900

struct _scheme_config {
  json_t * j_param;
};

static int generate_new_code(struct _scheme_config * config, const char * username, char * code, size_t len) {
  json_t * j_query;
  int res, ret;
  char * code_hash = NULL;
  
  j_query = json_pack("{sss{si}s{ss}}",
                      "table",
                      GLEWLWYD_SCHEME_CODE_TABLE,
                      "set",
                        "gusc_enabled",
                        0,
                       "where",
                        "gusc_username",
                        username);
  res = h_delete(config->config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (rand_code(code, len)) {
      if ((code_hash = generate_hash(config->config->hash_algorithm, code)) != NULL) {
        j_query = json_pack("{sss{ssss}}",
                            "table",
                            GLEWLWYD_SCHEME_CODE_TABLE,
                            "values",
                              "gusc_username",
                              username,
                              "gusc_code_hash",
                              code_hash);
        res = h_insert(config->config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          ret = G_OK;
        } else {
          ret = G_ERROR_DB;
        }
        o_free(code_hash);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_code - Error generate_hash");
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_code - Error rand_code");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_new_code - Error executing j_query (1)");
    ret = G_ERROR_DB;
  }
  return ret;
}

static int check_code(struct config_module * config, struct _scheme_config * scheme_config, const char * username, char * code) {
  json_t * j_query, * j_result;
  int res, ret;
  char * code_hash = NULL, * issued_at_clause = NULL;
  time_t now;
  
  if ((code_hash = generate_hash(config->hash_algorithm, code)) != NULL) {
    time(&now);
    if (conn->type==HOEL_DB_TYPE_MARIADB) {
      issued_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now - json_integer_value(json_object_get(scheme_config->j_param, "code-duration"))));
    } else if (conn->type==HOEL_DB_TYPE_PGSQL) {
      issued_at_clause = msprintf("> EXTRACT(TIMESTAMP FROM EPOCH %u)", (now - json_integer_value(json_object_get(scheme_config->j_param, "code-duration"))));
    } else { // HOEL_DB_TYPE_SQLITE
      issued_at_clause = msprintf("> %u", (now - json_integer_value(json_object_get(scheme_config->j_param, "code-duration"))));
    }
    j_query = json_pack("{sss{sssssis{ssss}}}",
                        "table",
                        GLEWLWYD_SCHEME_CODE_TABLE,
                        "where",
                          "gusc_username",
                          username,
                          "gusc_code_hash",
                          code_hash,
                          "gusc_enabled",
                          1,
                          "gusc_issued_at",
                            "operator",
                            "raw",
                            "value",
                            issued_at_clause);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        j_query = json_pack("{sss{si}s{ssss}}",
                            "table",
                            GLEWLWYD_SCHEME_CODE_TABLE,
                            "set",
                              "gusc_enabled",
                              0,
                             "where",
                               "gusc_username",
                               username,
                               "gusc_code_hash",
                               code_hash);
        res = h_update(config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "check_code - Error executing j_query (2)");
          ret = G_ERROR_DB;
        }
      } else {
        ret = G_ERROR_UNAUTHORIZED;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "check_code - Error executing j_query (1)");
      ret = G_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "check_code - Error generate_hash");
    ret = G_ERROR;
  }
  return ret;
}

static json_t * is_scheme_parameters_valid(json_t * j_params) {
  json_t * j_errors = json_array(), * j_result;
  
  if (j_errors != NULL) {
    if (!json_is_object(j_params)) {
      json_array_append_new(j_errors, json_string("parameters must be a JSON object"));
    } else {
      if (json_object_get(j_params, "code-length") != NULL && (!json_is_integer(json_object_get(j_params, "code-length")) || json_integer_value(json_object_get(j_params, "code-length")) <= 0)) {
        json_array_append_new(j_errors, json_string("code-length is optional and must be a positive integer"));
      } else if (json_object_get(j_params, "code-length") == NULL) {
        json_object_set_new(j_params, "code-length", json_integer(GLEWLWYD_SCHEME_CODE_DEFAULT_LENGTH));
      }
      if (json_object_get(j_params, "code-duration") != NULL && (!json_is_integer(json_object_get(j_params, "code-duration")) || json_integer_value(json_object_get(j_params, "code-duration")) <= 0)) {
        json_array_append_new(j_errors, json_string("code-duration is optional and must be a positive integer"));
      } else if (json_object_get(j_params, "code-duration") == NULL) {
        json_object_set_new(j_params, "code-duration", json_integer(GLEWLWYD_SCHEME_CODE_DEFAULT_LENGTH));
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
      if (json_object_get(j_params, "subject") != NULL && !json_string_length(json_object_get(j_params, "subject"))) {
        json_array_append_new(j_errors, json_string("subject is mandatory and must be a non empty string"));
      }
      if (json_object_get(j_params, "body-pattern") != NULL && !json_string_length(json_object_get(j_params, "body-pattern"))) {
        json_array_append_new(j_errors, json_string("body-pattern is mandatory and must be a non empty string"));
      }
    }
    if (json_array_size(j_errors)) {
      j_result = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_errors);
    } else {
      j_result = json_pack("{si}", "result", G_OK);
    }
    json_decref(j_errors);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_scheme_parameters_valid - Error allocating resources for j_errors");
    j_result = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_result;
}

/**
 * 
 * user_auth_scheme_module_load
 * 
 * Executed once when Glewlwyd service is loaded
 * Used to identify the module and to show its parameters on init
 * You can also use it to load resources that are required once for all
 * instance modules for example
 * 
 * @return value: G_OK on success, another value on error
 *                On error, the module will not be available
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter name: must return an allocated char * value containing the name
 *                  of the module, must be unique to identify the module
 * @parameter display_name: must return an allocated char * value containing the
 *                          display_name (long name) of the module
 * @parameter description: must return an allocated char * value containing the
 *                         description of the module
 * @parameter parameters: must return an allocated char * value containing the
 *                        expected parameters when calling user_auth_scheme_module_init
 *                        in JSON stringified format
 * 
 */
int user_auth_scheme_module_load(struct config_module * config, char ** name, char ** display_name, char ** description, char ** parameters) {
  int ret = G_OK;
  
  if (name != NULL && parameters != NULL && display_name != NULL && description != NULL) {
    *name = o_strdup("email");
    *display_name = o_strdup("Email code scheme module");
    *description = o_strdup("Send a code via email to authenticate the user");
    *parameters = o_strdup("{\"code-length\":{\"type\":\"number\",\"mandatory\":false},"
                            "\"code-duration\":{\"type\":\"number\",\"mandatory\":false},"
                            "\"host\":{\"type\":\"string\",\"mandatory\":true},"
                            "\"port\":{\"type\":\"number\",\"mandatory\":false},"
                            "\"use-tls\":{\"type\":\"boolean\",\"mandatory\":false},"
                            "\"check-certificate\":{\"type\":\"boolean\",\"mandatory\":false},"
                            "\"user\":{\"type\":\"string\",\"mandatory\":false},"
                            "\"password\":{\"type\":\"string\",\"mandatory\":false},"
                            "\"from\":{\"type\":\"string\",\"mandatory\":false},"
                            "\"subject\":{\"type\":\"string\",\"mandatory\":true},"
                            "\"body-pattern\":{\"type\":\"string\",\"mandatory\":true},"
                            "}");
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
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
 * @parameter: parameters used to initialize an instance in JSON stringified format
 * @parameter cls: must return an allocated void * pointer that will be sent back
 *                 as void * in all module functions
 * 
 */
int user_auth_scheme_module_init(struct config_module * config, const char * parameters, void ** cls) {
  json_t * j_params = json_loads(parameters, JSON_DECODE_ANY, NULL), * j_result;
  int ret;
  char * str_error;
  
  if (j_params != NULL) {
    *cls = o_malloc(sizeof(struct _scheme_config));
    if (*cls != NULL) {
      j_result = is_scheme_parameters_valid(j_params);
      if (check_result_value(j_result, G_OK)) {
        ((struct _scheme_config *)*cls)->j_param = j_params;
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init email - Error in parameters");
        str_error = json_dumps(json_object_get(k_result, "error"), JSON_ENCODE_ANY);
        y_log_message(Y_LOG_LEVEL_ERROR, str_error);
        o_free(str_error);
        ret = G_ERROR_PARAM;
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init email - Error allocating resources for cls");
      ret = G_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init email - Error parsing parameters in JSON format");
    ret = G_ERROR_PARAM;
  }
  if (ret != G_OK) {
    json_decref(j_params);
  }
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
  json_decref(((struct _scheme_config *)cls)->j_param);
  o_free(cls);
  return G_OK;
}

/**
 * 
 * user_auth_scheme_can_use
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
int user_can_use_scheme(struct config_module * config, const char * username, void * cls) {
  char * str_user = NULL;
  json_t * j_user;
  int ret, result;

  str_user = config->glewlwyd_module_callback_get_user(config, username, &result);
  if (result == G_OK) {
    j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
    if (j_user != NULL) {
      if (json_object_get(j_user, "email") != NULL) {
        ret = GLEWLWYD_IS_REGISTERED;
      } else {
        ret = GLEWLWYD_IS_NOT_AVAILABLE;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_can_use_scheme mail - Error parsing user");
      ret = GLEWLWYD_IS_NOT_AVAILABLE;
    }
    json_decref(j_user);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_can_use_scheme mail - Error glewlwyd_module_callback_get_user");
    ret = GLEWLWYD_IS_NOT_AVAILABLE;
  }
  o_free(str_user);
  return ret;
}

/**
 * 
 * user_auth_scheme_module_register
 * 
 * Register the scheme for a user
 * Ex: add a certificate, add new TOTP values, etc.
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter register_data: additional data used to register the scheme for the user
 *                           in JSON stringified format
 * @parameter register_response: must return an allocated char * value containing the
 *                               response of the registration in JSON stringified format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_register(struct config_module * config, const void * http_request, const char * username, const char * register_data, char ** register_response, void * cls) {
  if (user_can_use_scheme(username, cls) == GLEWLWYD_IS_REGISTERED) {
    return G_OK;
  } else {
    return G_ERROR_PARAM;
  }
}

/**
 * 
 * user_auth_scheme_module_register_get
 * 
 * Get the registration value(s) of the scheme for a user
 * 
 * @return value: Registration value for the user in JSON stringified format
 * as a dynamically allocated char *.
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter result: used to set the result of the function, must G_OK on success, another value on error
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
char * user_auth_scheme_module_register_get(struct config_module * config, const void * http_request, const char * username, int * result, void * cls) {
  char * str_result = NULL;
  if (user_can_use_scheme(username, cls) == GLEWLWYD_IS_REGISTERED) {
    *result = G_OK;
  } else {
    *result = G_ERROR_PARAM;
  }
  return str_result;
}

/**
 * 
 * user_auth_scheme_module_trigger
 * 
 * Trigger the scheme for a user
 * Ex: send the code to a device, generate a challenge, etc.
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter scheme_trigger: data sent to trigger the scheme for the user
 *                           in JSON stringified format
 * @parameter register_response: must return an allocated char * value containing the
 *                               response of the trigger in JSON stringified format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_trigger(struct config_module * config, const void * http_request, const char * username, const char * scheme_trigger, char ** scheme_trigger_response, void * cls) {
  struct _scheme_config * config = (struct _scheme_config *)cls;
  char * str_user = NULL;
  json_t * j_user;
  int ret, result;
  char * code = NULL, * body;

  if (user_can_use_scheme(username, cls) == GLEWLWYD_IS_REGISTERED) {
    str_user = config->glewlwyd_module_callback_get_user(config, username, &result);
    if (result == G_OK) {
      j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
      if (j_user != NULL) {
        if ((code = o_malloc((json_integer_value(json_object_get(config->j_param, "code-length")) + 1)*sizeof(char))) != NULL) {
          memset(code, 0, (json_integer_value(json_object_get(config->j_param, "code-length")) + 1));
          if (generate_new_code(config, username, code, json_integer_value(json_object_get(config->j_param, "code-length"))) == G_OK) {
            if ((body = str_replace(json_string_value(json_object_get(config->j_param, "body-pattern")), "{CODE}", code)) != NULL) {
              if (ulfius_send_smtp_email(json_string_value(json_object_get(config->j_param, "host")),
                                         json_integer_value(json_object_get(config->j_param, "port")),
                                         json_object_get(config->j_param, "use-tls")==json_true()?1:0,
                                         json_object_get(config->j_param, "verify-certificate")==json_false()?0:1,
                                         json_string_value(json_object_get(config->j_param, "user")),
                                         json_string_value(json_object_get(config->j_param, "password")),
                                         json_string_value(json_object_get(config->j_param, "from")),
                                         json_string_value(json_object_get(j_user, "email")),
                                         NULL,
                                         NULL,
                                         json_string_value(json_object_get(config->j_param, "subject")),
                                         body) == G_OK) {
                ret = G_OK;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger mail - Error ulfius_send_smtp_email");
                ret = G_ERROR_MEMORY;
              }
              o_free(body);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger mail - Error str_replace");
              ret = G_ERROR_MEMORY;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger mail - Error generate_new_code");
            ret = G_ERROR_MEMORY;
          }
          o_free(code);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger mail - Error parsing user");
          ret = G_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger mail - Error parsing user");
        ret = G_ERROR;
      }
      json_decref(j_user);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_trigger mail - Error glewlwyd_module_callback_get_user");
      ret = G_ERROR;
    }
    o_free(str_user);
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
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
 * @parameter scheme_data: data sent to validate the scheme for the user
 *                           in JSON stringified format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_validate(struct config_module * config, const void * http_request, const char * username, const char * scheme_data, void * cls) {
  struct _scheme_config * config = (struct _scheme_config *)cls;
  json_t * j_scheme = json_loads(scheme_data, JSON_DECODE_ANY, NULL);
  int ret, res;
  char * code_hash;
  
  if (j_scheme != NULL) {
    if (user_can_use_scheme(username, cls) != GLEWLWYD_IS_REGISTERED) {
      ret = G_ERROR_UNAUTHORIZED;
    } else if (json_object_get(j_scheme, "code") != NULL && json_is_string(json_object_get(j_scheme, "code")) && json_integer_value(json_object_get(config->j_param, "code-length")) == json_string_length(json_object_get(j_scheme, "code"))) {
      if ((res = check_code(config, username, json_string_value(json_object_get(j_scheme, "code")))) == G_OK) {
        ret = G_OK;
      } else if (res == G_ERROR_UNAUTHORIZED) {
        ret = G_ERROR_UNAUTHORIZED;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate mail - Error check_code");
        ret = res;
      }
    } else {
      ret = G_ERROR_PARAM;
    }
  } else {
    ret = G_ERROR_PARAM;
  }
  json_decref(j_scheme);
  return ret;
}

/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Mock authentication scheme module
 * 
 * Copyright 2018-2019 Nicolas Mora <mail@babelouest.org>
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
#include "../glewlwyd-common.h"

/**
 * 
 * Config structure specific for the module
 * An instance of this structure will be created in the init function
 * and passed as void * parameter in each function
 * So every function will have access to the module configuration
 * 
 */
struct mock_config {
  json_t * j_param;
};

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
    *name = o_strdup("webauthn");
    *display_name = o_strdup("Webauthn scheme module");
    *description = o_strdup("Web Authentiation scheme module");
    *parameters = o_strdup("{\"mock-value\":{\"type\":\"string\",\"mandatory\":true}}");
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
  *cls = o_malloc(sizeof(struct mock_config));
  ((struct mock_config *)*cls)->j_param = json_loads(parameters, JSON_DECODE_ANY, NULL);
  return G_OK;
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
  json_decref(((struct mock_config *)cls)->j_param);
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
  char * str_user = NULL, * key_mock;
  json_t * j_user;
  int ret, result;

  str_user = config->glewlwyd_module_callback_get_user(((struct mock_config *)cls)->config, username, &result);
  if (result == G_OK) {
    j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
    if (j_user != NULL) {
      key_mock = msprintf("mock-%s", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
      if (json_is_object(json_object_get(j_user, key_mock))) {
        ret = GLEWLWYD_IS_REGISTERED;
      } else {
        ret = GLEWLWYD_IS_AVAILABLE;
      }
      o_free(key_mock);
    } else {
      ret = GLEWLWYD_IS_NOT_AVAILABLE;
    }
    json_decref(j_user);
  } else {
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
json_t * user_auth_scheme_module_register(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls) {
  int ret, result = G_ERROR;
  char * str_user = NULL, * str_user_set, * key_mock;
  json_t * j_user, * j_data;
  
  str_user = config->glewlwyd_module_callback_get_user(((struct mock_config *)cls)->config, username, &result);
  if (result == G_OK) {
    j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
    j_data = json_loads(register_data, JSON_DECODE_ANY, NULL);
    if (j_user != NULL) {
      key_mock = msprintf("mock-%s", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
      if (json_object_get(j_data, "register") == json_true()) {
        json_object_set_new(j_user, key_mock, json_pack("{si}", "counter", 0));
      } else {
        json_object_set(j_user, key_mock, json_null());
      }
      str_user_set = json_dumps(j_user, JSON_COMPACT);
      ret = config->glewlwyd_module_callback_set_user(config, username, str_user_set);
      if (ret == G_OK) {
        *register_response = msprintf("{\"register-code\":\"%s\"}", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
      }
      o_free(str_user_set);
      o_free(key_mock);
    } else {
      ret = G_ERROR;
    }
    json_decref(j_user);
    json_decref(j_data);
  } else {
    ret = G_ERROR;
  }
  o_free(str_user);
  return ret;
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
json_t * user_auth_scheme_module_register_get(struct config_module * config, const struct _u_request * http_request, const char * username, void * cls) {
  int res;
  json_t * j_user, * j_register;
  char * str_result = NULL, * str_user, * key_mock;
  
  str_user = config->glewlwyd_module_callback_get_user(config, username, &res);
  if (res == G_OK) {
    j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
    if (j_user != NULL) {
      key_mock = msprintf("mock-%s", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
      if ((j_register = json_object_get(j_user, key_mock)) != NULL) {
        str_result = json_dumps(j_register, JSON_COMPACT);
        json_decref(j_register);
        *result = G_OK;
      } else {
        *result = G_ERROR_UNAUTHORIZED;
      }
      o_free(key_mock);
    } else {
      *result = G_ERROR;
    }
    json_decref(j_user);
  } else {
    *result = G_ERROR_NOT_FOUND;
  }
  o_free(str_user);
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
json_t * user_auth_scheme_module_trigger(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_trigger, void * cls) {
  int ret;
  
  if (user_auth_scheme_module_can_use(username, cls) == GLEWLWYD_IS_REGISTERED) {
    *scheme_trigger_response = msprintf("{\"code\":\"%s\"}", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
    ret = G_OK;
  } else {
    ret = G_ERROR_UNAUTHORIZED;
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
  json_t * j_scheme = json_loads(scheme_data, JSON_DECODE_ANY, NULL), * j_user;
  char * str_user = NULL, * str_user_set, * key_mock;
  int ret, result = G_ERROR;
  
  if (j_scheme != NULL) {
    if (user_auth_scheme_module_can_use(username, cls) != GLEWLWYD_IS_REGISTERED) {
      ret = G_ERROR_UNAUTHORIZED;
    } else if (json_object_get(j_scheme, "code") != NULL && json_is_string(json_object_get(j_scheme, "code")) && 0 == o_strcmp(json_string_value(json_object_get(j_scheme, "code")), json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")))) {
      str_user = config->glewlwyd_module_callback_get_user(config, username, &result);
      if (result == G_OK) {
        j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
        if (j_user != NULL) {
          key_mock = msprintf("mock-%s", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
          json_object_set_new(j_user, key_mock, json_pack("{si}", "counter", json_integer_value(json_object_get(json_object_get(j_user, key_mock), "counter")) + 1));
          str_user_set = json_dumps(j_user, JSON_COMPACT);
          ret = config->glewlwyd_module_callback_set_user(config, username, str_user_set);
          o_free(str_user_set);
          o_free(key_mock);
        } else {
          ret = G_ERROR;
        }
        json_decref(j_user);
      } else {
        ret = G_ERROR;
      }
      o_free(str_user);
    } else {
      ret = G_ERROR_UNAUTHORIZED;
    }
  } else {
    ret = G_ERROR_PARAM;
  }
  json_decref(j_scheme);
  return ret;
}

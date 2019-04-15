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
  return json_pack("{sisssssss{s{ssso}}}",
                   "result",
                   G_OK,
                   "name",
                   "mock",
                   "display_name",
                   "Mock scheme module",
                   "description",
                   "Mock scheme module for glewlwyd tests",
                   "parameters",
                     "mock-value",
                       "type",
                       "string",
                       "mandatory",
                       json_true());
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
 * @parameter j_parameters: used to initialize an instance in JSON format
 * @parameter cls: must return an allocated void * pointer that will be sent back
 *                 as void * in all module functions
 * 
 */
int user_auth_scheme_module_init(struct config_module * config, json_t * j_parameters, void ** cls) {
  *cls = o_malloc(sizeof(struct mock_config));
  ((struct mock_config *)*cls)->j_param = json_incref(j_parameters);
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
  char * key_mock;
  json_t * j_user;
  int ret;

  j_user = config->glewlwyd_module_callback_get_user(config, username);
  if (check_result_value(j_user, G_OK)) {
    key_mock = msprintf("mock-%s", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
    if (0 == o_strcmp("1", json_string_value(json_object_get(json_object_get(j_user, "user"), key_mock)))) {
      ret = GLEWLWYD_IS_REGISTERED;
    } else {
      ret = GLEWLWYD_IS_AVAILABLE;
    }
    o_free(key_mock);
  } else {
    ret = GLEWLWYD_IS_NOT_AVAILABLE;
  }
  json_decref(j_user);
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
  char  * key_mock;
  json_t * j_user, * j_return;
  
  j_user = config->glewlwyd_module_callback_get_user(config, username);
  if (check_result_value(j_user, G_OK)) {
    key_mock = msprintf("mock-%s", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
    if (json_object_get(j_scheme_data, "register") == json_true()) {
      json_object_set_new(json_object_get(j_user, "user"), key_mock, json_string("1"));
    } else {
      json_object_set_new(json_object_get(j_user, "user"), key_mock, json_string("0"));
    }
    if (config->glewlwyd_module_callback_set_user(config, username, json_object_get(j_user, "user")) == G_OK) {
      j_return = json_pack("{sis{ss}}", "result", G_OK, "response", "register-code", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
    } else {
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(key_mock);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_user);
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
  json_t * j_user, * j_register, * j_return;
  char * key_mock;
  
  j_user = config->glewlwyd_module_callback_get_user(config, username);
  if (check_result_value(j_user, G_OK)) {
    key_mock = msprintf("mock-%s", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
    if ((j_register = json_object_get(json_object_get(j_user, "user"), key_mock)) != NULL) {
      j_return = json_pack("{sisO}", "result", G_OK, "response", j_register);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
    o_free(key_mock);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  json_decref(j_user);
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
  json_t * j_return;
  
  if (user_auth_scheme_module_can_use(config, username, cls) == GLEWLWYD_IS_REGISTERED) {
    j_return = json_pack("{sis{ss}}", "result", G_OK, "response", "code", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
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
  int ret;
  
  if (user_auth_scheme_module_can_use(config, username, cls) != GLEWLWYD_IS_REGISTERED) {
    ret = G_ERROR_UNAUTHORIZED;
  } else if (json_object_get(j_scheme_data, "code") != NULL && json_is_string(json_object_get(j_scheme_data, "code")) && 0 == o_strcmp(json_string_value(json_object_get(j_scheme_data, "code")), json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")))) {
    ret = G_OK;
  } else {
    ret = G_ERROR_UNAUTHORIZED;
  }
  return ret;
}

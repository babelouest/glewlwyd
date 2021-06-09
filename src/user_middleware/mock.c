/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Mock user middleware module
 * 
 * Copyright 2021 Nicolas Mora <mail@babelouest.org>
 *
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <string.h>
#include <jansson.h>
#include <yder.h>
#include <orcania.h>
#include "glewlwyd-common.h"

/**
 * Note on the user middleware module
 * 
 * A middleware module is intended to improve and extend a user object
 * The first use case was the integration with casbin (https://github.com/casbin/casbin-cpp)
 * 
 * The user middleware modules are "placed" between the user backend and the outside world.
 * Therefore, the user middleware modules are executed _after_ a get_user_list, get_user
 * or a get_user_profile from the backend, and _before_ a add_user, set_user, set_user_profile
 * or delete_user
 * 
 * You can instaciate any number of user middleware modules, they will be excuted accordingly to
 * thei "order" parameter
 * 
 * The beckend user modules will never know that a middleware module exist on top of them, so on a
 * add/set/delete user, the middleware user should "clean its passage" to avoid undefined behaviour
 * on the user backend
 * 
 * What a middleware can do?
 * - Update the entire user object
 * 
 * What a middleware must not do?
 * - Change the username
 * - Use other values types than string or array of strings, and boolean for the reserved property "enabled"
 * 
 * Other than that, the possibilities are limitless and can be specialized for any use case.
 * Beware that those functions should be stateless, since the same function can potentially be
 * executed mutiple times for one process
 * 
 * A typical example is an ACL middleware module that will add access level and group properties to the user object
 * 
 * Definition of the struct config_module:
 * 
 * struct config_module {
 *   const char              * external_url;    // Absolute url of the glewlwyd service
 *   const char              * login_url;       // Relative url of the login page
 *   const char              * admin_scope;     // Value of the g_admin scope
 *   const char              * profile_scope;   // Value of the g_profile scope
 *   struct _h_connection    * conn;            // Hoel structure to access to the database
 *   digest_algorithm          hash_algorithm;  // Hash algorithm used in Glewlwyd
 *   struct config_elements  * glewlwyd_config; // Pointer to the global config structure
 *                          // Function used to return a user object
 *   json_t               * (* glewlwyd_module_callback_get_user)(struct config_module * config, const char * username);
 *                          // Function used to update a user
 *   int                    (* glewlwyd_module_callback_set_user)(struct config_module * config, const char * username, json_t * j_user);
 *                          // Function used to check the validity of a user's password
 *   int                    (* glewlwyd_module_callback_check_user_password)(struct config_module * config, const char * username, const char * password);
 * };
 * 
 */

/**
 * 
 * user_middleware_module_load
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
json_t * user_middleware_module_load(struct config_module * config) {
  UNUSED(config);
  return json_pack("{sisssssssf}",
                   "result", G_OK,
                   "name", "mock",
                   "display_name", "Mock user middleware module",
                   "description", "Mock user middleware module for glewlwyd tests",
                   "api_version", 2.6);
}

/**
 * 
 * user_middleware_module_unload
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
int user_middleware_module_unload(struct config_module * config) {
  UNUSED(config);
  return G_OK;
}

/**
 * 
 * user_middleware_module_init
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
json_t * user_middleware_module_init(struct config_module * config, json_t * j_parameters, void ** cls) {
  UNUSED(config);
  if (json_object_get(j_parameters, "middleware") != NULL && !json_is_string(json_object_get(j_parameters, "middleware"))) {
    return json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "middleware must be a string");
  } else {
    *cls = json_incref(j_parameters);
    y_log_message(Y_LOG_LEVEL_DEBUG, "user_middleware_module_init - middleware value: '%s'", json_string_value(json_object_get(j_parameters, "middleware")));
    return json_pack("{si}", "result", G_OK);
  }
}

/**
 * 
 * user_middleware_module_close
 * 
 * Close an instance of this module declared in Glewlwyd service.
 * You must free the memory previously allocated in
 * the user_module_init function as void * cls
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_middleware_module_close(struct config_module * config, void * cls) {
  UNUSED(config);
  json_decref((json_t *)cls);
  return G_OK;
}

/**
 *
 * user_middleware_module_get_list
 *
 * Update a list of users returned by user_get_list
 *
 * @return value: G_OK on success, another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter j_user_list: The list of users returned by the user backend modules
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_middleware_module_get_list(struct config_module * config, json_t * j_user_list, void * cls) {
  UNUSED(config);
  json_t * j_element = NULL;
  size_t index = 0;
  
  json_array_foreach(j_user_list, index, j_element) {
    json_object_set_new(j_element, "middleware", json_pack("s++", json_string_value(json_object_get((json_t *)cls, "middleware")), "-", json_string_value(json_object_get(j_element, "username"))));
  }
  return G_OK;
}

/**
 *
 * user_middleware_module_get
 *
 * Update a user returned by user_get
 *
 * @return value: G_OK on success, another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username corresponding to the j_user object
 * @parameter j_user: The user returned by the user backend module
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_middleware_module_get(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(username);
  json_object_set_new(j_user, "middleware", json_pack("s++", json_string_value(json_object_get((json_t *)cls, "middleware")), "-", username));
  return G_OK;
}

/**
 *
 * user_middleware_module_get_profile
 *
 * Update a user returned by user_get_profile
 *
 * @return value: G_OK on success, another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username corresponding to the j_user object
 * @parameter j_user: The user returned by the user backend module
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_middleware_module_get_profile(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(username);
  json_object_set_new(j_user, "middleware", json_pack("s+++", json_string_value(json_object_get((json_t *)cls, "middleware")), "-", username, "-profile"));
  return G_OK;
}

/**
 *
 * user_middleware_module_update
 *
 * Update a user before being passed to the backend functions
 * user_module_add, user_module_update, user_module_update_profile
 * or user_module_is_valid
 *
 * @return value: G_OK on success, another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username corresponding to the j_user object
 * @parameter j_user: The user returned by the API
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_middleware_module_update(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  json_object_del(j_user, "middleware");
  return G_OK;
}

/**
 *
 * user_middleware_module_delete
 * 
 * Update a user before being passed to the backend function user_module_delete
 *
 * @return value: G_OK on success, another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username corresponding to the j_user object
 * @parameter j_user: The user returned by the API
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_middleware_module_delete(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  json_object_del(j_user, "middleware");
  return G_OK;
}

/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * HTTP Basic authentication scheme module
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
#include "../glewlwyd-common.h"

/**
 *
 * Note on the user auth scheme module
 *
 * It's possible for the scheme module to get or store any value in the user object returned by the functions
 * struct config_module.glewlwyd_module_callback_get_user()
 * struct config_module.glewlwyd_module_callback_set_user()
 *
 * Although, the module can't know if any value, other than "name", "password", "email" or "enabled" can be added or updated by the scheme module
 * The scheme module can store its specific data for each user by itself or store the data in the user object, or both, this will depend on the implementation
 *
 * The format of the structure config_module is:
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
  return json_pack("{sisssssss{s{ssso}s{sssoso}s{ssso}}}",
                   "result",
                   G_OK,
                   "name",
                   "http",
                   "display_name",
                   "HTTP Basic Authentication",
                   "description",
                   "Authenticate users against a HTTP webservice that uses HTTP Basic Authentication",
                   "parameters",
                     "url",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                     "check-server-certificate",
                       "type",
                       "boolean",
                       "mandatory",
                       json_false(),
                       "default",
                       json_true(),
                     "username-format",
                       "type",
                       "string",
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
  json_t * j_return = NULL;
  int ret;
  
  if (json_is_object(j_parameters)) {
    ret = G_OK;
    if (!json_string_length(json_object_get(j_parameters, "url"))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init http - parameter url is mandatory must be a non empty string");
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "parameter url is mandatory must be a non empty string");
      ret = G_ERROR_PARAM;
    } else if (json_object_get(j_parameters, "check-server-certificate") != NULL && !json_is_boolean(json_object_get(j_parameters, "check-server-certificate"))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init http - parameter check-server-certificate is optional and must be a boolean");
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "parameter check-server-certificate is optional and must be a boolean");
    } else if (json_string_length(json_object_get(j_parameters, "username-format")) && o_strstr(json_string_value(json_object_get(j_parameters, "username-format")), "{USERNAME}") == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init http - parameter username-format is optional and must contain {USERNAME}");
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "parameter username-format is optional and must contain {USERNAME}");
      ret = G_ERROR_PARAM;
    }
    if (ret == G_OK) {
      j_return = json_pack("{si}", "result", G_OK);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init http - parameters must be a JSON object");
    ret = G_ERROR_PARAM;
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "parameters must be a JSON object");
  }
  if (ret == G_OK) {
    *cls = json_incref(j_parameters);
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
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  return GLEWLWYD_IS_AVAILABLE;
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
  UNUSED(username);
  UNUSED(j_scheme_data);
  UNUSED(cls);

  return json_pack("{siso}", "result", G_OK, "response", json_true());
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

  return json_pack("{sisO}", "result", G_OK, "response", json_true());
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
  struct _u_request request;
  struct _u_response response;
  int res, ret;
  
  if (json_string_length(json_object_get(j_scheme_data, "password"))) {
    ulfius_init_request(&request);
    ulfius_init_response(&response);
    request.http_verb = o_strdup("GET");
    request.http_url = o_strdup(json_string_value(json_object_get((json_t *)cls, "url")));
    if (json_object_get((json_t *)cls, "check-server-certificate") == json_false()) {
      request.check_server_certificate = 0;
    }
    if (json_string_length(json_object_get((json_t *)cls, "username-format"))) {
      request.auth_basic_user = str_replace(json_string_value(json_object_get((json_t *)cls, "username-format")), "{USERNAME}", username);
    } else {
      request.auth_basic_user = o_strdup(username);
    }
    request.auth_basic_password = o_strdup(json_string_value(json_object_get(j_scheme_data, "password")));
    
    res = ulfius_send_http_request(&request, &response);
    if (res == H_OK) {
      if (response.status == 200) {
        ret = G_OK;
      } else {
        if (response.status != 401 && response.status != 403) {
          y_log_message(Y_LOG_LEVEL_WARNING, "user_auth_scheme_module_validate http - Error connecting to webservice %s, response status is %d", request.http_url, response.status);
        }
        ret = G_ERROR_UNAUTHORIZED;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_validate http - Error ulfius_send_http_request");
      ret = G_ERROR_UNAUTHORIZED;
    }
    
    ulfius_clean_request(&request);
    ulfius_clean_response(&response);
  } else {
    ret = G_ERROR_UNAUTHORIZED;
  }
  return ret;
}

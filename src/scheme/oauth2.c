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
  json_t * j_errors = json_array(), * j_return, * j_element = NULL;
  size_t index = 0;
  char * message;
  const char * name;
  
  if (j_errors != NULL) {
    if (json_is_object(j_params)) {
      if (!json_string_length(json_object_get(j_params, "callback_uri"))) {
        json_array_append_new(j_errors, json_string("callback_uri is mandatory and must be a non empty string"));
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
          if (!json_string_length(json_object_get(j_element, "redirect_uri"))) {
            message = msprintf("redirect_uri string is missing for provider '%s' at index %zu", name, index);
            json_array_append_new(j_errors, json_string(message));
            o_free(message);
          }
          if (!json_string_length(json_object_get(j_element, "userid_property"))) {
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
          if (!json_string_length(json_object_get(j_element, "config_endpoint")) && !json_string_length(json_object_get(j_element, "auth_endpoint"))) {
            message = msprintf("You must set config_endpoint or auth_endpoint is mandatory for provider '%s' at index %zu", name, index);
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
                     "callback_uri",
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
                       "redirect_uri",
                         "type",
                         "string",
                         "mandatory",
                         json_true(),
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
  char * str_error;
  size_t index = 0;
  struct _i_session i_session;
  
  j_result = is_scheme_parameters_valid(j_parameters);
  if (check_result_value(j_result, G_OK)) {
    *cls = json_pack("{sssOs[]}", "name", mod_name, "callback_uri", json_object_get(j_parameters, "callback_uri"), "provider_list");
    if (*cls != NULL) {
      json_array_foreach(json_object_get(j_parameters, "provider_list"), index, j_element) {
        if (i_init_session(&i_session) == I_OK) {
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
              json_array_append(json_object_get(((json_t *)*cls), "provider_list"), j_export);
            }
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
              json_array_append(json_object_get(((json_t *)*cls), "provider_list"), j_export);
            }
          }
          i_clean_session(&i_session);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init oauth2 - Error i_init_session");
        }
      }
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
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  return GLEWLWYD_IS_NOT_AVAILABLE;
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

  return json_pack("{si}", "result", G_ERROR);
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

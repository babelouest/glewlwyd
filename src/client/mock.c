/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Mock client module
 * 
 * Copyright 2016-2020 Nicolas Mora <mail@babelouest.org>
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
 *
 * Note on the client module
 *
 * The JSON object of the client has the following format concerning the reserved properties:
 * {
 *   "client_id": string, client_id of the user (its login), must be at most 128 characters and unique among the current instance
 *   "name": string, full name
 *   "description": string, description for the client
 *   "confidential": boolean, flag to set if the user is confidential or not (used in oauth2 and oidc)
 *   "scope": array of strings, scopes available for the user, each scope must be a string of at most 128 characters
 *   "enabled": boolean, if false, the user won't be able to connect
 * }
 *
 * - The username shouldbn't be updated after creation
 * - How the password is stored and encrypted is up to the implementation.
 *   Although the password encrypted or not SHOULDN'T be returned in the user object
 * - The scope values mustn't be updated in profile mode, to avoid a user to change his or her own credential
 * - The "enabled" property is mandatory in the returned values of user_module_get_list or user_module_get
 *   If a user doesn't have "enabled":true set, then it will be unavailable for connection
 * 
 * The only mandatory values are username and anabled, other values are optional
 * Other values can be handled by the module, it's up to the implementation
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

static int json_has_str_pattern_case(json_t * j_source, const char * pattern) {
  const char * key = NULL;
  size_t index = 0;
  json_t * j_element = NULL;

  if (j_source != NULL) {
    if (json_is_string(j_source) && o_strcasestr(json_string_value(j_source), pattern) != NULL) {
      return 1;
    } else if (json_is_object(j_source)) {
      json_object_foreach(j_source, key, j_element) {
        if (json_has_str_pattern_case(j_element, pattern)) {
          return 1;
        }
      }
      return 0;
    } else if (json_is_array(j_source)) {
      json_array_foreach(j_source, index, j_element) {
        if (json_has_str_pattern_case(j_element, pattern)) {
          return 1;
        }
      }
      return 0;
    } else {
      return 0;
    }
  } else {
    return 0;
  }
}

/**
 * 
 * client_module_load
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
json_t * client_module_load(struct config_module * config) {
  UNUSED(config);
  return json_pack("{sissssss}",
                   "result", G_OK,
                   "name", "mock",
                   "display_name", "Mock scheme module",
                   "description", "Mock scheme module for glewlwyd tests");
}

/**
 * 
 * client_module_unload
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
int client_module_unload(struct config_module * config) {
  UNUSED(config);
  return G_OK;
}

/**
 * 
 * client_module_init
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
json_t * client_module_init(struct config_module * config, int readonly, json_t * j_parameters, void ** cls) {
  UNUSED(readonly);
  const char * prefix = "";
  json_t * j_return;

  if (json_object_get(j_parameters, "error") == NULL) {
    if (!json_string_null_or_empty(json_object_get(j_parameters, "client-id-prefix"))) {
      prefix = json_string_value(json_object_get(j_parameters, "client-id-prefix"));
    }
    *cls = (void*)json_pack("[{ss+ ss ss so s[ssssss] s[sss] ss s[] so}{ss+ ss ss so s[s] s[s] s[] so}{ss+ ss ss so ss s[s] s[ssssssss] s[ss] ss s[ss] so}{ss+ ss ss so ss s[s] s[ssss] s[s] ss so ss}]",
                              "client_id",
                              prefix,
                              "client1_id",
                              "name",
                              "client1",
                              "description",
                              "Client mock 1",
                              "confidential",
                              json_false(),
                              "authorization_type",
                                "code",
                                "token",
                                "id_token",
                                "none",
                                "refresh_token",
                                "delete_token",
                              "redirect_uri",
                                "../../test-oauth2.html?param=client1_cb1",
                                "../../test-oauth2.html?param=client1_cb2",
                                "../../test-oidc.html?param=client1_cb1",
                              "sector_identifier_uri",
                                "https://sector1.glewlwyd.tld",
                              "scope",
                              "enabled",
                              json_true(),
                              "client_id",
                              prefix,
                              "client2_id",
                              "name",
                              "client2",
                              "description",
                              "Client mock 2",
                              "confidential",
                              json_false(),
                              "authorization_type",
                                "code",
                              "redirect_uri",
                                "../../test-oauth2.html?param=client2",
                              "scope",
                              "enabled",
                              json_true(),
                              "client_id",
                              prefix,
                              "client3_id",
                              "name",
                              "client3",
                              "description",
                              "Client mock 3",
                              "confidential",
                              json_true(),
                              "password",
                              "password",
                              "token_endpoint_auth_method",
                                "client_secret_basic",
                              "authorization_type",
                                "code",
                                "token",
                                "id_token",
                                "none",
                                "password",
                                "client_credentials",
                                "refresh_token",
                                "delete_token",
                              "redirect_uri",
                                "../../test-oauth2.html?param=client3",
                                "../../test-oidc.html?param=client3",
                              "sector_identifier_uri",
                                "https://sector1.glewlwyd.tld",
                              "scope",
                                "scope2",
                                "scope3",
                              "enabled",
                              json_true(),
                              "client_id",
                              prefix,
                              "client4_id",
                              "name",
                              "client4",
                              "description",
                              "Client mock 4",
                              "confidential",
                              json_true(),
                              "client_secret",
                              "secret",
                              "token_endpoint_auth_method",
                                "client_secret_basic",
                              "authorization_type",
                                "code",
                                "token",
                                "id_token",
                                "client_credentials",
                              "redirect_uri",
                                "../../test-oidc.html?param=client4",
                              "sector_identifier_uri",
                                "https://sector4.glewlwyd.tld",
                              "enabled",
                              json_true(),
                              "request_object_signing_alg",
                              "HS256");
    y_log_message(Y_LOG_LEVEL_DEBUG, "client_module_init - success %s %s, prefix: '%s'", config->profile_scope, config->admin_scope, prefix);
    j_return = json_pack("{si}", "result", G_OK);
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "Error input parameters");
  }
  return j_return;
}

/**
 * 
 * client_module_close
 * 
 * Close an instance of this module declared in Glewlwyd service.
 * You must free the memory previously allocated in
 * the client_module_init function as void * cls
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter cls: pointer to the void * cls value allocated in client_module_init
 * 
 */
int client_module_close(struct config_module * config, void * cls) {
  UNUSED(config);
  y_log_message(Y_LOG_LEVEL_DEBUG, "client_module_close - success");
  json_decref((json_t *)cls);
  return G_OK;
}

/**
 *
 * client_module_count_total
 *
 * Return the total number of clients handled by this module corresponding
 * to the given pattern
 *
 * @return value: The total of corresponding clients
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter pattern: The pattern to match for the clients. How the
 *                     pattern is used is up to the implementation.
 *                     Glewlwyd recommends to match the pattern with the
 *                     client_id, name and description value for each clients
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
size_t client_module_count_total(struct config_module * config, const char * pattern, void * cls) {
  UNUSED(config);
  size_t index = 0, total;
  json_t * j_user = NULL;

  if (!o_strnullempty(pattern)) {
    total = 0;
    json_array_foreach((json_t *)cls, index, j_user) {
      if (json_has_str_pattern_case(j_user, pattern)) {
        total++;
      }
    }
  } else {
    total = json_array_size((json_t *)cls);
  }
  return total;
}

/**
 *
 * client_module_get_list
 *
 * Return a list of clients handled by this module corresponding
 * to the given pattern between the specified offset and limit
 * These are the client objects returned to the administrator
 *
 * @return value: A list of corresponding clients or an empty list
 *                using the following JSON format: {"result":G_OK,"list":[{client object}]}
 *                On error, this function must return another value for "result"
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter pattern: The pattern to match for the clients. How the
 *                     pattern is used is up to the implementation.
 *                     Glewlwyd recommends to match the pattern with the
 *                     client_id, name and description value for each clients
 * @pattern offset: The offset to reduce the returned list among the total list
 * @pattern limit: The maximum number of clients to return
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
json_t * client_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls) {
  UNUSED(config);
  json_t * j_user = NULL, * j_array, * j_array_pattern, * j_return, * j_user_copy;
  size_t index = 0, counter = 0;

  if (limit > 0) {
    if (!o_strnullempty(pattern)) {
      j_array_pattern = json_array();
      json_array_foreach((json_t *)cls, index, j_user) {
        if (json_has_str_pattern_case(j_user, pattern)) {
          json_array_append(j_array_pattern, j_user);
        }
      }
    } else {
      j_array_pattern = json_copy((json_t *)cls);
    }
    j_array = json_array();
    if (j_array != NULL) {
      json_array_foreach(j_array_pattern, index, j_user) {
        if (index >= offset && (offset + counter) < json_array_size(j_array_pattern) && counter < limit) {
          j_user_copy = json_deep_copy(j_user);
          json_object_del(j_user_copy, "password");
          json_array_append_new(j_array, j_user_copy);
          counter++;
        }
      }
      j_return = json_pack("{sisO}", "result", G_OK, "list", j_array);
      json_decref(j_array);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_array_pattern);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

/**
 *
 * client_module_get
 *
 * Return a client object handled by this module corresponding
 * to the client_id specified
 *
 * @return value: G_OK and the corresponding client
 *                G_ERROR_NOT_FOUND if client_id is not found
 *                The returned format is {"result":G_OK,"client":{client object}}
 *                On error, this function must return another value for "result"
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter client_id: the client_id to match, must be case insensitive
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
json_t * client_module_get(struct config_module * config, const char * client_id, void * cls) {
  UNUSED(config);
  json_t * j_client = NULL, * j_return = NULL;
  size_t index = 0;
  
  if (client_id != NULL && !o_strnullempty(client_id)) {
    json_array_foreach((json_t *)cls, index, j_client) {
      if (0 == o_strcmp(client_id, json_string_value(json_object_get(j_client, "client_id")))) {
        j_return = json_pack("{siso}", "result", G_OK, "client", json_deep_copy(j_client));
        break;
      }
    }
    if (j_return == NULL) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

/**
 *
 * client_module_is_valid
 *
 * Validate if a client is valid to save for the specified mode
 *
 * @return value: G_OK if the client is valid
 *                G_ERROR_PARAM and an array containing the errors in string format
 *                The returned format is {"result":G_OK} on success
 *                {"result":G_ERROR_PARAM,"error":["error 1","error 2"]} on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter client_id: the client_id to match, must be case insensitive
 * @parameter j_client: The client to validate
 * @parameter mode: The mode corresponding to the context, values available are:
 *                  - GLEWLWYD_IS_VALID_MODE_ADD: Add a client by an administrator
 *                    Note: in this mode, the module musn't check for already existing client,
 *                          This is already handled by Glewlwyd
 *                  - GLEWLWYD_IS_VALID_MODE_UPDATE: Update a client by an administrator
 * @parameter cls: pointer to the void * cls value allocated in client_module_init
 * 
 */
json_t * client_module_is_valid(struct config_module * config, const char * client_id, json_t * j_client, int mode, void * cls) {
  UNUSED(config);
  UNUSED(cls);
  json_t * j_return = NULL;

  if ((mode == GLEWLWYD_IS_VALID_MODE_UPDATE || mode == GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) && client_id == NULL) {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "client_id is mandatory on update mode");
  } else {
    if (json_is_object(j_client)) {
      if (mode == GLEWLWYD_IS_VALID_MODE_ADD) {
        if (json_is_string(json_object_get(j_client, "client_id")) && json_string_length(json_object_get(j_client, "client_id")) <= 128) {
          j_return = json_pack("{si}", "result", G_OK);
        } else {
          j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "client_id must be a string value of maximum 128 characters");
        }
      } else {
        j_return = json_pack("{si}", "result", G_OK);
      }
    } else {
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "client must be a JSON object");
    }
  }

  return j_return;
}

/**
 *
 * client_module_add
 *
 * Add a new client by an administrator
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter j_client: The client to add
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int client_module_add(struct config_module * config, json_t * j_client, void * cls) {
  UNUSED(config);
  json_array_append((json_t *)cls, j_client);
  return G_OK;
}

/**
 *
 * client_module_update
 *
 * Update an existing client by an administrator
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter client_id: the client_id to match, must be case insensitive
 * @parameter j_client: The client to update. If this function must replace all values or 
 *                    only the given ones or any other solution is up to the implementation
 * @parameter cls: pointer to the void * cls value allocated in client_module_init
 * 
 */
int client_module_update(struct config_module * config, const char * client_id, json_t * j_client, void * cls) {
  UNUSED(config);
  size_t index = 0;
  int ret, found = 0;
  json_t * j_element = NULL, * j_property;
  const char * key;
  
  json_array_foreach((json_t *)cls, index, j_element) {
    if (0 == o_strcmp(client_id, json_string_value(json_object_get(j_element, "client_id")))) {
      json_object_set_new(j_client, "client_id", json_string(client_id));
      json_object_foreach(j_client, key, j_property) {
        if (j_property != json_null()) {
          json_object_set(j_element, key, j_property);
        } else {
          json_object_del(j_element, key);
        }
      }
      ret = G_OK;
      found = 1;
      break;
    }
  }
  if (!found) {
    ret = G_ERROR_NOT_FOUND;
  }
  return ret;
}

/**
 *
 * client_module_delete
 *
 * Delete an existing client by an administrator
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter client_id: the client_id to match, must be case insensitive
 * @parameter cls: pointer to the void * cls value allocated in client_module_init
 * 
 */
int client_module_delete(struct config_module * config, const char * client_id, void * cls) {
  UNUSED(config);
  json_t * j_client = NULL;
  size_t index = 0;
  int ret, found = 0;
  
  json_array_foreach((json_t *)cls, index, j_client) {
    if (0 == o_strcmp(client_id, json_string_value(json_object_get(j_client, "client_id")))) {
      json_array_remove((json_t *)cls, index);
      ret = G_OK;
      found = 1;
      break;
    }
  }
  if (!found) {
    ret = G_ERROR_NOT_FOUND;
  }
  return ret;
}

/**
 *
 * client_module_check_password
 *
 * Validate the password of an existing client
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter client_id: the client_id to match, must be case insensitive
 * @parameter password: the password to validate
 * @parameter cls: pointer to the void * cls value allocated in client_module_init
 * 
 */
int client_module_check_password(struct config_module * config, const char * client_id, const char * password, void * cls) {
  UNUSED(config);
  int ret;
  json_t * j_client = client_module_get(config, client_id, cls);
  
  if (check_result_value(j_client, G_OK)) {
    if (json_object_get(json_object_get(j_client, "client"), "confidential") == json_true() && 0 == o_strcmp(password, "password")) {
      ret = G_OK;
    } else {
      ret = G_ERROR_UNAUTHORIZED;
    }
  } else {
    ret = G_ERROR_NOT_FOUND;
  }
  json_decref(j_client);
  return ret;
}

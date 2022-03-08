/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Mock user module
 * 
 * Copyright 2019-2020 Nicolas Mora <mail@babelouest.org>
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
 * Note on the user module
 *
 * The JSON object of the user has the following format concerning the reserved properties:
 * {
 *   "username": string, username of the user (its login), must be at most 128 characters and unique among the current instance
 *   "name": string, full name
 *   "scope": array of strings, scopes available for the user, each scope must be a string of at most 128 characters
 *   "enabled": boolean, if false, the user won't be able to connect
 * }
 *
 * - The username shouldn't be updated after creation
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
 * user_module_load
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
json_t * user_module_load(struct config_module * config) {
  UNUSED(config);
  return json_pack("{sisssssssf}",
                   "result", G_OK,
                   "name", "mock",
                   "display_name", "Mock user module",
                   "description", "Mock user module for glewlwyd tests",
                   "api_version", 2.5);
}

/**
 * 
 * user_module_unload
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
int user_module_unload(struct config_module * config) {
  UNUSED(config);
  return G_OK;
}

/**
 * 
 * user_module_init
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
json_t * user_module_init(struct config_module * config, int readonly, int multiple_passwords, json_t * j_parameters, void ** cls) {
  UNUSED(readonly);
  json_t * j_return, * j_password = NULL;
  const char * password = json_string_value(json_object_get(j_parameters, "password"));
  
  if (json_object_get(j_parameters, "error") == NULL) {
    const char * prefix = "";
    if (!json_string_null_or_empty(json_object_get(j_parameters, "username-prefix"))) {
      prefix = json_string_value(json_object_get(j_parameters, "username-prefix"));
    }
    if (password == NULL) {
      password = "password";
    }
    if (multiple_passwords) {
      j_password = json_pack("[s]", password);
    } else {
      j_password = json_string(password);
    }
    *cls = (void*)json_pack("{sos[{ss+ ss ss so s[sss]}{ss+ ss ss so s[sssss]}{ss+ ss ss so s[sss]}{ss+ ss ss so s[ssss]}]}",
                            "password", j_password,
                            "list",
                              "username", prefix, "admin", 
                              "name", "The Boss", 
                              "email", "boss@glewlwyd.domain",
                              "enabled",json_true(),
                              "scope",
                                config->admin_scope,
                                config->profile_scope,
                                "openid",

                              "username", prefix, "user1",
                              "name", "Dave Lopper 1",
                              "email", "dev1@glewlwyd",
                              "enabled", json_true(),
                              "scope",
                                config->profile_scope,
                                "openid",
                                "scope1",
                                "scope2",
                                "scope3",

                              "username", prefix, "user2",
                              "name", "Dave Lopper 2",
                              "email", "dev2@glewlwyd",
                              "enabled", json_true(),
                              "scope",
                                config->profile_scope,
                                "openid",
                                "scope1",

                              "username", prefix, "user3",
                              "name", "Dave Lopper 3",
                              "email", "dev3@glewlwyd",
                              "enabled", json_true(),
                              "scope",
                                config->profile_scope,
                                "scope1",
                                "scope2",
                                "scope3");
    y_log_message(Y_LOG_LEVEL_DEBUG, "user_module_init - success prefix: '%s', profile_scope: '%s', admin_scope: '%s'", prefix, config->profile_scope, config->admin_scope);
    j_return = json_pack("{si}", "result", G_OK);
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "Error input parameters");
  }
  return j_return;
}

/**
 * 
 * user_module_close
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
int user_module_close(struct config_module * config, void * cls) {
  UNUSED(config);
  y_log_message(Y_LOG_LEVEL_DEBUG, "user_module_close - success");
  json_decref((json_t *)cls);
  return G_OK;
}

/**
 *
 * user_module_count_total
 *
 * Return the total number of users handled by this module corresponding
 * to the given pattern
 *
 * @return value: The total of corresponding users
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter pattern: The pattern to match for the users. How the
 *                     pattern is used is up to the implementation.
 *                     Glewlwyd recommends to match the pattern with the
 *                     username, name and e-mail value for each users
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
size_t user_module_count_total(struct config_module * config, const char * pattern, void * cls) {
  UNUSED(config);
  json_t * j_user = NULL;
  size_t index = 0, total;

  if (!o_strnullempty(pattern)) {
    total = 0;
    json_array_foreach(json_object_get((json_t *)cls, "list"), index, j_user) {
      if (json_has_str_pattern_case(j_user, pattern)) {
        total++;
      }
    }
  } else {
    total = json_array_size(json_object_get((json_t *)cls, "list"));
  }
  return total;
}

/**
 *
 * user_module_get_list
 *
 * Return a list of users handled by this module corresponding
 * to the given pattern between the specified offset and limit
 * These are the user objects returned to the administrator
 *
 * @return value: A list of corresponding users or an empty list
 *                using the following JSON format: {"result":G_OK,"list":[{user object}]}
 *                On error, this function must return another value for "result"
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter pattern: The pattern to match for the users. How the
 *                     pattern is used is up to the implementation.
 *                     Glewlwyd recommends to match the pattern with the
 *                     username, name and e-mail value for each users
 * @pattern offset: The offset to reduce the returned list among the total list
 * @pattern limit: The maximum number of users to return
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
json_t * user_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls) {
  UNUSED(config);
  json_t * j_user = NULL, * j_array, * j_pattern_array, * j_return;
  size_t index = 0, counter = 0;
  json_int_t password = -1;

  if (json_is_array(json_object_get((json_t *)cls, "password"))) {
    password = (json_int_t)json_array_size(json_object_get((json_t *)cls, "password"));
  }
  if (limit) {
    if (!o_strnullempty(pattern)) {
      j_pattern_array = json_array();
      json_array_foreach(json_object_get((json_t *)cls, "list"), index, j_user) {
        if (json_has_str_pattern_case(j_user, pattern)) {
          json_array_append_new(j_pattern_array, json_deep_copy(j_user));
        }
      }
    } else {
      j_pattern_array = json_deep_copy(json_object_get((json_t *)cls, "list"));
    }
    j_array = json_array();
    if (j_array != NULL) {
      json_array_foreach(j_pattern_array, index, j_user) {
        if (index >= offset && (offset + counter) < json_array_size(j_pattern_array) && counter < limit) {
          if (password > -1) {
            json_object_set_new(j_user, "password", json_integer(password));
          }
          json_array_append(j_array, j_user);
          counter++;
        }
      }
      j_return = json_pack("{sisO}", "result", G_OK, "list", j_array);
      json_decref(j_array);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_pattern_array);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

/**
 *
 * user_module_get
 *
 * Return a user object handled by this module corresponding
 * to the username specified
 * This is the user object returned to the administrator
 *
 * @return value: G_OK and the corresponding user
 *                G_ERROR_NOT_FOUND if username is not found
 *                The returned format is {"result":G_OK,"user":{user object}}
 *                On error, this function must return another value for "result"
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
json_t * user_module_get(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  json_t * j_user = NULL, * j_new_user;
  size_t index = 0;
  
  if (username != NULL && !o_strnullempty(username)) {
    json_array_foreach(json_object_get((json_t *)cls, "list"), index, j_user) {
      if (0 == o_strcmp(username, json_string_value(json_object_get(j_user, "username")))) {
        j_new_user = json_deep_copy(j_user);
        if (json_is_array(json_object_get((json_t *)cls, "password"))) {
          json_object_set_new(j_new_user, "password", json_integer(json_array_size(json_object_get((json_t *)cls, "password"))));
        }
        return json_pack("{siso}", "result", G_OK, "user", j_new_user);
        break;
      }
    }
      return json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  } else {
    return json_pack("{si}", "result", G_ERROR);
  }
}

/**
 *
 * user_module_get_profile
 *
 * Return a user object handled by this module corresponding
 * to the username specified.
 * This is the user object returned to the connected user, may be different from the 
 * user_module_get object format if a connected user must have access to different data
 *
 * @return value: G_OK and the corresponding user
 *                G_ERROR_NOT_FOUND if username is not found
 *                The returned format is {"result":G_OK,"user":{user object}}
 *                On error, this function must return another value for "result"
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
json_t * user_module_get_profile(struct config_module * config, const char * username, void * cls) {
  return user_module_get(config, username, cls);
}

/**
 *
 * user_module_is_valid
 *
 * Validate if a user is valid to save for the specified mode
 *
 * @return value: G_OK if the user is valid
 *                G_ERROR_PARAM and an array containing the errors in string format
 *                The returned format is {"result":G_OK} on success
 *                {"result":G_ERROR_PARAM,"error":["error 1","error 2"]} on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter j_user: The user to validate
 * @parameter mode: The mode corresponding to the context, values available are:
 *                  - GLEWLWYD_IS_VALID_MODE_ADD: Add a user by an administrator
 *                    Note: in this mode, the module musn't check for already existing user,
 *                          This is already handled by Glewlwyd
 *                  - GLEWLWYD_IS_VALID_MODE_UPDATE: Update a user by an administrator
 *                  - GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE: Update a user by him or 
 *                                                           herself in the profile context
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
json_t * user_module_is_valid(struct config_module * config, const char * username, json_t * j_user, int mode, void * cls) {
  UNUSED(config);
  json_t * j_return = NULL;

  if ((mode == GLEWLWYD_IS_VALID_MODE_UPDATE || mode == GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) && username == NULL) {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "username is mandatory on update mode");
  } else {
    if (mode == GLEWLWYD_IS_VALID_MODE_ADD) {
      if (json_is_string(json_object_get(j_user, "username")) && json_string_length(json_object_get(j_user, "username")) <= 128) {
        if (json_object_get(j_user, "password") != NULL) {
          if (json_is_array(json_object_get((json_t *)cls, "password")) && json_is_array(json_object_get(j_user, "password"))) {
            j_return = json_pack("{si}", "result", G_OK);
          } else if (!json_is_array(json_object_get((json_t *)cls, "password")) && json_string_length(json_object_get(j_user, "password"))) {
            j_return = json_pack("{si}", "result", G_OK);
          } else {
            j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "invalid password");
          }
        } else {
          j_return = json_pack("{si}", "result", G_OK);
        }
      } else {
        j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "username must be a string value of maximum 128 characters");
      }
    } else {
      if (json_object_get(j_user, "password") != NULL) {
        if (json_is_array(json_object_get((json_t *)cls, "password")) && json_is_array(json_object_get(j_user, "password"))) {
          j_return = json_pack("{si}", "result", G_OK);
        } else if (!json_is_array(json_object_get((json_t *)cls, "password")) && json_string_length(json_object_get(j_user, "password"))) {
          j_return = json_pack("{si}", "result", G_OK);
        } else {
          j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "invalid password");
        }
      } else {
        j_return = json_pack("{si}", "result", G_OK);
      }
    }
  }
  return j_return;
}

/**
 *
 * user_module_add
 *
 * Add a new user by an administrator
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter j_user: The user to add
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_module_add(struct config_module * config, json_t * j_user, void * cls) {
  UNUSED(config);
  json_t * j_password, * j_pwd_cur, * j_pwd_next;
  size_t index = 0, pwd_max = 0;
  
  if (json_object_get(j_user, "password") != NULL) {
    if (json_is_array(json_object_get((json_t *)cls, "password"))) {
      j_password = json_array();
      pwd_max = MAX(json_array_size(json_object_get(j_user, "password")), json_array_size(json_object_get((json_t *)cls, "password")));
      for (index=0; index<pwd_max; index++) {
        j_pwd_cur = json_array_get(json_object_get((json_t *)cls, "password"), index);
        j_pwd_next = json_array_get(json_object_get(j_user, "password"), index);
        
        if (!json_string_null_or_empty(j_pwd_next)) {
          json_array_append(j_password, j_pwd_next);
        } else if (j_pwd_cur != NULL && 0 == o_strcmp("", json_string_value(j_pwd_next))) {
          json_array_append(j_password, j_pwd_cur);
        }
      }
      json_object_set_new((json_t *)cls, "password", j_password);
    } else {
      if (!json_string_null_or_empty(json_object_get(j_user, "password"))) {
        json_object_set((json_t *)cls, "password", json_object_get(j_user, "password"));
      } else {
        json_object_set((json_t *)cls, "password", json_null());
      }
    }
  }
  json_array_append(json_object_get((json_t *)cls, "list"), j_user);
  return G_OK;
}

/**
 *
 * user_module_update
 *
 * Update an existing user by an administrator
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter j_user: The user to update. If this function must replace all values or 
 *                    only the given ones or any other solution is up to the implementation
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_module_update(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  json_t * j_element = NULL, * j_property, * j_password, * j_pwd_cur, * j_pwd_next;
  size_t index = 0, pwd_max = 0;
  int found = 0, ret;
  const char * key;
  
  if (json_object_get(j_user, "password") != NULL) {
    if (json_is_array(json_object_get((json_t *)cls, "password"))) {
      j_password = json_array();
      pwd_max = MAX(json_array_size(json_object_get(j_user, "password")), json_array_size(json_object_get((json_t *)cls, "password")));
      for (index=0; index<pwd_max; index++) {
        j_pwd_cur = json_array_get(json_object_get((json_t *)cls, "password"), index);
        j_pwd_next = json_array_get(json_object_get(j_user, "password"), index);
        
        if (!json_string_null_or_empty(j_pwd_next)) {
          json_array_append(j_password, j_pwd_next);
        } else if (j_pwd_cur != NULL && 0 == o_strcmp("", json_string_value(j_pwd_next))) {
          json_array_append(j_password, j_pwd_cur);
        }
      }
      json_object_set_new((json_t *)cls, "password", j_password);
    } else {
      if (!json_string_null_or_empty(json_object_get(j_user, "password"))) {
        json_object_set((json_t *)cls, "password", json_object_get(j_user, "password"));
      } else {
        json_object_set((json_t *)cls, "password", json_null());
      }
    }
  }
  json_array_foreach(json_object_get((json_t *)cls, "list"), index, j_element) {
    if (0 == o_strcmp(username, json_string_value(json_object_get(j_element, "username")))) {
      json_object_set_new(j_user, "username", json_string(username));
      json_object_foreach(j_user, key, j_property) {
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
 * user_module_update_profile
 *
 * Update an existing user in the profile context
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter j_user: The user to update. If this function must replace all values or 
 *                    only the given ones or any other solution is up to the implementation
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_module_update_profile(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  return user_module_update(config, username, j_user, cls);
}

/**
 *
 * user_module_delete
 *
 * Delete an existing user by an administrator
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_module_delete(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  json_t * j_user = NULL;
  size_t index = 0;
  int ret, found = 0;
  
  json_array_foreach(json_object_get((json_t *)cls, "list"), index, j_user) {
    if (0 == o_strcmp(username, json_string_value(json_object_get(j_user, "username")))) {
      json_array_remove(json_object_get((json_t *)cls, "list"), index);
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
 * user_module_check_password
 *
 * Validate the password of an existing user
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter password: the password to validate
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_module_check_password(struct config_module * config, const char * username, const char * password, void * cls) {
  int ret;
  json_t * j_user = user_module_get(config, username, cls), * j_element = NULL;
  size_t index = 0;
  
  if (check_result_value(j_user, G_OK)) {
    if (json_is_array(json_object_get((json_t *)cls, "password"))) {
      ret = G_ERROR_UNAUTHORIZED;
      json_array_foreach(json_object_get((json_t *)cls, "password"), index, j_element) {
        if (0 == o_strcmp(password, json_string_value(j_element))) {
          ret = G_OK;
        }
      }
    } else {
      if (0 == o_strcmp(password, json_string_value(json_object_get((json_t *)cls, "password")))) {
        ret = G_OK;
      } else {
        ret = G_ERROR_UNAUTHORIZED;
      }
    }
  } else {
    ret = G_ERROR_NOT_FOUND;
  }
  json_decref(j_user);
  return ret;
}

/**
 *
 * user_module_update_password
 *
 * Update the password only of an existing user
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter new_password: the new password
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_module_update_password(struct config_module * config, const char * username, const char ** new_passwords, size_t new_passwords_len, void * cls) {
  UNUSED(config);
  UNUSED(cls);
  UNUSED(username);
  json_t * j_password;
  size_t index = 0;
  
  if (json_is_array(json_object_get((json_t *)cls, "password"))) {
    j_password = json_array();
    for (index=0; index<new_passwords_len; index++) {
      if (!o_strnullempty(new_passwords[index])) {
        json_array_append_new(j_password, json_string(new_passwords[index]));
      } else if (new_passwords[index] != NULL && !json_string_null_or_empty(json_array_get(json_object_get((json_t *)cls, "password"), index))) {
        json_array_append(j_password, json_array_get(json_object_get((json_t *)cls, "password"), index));
      }
    }
    json_object_set_new((json_t *)cls, "password", j_password);
  } else {
    if (new_passwords_len && new_passwords[0] != NULL) {
      json_object_set_new((json_t *)cls, "password", json_string(new_passwords[0]));
    } else {
      json_object_set((json_t *)cls, "password", json_null());
    }
  }
  return G_OK;
}

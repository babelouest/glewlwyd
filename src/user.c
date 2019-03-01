/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * user management functions definition
 *
 * Copyright 2016-2019 Nicolas Mora <mail@babelouest.org>
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
#include "glewlwyd.h"

json_t * auth_check_user_credentials(struct config_elements * config, const char * username, const char * password) {
  int res;
  json_t * j_return = NULL, * j_module_list = get_user_module_list(config), * j_module;
  struct _user_module_instance * user_module;
  size_t index;
  
  if (check_result_value(j_module_list, G_OK)) {
    json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
      user_module = get_user_module_instance(config, json_string_value(json_object_get(j_module, "name")));
      if (user_module != NULL) {
        if (user_module->enabled) {
          res = user_module->module->user_module_check_password(username, password, user_module->cls);
          if (res == G_OK) {
            j_return = json_pack("{si}", "result", G_OK);
          } else if (res == G_ERROR_UNAUTHORIZED) {
            j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          } else if (res != G_ERROR_NOT_FOUND) {
            y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_credentials - Error, user_module_check_password for module '%s', skip", user_module->name);
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_credentials - Error, user_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_credentials - Error get_user_module_list");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  if (j_return == NULL) {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  json_decref(j_module_list);
  return j_return;
}

json_t * auth_check_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, json_t * scheme_value) {
  struct _user_auth_scheme_module_instance * scheme_instance;
  json_t * j_return = NULL;
  char * str_scheme_value = json_dumps(scheme_value, JSON_COMPACT);
  int res;
  
  if (NULL != str_scheme_value) {
    scheme_instance = get_user_auth_scheme_module_instance(config, scheme_name);
    if (scheme_instance != NULL && 0 == o_strcmp(scheme_type, scheme_instance->module->name)) {
      res = scheme_instance->module->user_auth_scheme_module_validate(username, str_scheme_value, scheme_instance->cls);
      if (res == G_OK || res == G_ERROR_UNAUTHORIZED || res == G_ERROR_PARAM || res == G_ERROR_NOT_FOUND) {
        j_return = json_pack("{si}", "result", res);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_scheme - Error unrecognize return value for user_auth_scheme_module_validate: %d", res);
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  o_free(str_scheme_value);
  return j_return;
}

json_t * auth_trigger_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, json_t * trigger_parameters) {
  struct _user_auth_scheme_module_instance * scheme_instance;
  json_t * j_return = NULL, * j_response = NULL;
  char * str_trigger_parameters = json_dumps(trigger_parameters, JSON_COMPACT), * str_trigger_response = NULL;
  int res;
  
  if (NULL != str_trigger_parameters) {
    scheme_instance = get_user_auth_scheme_module_instance(config, scheme_name);
    if (scheme_instance != NULL && 0 == o_strcmp(scheme_type, scheme_instance->module->name)) {
      res = scheme_instance->module->user_auth_scheme_module_trigger(username, str_trigger_parameters, &str_trigger_response, scheme_instance->cls);
      if (res == G_OK) {
        j_response = json_loads(str_trigger_response, JSON_DECODE_ANY, NULL);
        if (j_response != NULL) {
          j_return = json_pack("{sisO}", "result", res, "trigger", j_response);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "auth_trigger_user_scheme - Error parsing trigger response into JSON format: %s", str_trigger_response);
        }
        json_decref(j_response);
      } else if (res != G_ERROR) {
        j_return = json_pack("{si}", "result", res);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "auth_trigger_user_scheme - Error unrecognize return value for user_auth_scheme_module_trigger: %d", res);
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      o_free(str_trigger_response);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  o_free(str_trigger_parameters);
  return j_return;
}

json_t * get_user(struct config_elements * config, const char * username) {
  int i, found = 0, result;
  char * str_user;
  json_t * j_return = NULL, * j_user;
  struct _user_module_instance * user_module;
  
  for (i=0; !found && i<pointer_list_size(config->user_module_instance_list) && j_return == NULL; i++) {
    if ((user_module = pointer_list_get_at(config->user_module_instance_list, i)) != NULL) {
      if (user_module->enabled) {
        str_user = user_module->module->user_module_get(username, &result, user_module->cls);
        if (result == G_OK && str_user != NULL) {
          j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
          if (j_user != NULL) {
            j_return = json_pack("{sisO}", "result", G_OK, "user", j_user);
            json_decref(j_user);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_user - Error json_loads");
          }
          found = 1;
        } else if (result != G_OK && result != G_ERROR_NOT_FOUND) {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_user - Error, user_module_get for module %s", user_module->name);
        }
        o_free(str_user);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_user - Error, user_module_instance %d is NULL", i);
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  }
  if (j_return == NULL) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

int user_has_scope(json_t * j_user, const char * scope) {
  json_t * j_element;
  size_t index;
  
  json_array_foreach(json_object_get(j_user, "scope"), index, j_element) {
    if (0 == o_strcmp(scope, json_string_value(j_element))) {
      return 1;
    }
  }
  return 0;
}

/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * user management functions definition
 *
 * Copyright 2018 Nicolas Mora <mail@babelouest.org>
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

json_t * auth_check_user_credentials_scope(struct config_elements * config, const char * username, const char * password, const char * scope_list) {
  return NULL;
}

json_t * auth_check_user_credentials(struct config_elements * config, const char * username, const char * password) {
  int i, res;
  json_t * j_return = NULL;
  
  for (i=0; i<config->user_module_instance_list_size && j_return == NULL; i++) {
    if (config->user_module_instance_list[i] != NULL) {
      if (config->user_module_instance_list[i]->enabled) {
        res = config->user_module_instance_list[i]->module->user_module_check_password(username, password, config->user_module_instance_list[i]->cls);
        if (res == G_OK) {
          j_return = json_pack("{si}", "result", G_OK);
        } else if (res == G_ERROR_UNAUTHORIZED) {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        } else if (res != G_ERROR_NOT_FOUND) {
          y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_credentials - Error, user_module_check_password for module '%s', skip", config->user_module_instance_list[i]->name);
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_credentials - Error, user_module_instance %d is NULL", i);
    }
  }
  if (j_return == NULL) {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  return j_return;
}

json_t * auth_check_user_scheme(struct config_elements * config, const char * scheme_name, const char * username, json_t * scheme_parameters) {
  struct _user_auth_scheme_module_instance * scheme_instance;
  json_t * j_return;
  char * str_scheme_parameters = json_dumps(scheme_parameters, JSON_COMPACT);
  int res;
  
  if (NULL != str_scheme_parameters) {
    scheme_instance = get_user_auth_scheme_module_instance(config, scheme_name);
    if (scheme_instance != NULL) {
      res = scheme_instance->module->user_auth_scheme_module_validate(username, str_scheme_parameters, scheme_instance->cls);
      if (res == G_OK || res == G_ERROR_UNAUTHORIZED || res == G_ERROR_PARAM || res == G_ERROR_NOT_FOUND) {
        j_return = json_pack("{si}", "result", res);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_scheme - Error unrecognize return value for user_auth_scheme_module_validate: %d", res);
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  o_free(str_scheme_parameters);
  return j_return;
}

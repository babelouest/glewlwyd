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
  struct _user_module * user_module;
  int i;
  json_t * j_result, * j_return = NULL;
  
  for (i=0; i<config->user_module_instance_list_size && j_return == NULL; i++) {
    if (config->user_module_instance_list[i] != NULL) {
      user_module = get_user_module(config, config->user_module_instance_list[i]->uid);
      if (user_module != NULL && config->user_module_instance_list[i]->enabled) {
        j_result = user_module->user_module_check_password(username, password, config->user_module_instance_list[i]->cls);
        if (check_result_value(j_result, G_OK)) {
          j_return = json_pack("{si}", "result", G_OK);
        } else if (check_result_value(j_result, G_ERROR_UNAUTHORIZED)) {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        } else if (!check_result_value(j_result, G_ERROR_NOT_FOUND)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_credentials - Error, user_module_check_password for module '%s', skip", config->user_module_instance_list[i]->name);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_credentials - Error, user_module uid %hu not found", config->user_module_instance_list[i]->uid);
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

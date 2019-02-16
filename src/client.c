/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * client management functions definition
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

json_t * get_client(struct config_elements * config, const char * client_id) {
  int i, found = 0, result;
  char * str_client;
  json_t * j_return = NULL, * j_client;
  struct _client_module_instance * client_module;
  
  for (i=0; !found && i<pointer_list_size(config->client_module_instance_list) && j_return == NULL; i++) {
    if ((client_module = pointer_list_get_at(config->client_module_instance_list, i)) != NULL) {
      if (client_module->enabled) {
        str_client = client_module->module->client_module_get(client_id, &result, client_module->cls);
        if (result == G_OK && str_client != NULL) {
          j_client = json_loads(str_client, JSON_DECODE_ANY, NULL);
          j_return = json_pack("{sisO}", "result", G_OK, "client", j_client);
          json_decref(j_client);
          found = 1;
        } else if (result != G_OK && result != G_ERROR_NOT_FOUND) {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_client - Error, client_module_get for module %s", client_module->name);
        }
        o_free(str_client);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_client - Error, client_module_instance %d is NULL", i);
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  }
  if (j_return == NULL) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

json_t * auth_check_client_credentials(struct config_elements * config, const char * client_id, const char * password) {
  int i, res;
  json_t * j_return = NULL;
  struct _client_module_instance * client_module;
  
  for (i=0; i<pointer_list_size(config->client_module_instance_list); i++) {
    client_module = pointer_list_get_at(config->client_module_instance_list, i);
    if (client_module != NULL) {
      if (client_module->enabled) {
        res = client_module->module->client_module_check_password(client_id, password, client_module->cls);
        if (res == G_OK) {
          j_return = json_pack("{si}", "result", G_OK);
        } else if (res == G_ERROR_UNAUTHORIZED) {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        } else if (res != G_ERROR_NOT_FOUND) {
          y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_client_credentials - Error, client_module_check_password for module '%s', skip", client_module->name);
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_client_credentials - Error, client_module_instance %d is NULL", i);
    }
  }
  if (j_return == NULL) {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  return j_return;
}


/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Database client module
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

#include <string.h>
#include <jansson.h>
#include <yder.h>
#include <orcania.h>
#include "../glewlwyd-common.h"

int client_module_load(struct config_elements * config, char ** name, char ** parameters) {
  int ret = G_OK;
  if (name != NULL && parameters != NULL) {
    *name = o_strdup("mock");
    *parameters = o_strdup("{\"mock-param-string\":{\"type\":\"string\",\"mandatory\":true},\"mock-param-number\":{\"type\":\"number\",\"mandatory\":true},\"mock-param-boolean\":{\"type\":\"boolean\",\"mandatory\":false},\"mock-param-list\":{\"type\":\"list\",\"values\":[\"elt1\",\"elt2\",\"elt3\"],\"mandatory\":true}}");
  } else {
    ret = G_ERROR;
  }
  return ret;
}

int client_module_unload(struct config_elements * config) {
  return G_OK;
}

int client_module_init(struct config_elements * config, const char * parameters, void ** cls) {
  *cls = (void*)json_pack("[{sssssssos[ss]s[ss]s[]so}{sssssssos[s]s[s]s[]so}{sssssssos[ssssss]s[s]s[ss]so}]",
                            "client_id",
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
                            "redirect_uri",
                              "../../test-oauth2.html?param=client1_cb1",
                              "../../test-oauth2.html?param=client1_cb2",
                            "scope",
                            "enabled",
                            json_true(),
                            "client_id",
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
                            "client3_id",
                            "name",
                            "client3",
                            "description",
                            "Client mock 3",
                            "confidential",
                            json_true(),
                            "authorization_type",
                              "code",
                              "token",
                              "password",
                              "client_credentials",
                              "refresh_token",
                              "delete_token",
                            "redirect_uri",
                              "../../test-oauth2.html?param=client3",
                            "scope",
                              "scope2",
                              "scope3",
                            "enabled",
                            json_true());
  y_log_message(Y_LOG_LEVEL_DEBUG, "client_module_init - success %s %s", config->profile_scope, config->admin_scope);
  return G_OK;
}

int client_module_close(struct config_elements * config, void * cls) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "client_module_close - success");
  json_decref((json_t *)cls);
  return G_OK;
}

char ** client_module_get_list(const char * pattern, uint limit, uint offset, uint * total, int * result, void * cls) {
  json_t * j_client;
  size_t index;
  char ** array_return = o_malloc(json_array_size((json_t *)cls) * sizeof(char *));
  
  if (array_return != NULL) {
    *total = json_array_size((json_t *)cls);
    json_array_foreach((json_t *)cls, index, j_client) {
      array_return[index] = json_dumps(j_client, JSON_COMPACT);
    }
    *result = G_OK;
  } else {
    *result = G_ERROR;
  }
  return array_return;
}

char * client_module_get(const char * client_id, int * result, void * cls) {
  json_t * j_client, * j_copy;
  size_t index;
  char * str_return = NULL;
  
  if (client_id != NULL && o_strlen(client_id)) {
    *result = G_ERROR_NOT_FOUND;
    json_array_foreach((json_t *)cls, index, j_client) {
      if (0 == o_strcmp(client_id, json_string_value(json_object_get(j_client, "client_id")))) {
        j_copy = json_deep_copy(j_client);
        json_object_del(j_copy, "plugins");
        str_return = json_dumps(j_copy, JSON_COMPACT);
        *result = G_OK;
        json_decref(j_copy);
        break;
      }
    }
  } else {
    *result = G_ERROR;
  }
  return str_return;
}

int client_module_add(const char * str_new_client, void * cls) {
  json_t * j_client = json_loads(str_new_client, JSON_DECODE_ANY, NULL);
  int ret, result;
  char * str_client;
  
  if (j_client != NULL) {
    str_client = client_module_get(json_string_value(json_object_get(j_client, "username")), &result, cls);
    if (result == G_ERROR_NOT_FOUND) {
      json_array_append((json_t *)cls, j_client);
      ret = G_OK;
    } else {
      ret = G_ERROR;
    }
    json_decref(j_client);
    o_free(str_client);
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int client_module_update(const char * client_id, const char * str_client, void * cls) {
  json_t * j_client = json_loads(str_client, JSON_DECODE_ANY, NULL), * j_element;
  size_t index;
  int ret, found = 0;
  
  if (j_client != NULL) {
    json_array_foreach((json_t *)cls, index, j_element) {
      if (0 == o_strcmp(client_id, json_string_value(json_object_get(j_element, "client_id")))) {
        json_object_set_new(j_client, "client_id", json_string(client_id));
        json_array_set((json_t *)cls, index, j_client);
        ret = G_OK;
        found = 1;
        break;
      }
    }
    if (!found) {
      ret = G_ERROR_NOT_FOUND;
    }
  } else {
    ret = G_ERROR_PARAM;
  }
  json_decref(j_client);
  return ret;
}

int client_module_delete(const char * client_id, void * cls) {
  json_t * j_client;
  size_t index;
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

int client_module_check_password(const char * client_id, const char * password, void * cls) {
  json_t * j_client;
  int ret, result;
  char * str_client = client_module_get(client_id, &result, cls);
  j_client = json_loads(str_client, JSON_DECODE_ANY, NULL);
  
  if (result == G_OK) {
    if (json_object_get(j_client, "confidential") == json_true() && 0 == o_strcmp(password, "password")) {
      ret = G_OK;
    } else {
      ret = G_ERROR_UNAUTHORIZED;
    }
  } else {
    ret = G_ERROR_NOT_FOUND;
  }
  json_decref(j_client);
  o_free(str_client);
  return ret;
}

int client_module_update_password(const char * client_id, const char * new_password, void * cls) {
  return G_OK;
}


/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Clients are authenticated via various backend available: database, ldap
 * 
 * Mock client module
 *
 * Copyright 2018 Nicolas Mora <mail@babelouest.org>
 *
 * Licence MIT
 *
 */

#include <string.h>
#include <jansson.h>
#include <yder.h>
#include <orcania.h>
#include "../glewlwyd.h"

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
  *cls = (void*)json_pack("[{ss ss ss so s[sss] s[s] s[s] so}]",
                            "client_id",
                            "mock1",
                            "name",
                            "Mock client 1",
                            "description",
                            "Client mock",
                            "confidential",
                            json_false(),
                            "authorization_types",
                              "code",
                              "token",
                              "password",
                            "redirect_uri",
                              "https://localhost/mock",
                            "scopes",
                              config->glewlwyd_resource_config_profile->oauth_scope,
                            "enabled",
                            json_true());
  y_log_message(Y_LOG_LEVEL_DEBUG, "client_module_init - success %s %s", config->glewlwyd_resource_config_profile->oauth_scope, config->glewlwyd_resource_config_admin->oauth_scope);
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
    if (0 == o_strcmp(password, "password")) {
      ret = G_OK;
    } else {
      ret = G_ERROR;
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

char * client_module_check_scope_list(const char * client_id, const char * scope_list, void * cls) {
  int res;
  char * s_client = client_module_get(client_id, &res, cls), ** scope_array = NULL, ** scope_target = NULL, * scope_target_list = NULL;
  json_t * j_client, * j_element;
  int scopes_length, count = 0;
  size_t index;
  
  if (res == G_OK) {
    j_client = json_loads(s_client, JSON_DECODE_ANY, NULL);
    if (j_client != NULL && json_object_get(j_client, "scopes") != NULL && (scopes_length = split_string(scope_list, " ", &scope_array))) {
      scope_target = o_malloc((scopes_length + 1) * sizeof(char *));
      if (scope_target != NULL) {
        json_array_foreach(json_object_get(j_client, "scopes"), index, j_element) {
          if (string_array_has_value_case((const char **)scope_array, json_string_value(j_element))) {
            scope_target[count] = (char *)json_string_value(j_element);
            scope_target[count+1] = NULL;
            count++;
          }
        }
        if (count) {
          scope_target_list = string_array_join((const char **)scope_target, " ");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "client_module_check_scope_list - Error allocating resources for scope_target");
      }
    }
    json_decref(j_client);
    free_string_array(scope_array);
  }
  o_free(s_client);
  return scope_target_list;
}

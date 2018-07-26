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
                            "mock1", 
                            "description", 
                            "Client mock",
                            "confidential",
                            json_false(),
                            "authorization_types",
                              "code",
                              "token",
                              "password",
                            "scopes",
                              config->glewlwyd_resource_config_profile->oauth_scope,
                            "redirect_uri",
                              "https://localhost/mock",
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

char ** client_module_get_list(const char * pattern, uint limit, uint offset, uint * total, void * cls) {
  json_t * j_element;
  size_t index, list_size = 0;
  char ** list = o_malloc(sizeof(char *));
  
  if (total != NULL) {
    *total = json_array_size((json_t *)cls);
  }
  
  list[0] = NULL;
  json_array_foreach((json_t *)cls, index, j_element) {
    if (index >= offset && index < (offset + limit)) {
      list = o_realloc(list, (list_size +1) * sizeof(char *));
      list[list_size] = json_dumps(j_element, JSON_ENCODE_ANY);
      list[list_size + 1] = NULL;
    }
  }
  return list;
}

char * client_module_get(const char * client_id, void * cls) {
  json_t * j_client, * j_return = NULL;
  size_t index;
  char * to_return;
  
  if (client_id == NULL || !o_strlen(client_id)) {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  } else {
    json_array_foreach((json_t *)cls, index, j_client) {
      if (0 == o_strcmp(client_id, json_string_value(json_object_get(j_client, "client_id")))) {
        j_return = json_pack("{sisO}", "result", G_OK, "client", j_client);
      }
    }
    if (j_return == NULL) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  }
  to_return = json_dumps(j_return, JSON_COMPACT);
  json_decref(j_return);
  return to_return;
}

int client_module_add(const char * client, void * cls) {
  json_t * parsed_client = json_loads(client, JSON_DECODE_ANY, NULL), * j_client;
  int ret;
  char * str_client;
  
  if (parsed_client != NULL) {
    str_client = client_module_get(json_string_value(json_object_get((json_t *)cls, "client_id")), cls);
    j_client = json_loads(str_client, JSON_DECODE_ANY, NULL);
    if (check_result_value(j_client, G_ERROR_NOT_FOUND)) {
      json_array_append((json_t *)cls, parsed_client);
      ret = G_OK;
    } else {
      ret = G_ERROR;
    }
    o_free(str_client);
    json_decref(j_client);
    json_decref(parsed_client);
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int client_module_update(const char * client_id, const char * client, void * cls) {
  json_t * parsed_client = json_loads(client, JSON_DECODE_ANY, NULL), * j_client;
  size_t index;
  int ret, found = 0;
  
  if (parsed_client != NULL) {
    json_array_foreach((json_t *)cls, index, j_client) {
      if (0 == o_strcmp(client_id, json_string_value(json_object_get(j_client, "client_id")))) {
        json_object_set_new(parsed_client, "client_id", json_string(client_id));
        json_array_set((json_t *)cls, index, parsed_client);
        ret = G_OK;
        found = 1;
        break;
      }
    }
    if (!found) {
      ret = G_ERROR_NOT_FOUND;
    }
    json_decref(parsed_client);
  } else {
    ret = G_ERROR_PARAM;
  }
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
  int ret;
  char * str_client = client_module_get(client_id, cls);
  j_client = json_loads(str_client, JSON_DECODE_ANY, NULL);
  
  if (check_result_value(j_client, G_OK)) {
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

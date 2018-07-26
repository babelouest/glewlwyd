/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * Mock user module
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

int user_module_load(struct config_elements * config, char ** name, char ** parameters) {
  int ret = G_OK;
  if (name != NULL && parameters != NULL) {
    *name = o_strdup("mock");
    *parameters = o_strdup("{\"mock-param-string\":{\"type\":\"string\",\"mandatory\":false},\"mock-param-number\":{\"type\":\"number\",\"mandatory\":true},\"mock-param-boolean\":{\"type\":\"boolean\",\"mandatory\":true},\"mock-param-list\":{\"type\":\"list\",\"values\":[\"elt1\",\"elt2\",\"elt3\"],\"mandatory\":true}}");
  } else {
    ret = G_ERROR;
  }
  return ret;
}

int user_module_unload(struct config_elements * config) {
  return G_OK;
}

int user_module_init(struct config_elements * config, const char * parameters, void ** cls) {
  *cls = (void*)json_pack("[{ss ss ss s[ss]}{ss ss ss s[s]}]",
                            "username", 
                            "admin", 
                            "name", 
                            "The Boss", 
                            "email", 
                            "admin@glewlwyd",
                            "scope",
                              config->glewlwyd_resource_config_admin->oauth_scope,
                              config->glewlwyd_resource_config_profile->oauth_scope,
                            "username",
                            "dev", 
                            "name", 
                            "Dave Lopper", 
                            "email", 
                            "dev@glewlwyd",
                            "scope",
                              config->glewlwyd_resource_config_profile->oauth_scope);
  y_log_message(Y_LOG_LEVEL_DEBUG, "user_module_init - success %s %s", config->glewlwyd_resource_config_profile->oauth_scope, config->glewlwyd_resource_config_admin->oauth_scope);
  return G_OK;
}

int user_module_close(struct config_elements * config, void * cls) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "user_module_close - success");
  json_decref((json_t *)cls);
  return G_OK;
}

char ** user_module_get_list(const char * pattern, uint limit, uint offset, uint * total, void * cls) {
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

char * user_module_get(const char * username, void * cls) {
  json_t * j_user, * j_return = NULL;
  size_t index;
  char * to_return;
  
  if (username == NULL || !o_strlen(username)) {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  } else {
    json_array_foreach((json_t *)cls, index, j_user) {
      if (0 == o_strcmp(username, json_string_value(json_object_get(j_user, "username")))) {
        j_return = json_pack("{sisO}", "result", G_OK, "user", j_user);
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

int user_module_add(const char * user, void * cls) {
  json_t * parsed_user = json_loads(user, JSON_DECODE_ANY, NULL), * j_user;
  int ret;
  char * str_user;
  
  if (parsed_user != NULL) {
    str_user = user_module_get(json_string_value(json_object_get((json_t *)cls, "username")), cls);
    j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
    if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
      json_array_append((json_t *)cls, parsed_user);
      ret = G_OK;
    } else {
      ret = G_ERROR;
    }
    o_free(str_user);
    json_decref(j_user);
    json_decref(parsed_user);
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int user_module_update(const char * username, const char * user, void * cls) {
  json_t * parsed_user = json_loads(user, JSON_DECODE_ANY, NULL), * j_user;
  size_t index;
  int ret, found = 0;
  
  if (parsed_user != NULL) {
    json_array_foreach((json_t *)cls, index, j_user) {
      if (0 == o_strcmp(username, json_string_value(json_object_get(j_user, "username")))) {
        json_object_set_new(parsed_user, "username", json_string(username));
        json_array_set((json_t *)cls, index, parsed_user);
        ret = G_OK;
        found = 1;
        break;
      }
    }
    if (!found) {
      ret = G_ERROR_NOT_FOUND;
    }
    json_decref(parsed_user);
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int user_module_delete(const char * username, void * cls) {
  json_t * j_user;
  size_t index;
  int ret, found = 0;
  
  json_array_foreach((json_t *)cls, index, j_user) {
    if (0 == o_strcmp(username, json_string_value(json_object_get(j_user, "username")))) {
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

int user_module_check_password(const char * username, const char * password, void * cls) {
  json_t * j_user;
  int ret;
  char * str_user = user_module_get(username, cls);
  j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
  
  if (check_result_value(j_user, G_OK)) {
    if (0 == o_strcmp(password, "password")) {
      ret = G_OK;
    } else {
      ret = G_ERROR;
    }
  } else {
    ret = G_ERROR_NOT_FOUND;
  }
  json_decref(j_user);
  o_free(str_user);
  return ret;
}

int user_module_update_password(const char * username, const char * new_password, void * cls) {
  return G_OK;
}

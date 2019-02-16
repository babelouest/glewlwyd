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
#include "../glewlwyd-common.h"

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
  *cls = (void*)json_pack("[{ss ss ss so s[ss]}{ss ss ss so s[sss]}{ss ss ss so s[ss]}{ss ss ss so s[ss]}]",
                            "username", 
                            "admin", 
                            "name", 
                            "The Boss", 
                            "email", 
                            "admin@glewlwyd",
                            "enabled",
                            json_true(),
                            "scope",
                              config->admin_scope,
                              config->profile_scope,
                            "username",
                            "dev", 
                            "name", 
                            "Dave Lopper", 
                            "email", 
                            "dev@glewlwyd",
                            "enabled",
                            json_true(),
                            "scope",
                              config->profile_scope,
                              "g_mock_1",
                              "g_mock_2",
                            "username",
                            "bob", 
                            "name", 
                            "Bob the user", 
                            "email", 
                            "bob@glewlwyd",
                            "enabled",
                            json_true(),
                            "scope",
                              config->profile_scope,
                              "g_mock_2",
                            "username",
                            "sam", 
                            "name", 
                            "Sam the user", 
                            "email", 
                            "sam@glewlwyd",
                            "enabled",
                            json_true(),
                            "scope",
                              config->profile_scope,
                              "g_mock_1");
  y_log_message(Y_LOG_LEVEL_DEBUG, "user_module_init - success %s %s", config->profile_scope, config->admin_scope);
  return G_OK;
}

int user_module_close(struct config_elements * config, void * cls) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "user_module_close - success");
  json_decref((json_t *)cls);
  return G_OK;
}

char ** user_module_get_list(const char * pattern, uint limit, uint offset, uint * total, int * result, void * cls) {
  json_t * j_user;
  size_t index;
  char ** array_return = o_malloc(json_array_size((json_t *)cls) * sizeof(char *));
  
  if (array_return != NULL) {
    *total = json_array_size((json_t *)cls);
    json_array_foreach((json_t *)cls, index, j_user) {
      array_return[index] = json_dumps(j_user, JSON_COMPACT);
    }
    *result = G_OK;
  } else {
    *result = G_ERROR;
  }
  return array_return;
}

char * user_module_get(const char * username, int * result, void * cls) {
  json_t * j_user;
  size_t index;
  char * str_return = NULL;
  
  if (username != NULL && o_strlen(username)) {
    *result = G_ERROR_NOT_FOUND;
    json_array_foreach((json_t *)cls, index, j_user) {
      if (0 == o_strcmp(username, json_string_value(json_object_get(j_user, "username")))) {
        str_return = json_dumps(j_user, JSON_COMPACT);
        *result = G_OK;
        break;
      }
    }
  } else {
    *result = G_ERROR;
  }
  return str_return;
}

int user_module_add(const char * str_new_user, void * cls) {
  json_t * j_user = json_loads(str_new_user, JSON_DECODE_ANY, NULL);
  int ret, result;
  char * str_user;
  
  if (j_user != NULL) {
    str_user = user_module_get(json_string_value(json_object_get(j_user, "username")), &result, cls);
    if (result == G_ERROR_NOT_FOUND) {
      json_array_append((json_t *)cls, j_user);
      ret = G_OK;
    } else {
      ret = G_ERROR;
    }
    json_decref(j_user);
    o_free(str_user);
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int user_module_update(const char * username, const char * str_user, void * cls) {
  json_t * j_user = json_loads(str_user, JSON_DECODE_ANY, NULL), * j_element;
  size_t index;
  int ret, found = 0;
  
  if (j_user != NULL) {
    json_array_foreach((json_t *)cls, index, j_element) {
      if (0 == o_strcmp(username, json_string_value(json_object_get(j_element, "username")))) {
        json_object_set_new(j_user, "username", json_string(username));
        json_array_set((json_t *)cls, index, j_user);
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
  json_decref(j_user);
  return ret;
}

int user_module_update_profile(const char * username, const char * str_user, void * cls) {
  return user_module_update(username, str_user, cls);
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
  char * str_user;
  int ret, result;
  str_user = user_module_get(username, &result, cls);
  
  if (result == G_OK) {
    if (0 == o_strcmp(password, "password")) {
      ret = G_OK;
    } else {
      ret = G_ERROR_PARAM;
    }
  } else {
    ret = G_ERROR_NOT_FOUND;
  }
  o_free(str_user);
  return ret;
}

int user_module_update_password(const char * username, const char * new_password, void * cls) {
  return G_ERROR_PARAM;
}

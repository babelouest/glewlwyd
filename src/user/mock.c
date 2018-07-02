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

int user_module_load(struct config_elements * config, uint16_t * uid, char ** display_name) {
  int ret = G_OK;
  if (uid != NULL) {
    *uid = 42;
  } else {
    ret = G_ERROR;
  }
  if (display_name != NULL) {
    *display_name = o_strdup("mock");
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

json_t * user_module_get_list(const char * pattern, uint limit, uint offset, void * cls) {
  return (json_t *)cls;
}

json_t * user_module_get(const char * username, void * cls) {
  json_t * j_user, * j_return = NULL;
  size_t index;
  
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
  return j_return;
}

json_t * user_module_add(json_t * user, void * cls) {
  json_t * j_user = user_module_get(json_string_value(json_object_get((json_t *)cls, "username")), cls), * j_return;
  if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
    json_array_append((json_t *)cls, user);
    j_return = json_pack("{si}", "result", G_OK);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_user);
  return j_return;
}

json_t * user_module_update(const char * username, json_t * user, void * cls) {
  json_t * j_return = NULL, * j_user;
  size_t index;
  
  json_array_foreach((json_t *)cls, index, j_user) {
    if (0 == o_strcmp(username, json_string_value(json_object_get(j_user, "username")))) {
      json_decref(j_user);
      json_object_set_new(user, "username", json_string(username));
      json_array_set((json_t *)cls, index, user);
      j_return = json_pack("{si}", "result", G_OK);
      break;
    }
  }
  if (j_return == NULL) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

json_t * user_module_delete(const char * username, void * cls) {
  json_t * j_return = NULL, * j_user;
  size_t index;
  
  json_array_foreach((json_t *)cls, index, j_user) {
    if (0 == o_strcmp(username, json_string_value(json_object_get(j_user, "username")))) {
      json_array_remove((json_t *)cls, index);
      j_return = json_pack("{si}", "result", G_OK);
      break;
    }
  }
  if (j_return == NULL) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

json_t * user_module_check_password(const char * username, const char * password, void * cls) {
  json_t * j_return = NULL, * j_user = user_module_get(username, cls);
  
  if (check_result_value(j_user, G_OK)) {
    if (0 == o_strcmp(password, "password")) {
      j_return = json_pack("{si}", "result", G_OK);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  json_decref(j_user);
  return j_return;
}


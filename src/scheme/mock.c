/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * Mock user authentication scheme module
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

int user_auth_scheme_module_load(struct config_elements * config, char ** name) {
  int ret = G_OK;
  
  if (name != NULL) {
    *name = o_strdup("mock");
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int user_auth_scheme_module_unload(struct config_elements * config) {
  return G_OK;
}

int user_auth_scheme_module_init(struct config_elements * config, void ** cls) {
  return G_OK;
}

int user_auth_scheme_module_close(struct config_elements * config, void * cls) {
  return G_OK;
}

int user_auth_scheme_module_validate(const char * username, const char * scheme_data, void * cls) {
  json_t * j_scheme = json_loads(scheme_data, JSON_DECODE_ANY, NULL);
  int ret;
  
  if (j_scheme != NULL) {
    if (json_object_get(j_scheme, "code") != NULL && json_is_integer(json_object_get(j_scheme, "code")) && json_integer_value(json_object_get(j_scheme, "code")) == 42) {
      ret = G_OK;
    } else {
      ret = G_ERROR_UNAUTHORIZED;
    }
  } else {
    ret = G_ERROR_PARAM;
  }
  json_decref(j_scheme);
  return ret;
}

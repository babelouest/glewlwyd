/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Mock authentication scheme module
 * 
 * Copyright 2018-2019 Nicolas Mora <mail@babelouest.org>
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

int user_auth_scheme_module_load(struct config_elements * config, char ** name, char ** display_name, char ** description, char ** parameters) {
  int ret = G_OK;
  
  if (name != NULL && parameters != NULL && display_name != NULL && description != NULL) {
    *name = o_strdup("mock");
    *display_name = o_strdup("Mock scheme module");
    *description = o_strdup("Mock scheme module for glewlwyd tests");
    *parameters = o_strdup("{\"mock-value\":{\"type\":\"string\",\"mandatory\":true},\"mock-param-string\":{\"type\":\"string\",\"mandatory\":true},\"mock-param-number\":{\"type\":\"number\",\"mandatory\":false},\"mock-param-boolean\":{\"type\":\"boolean\",\"mandatory\":true},\"mock-param-list\":{\"type\":\"list\",\"values\":[\"elt1\",\"elt2\",\"elt3\"],\"mandatory\":true}}");
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int user_auth_scheme_module_unload(struct config_elements * config) {
  return G_OK;
}

int user_auth_scheme_module_init(struct config_elements * config, const char * parameters, void ** cls) {
  *cls = json_loads(parameters, JSON_DECODE_ANY, NULL);
  return G_OK;
}

int user_auth_scheme_module_close(struct config_elements * config, void * cls) {
  json_decref((json_t *)cls);
  return G_OK;
}

int user_auth_scheme_module_trigger(const char * username, const char * scheme_trigger, char ** scheme_trigger_response, void * cls) {
  *scheme_trigger_response = msprintf("{\"code\":" JSON_INTEGER_FORMAT "}", json_integer_value(json_object_get((json_t *)cls, "mock-param-number")));
  return G_OK;
}

int user_auth_scheme_module_validate(const char * username, const char * scheme_data, void * cls) {
  json_t * j_scheme = json_loads(scheme_data, JSON_DECODE_ANY, NULL);
  int ret;
  
  if (j_scheme != NULL) {
    if (json_object_get(j_scheme, "code") != NULL && json_is_string(json_object_get(j_scheme, "code")) && 0 == o_strcmp(json_string_value(json_object_get(j_scheme, "code")), json_string_value(json_object_get((json_t *)cls, "mock-value")))) {
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

int user_can_use_scheme(const char * username, void * cls) {
  if (0 == o_strcmp(username, json_string_value(json_object_get((json_t *)cls, "mock-user-forbidden")))) {
    return 0;
  } else {
    return 1;
  }
}

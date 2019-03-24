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

struct mock_config {
  json_t * j_param;
  struct config_module * config;
};

int user_auth_scheme_module_load(struct config_module * config, char ** name, char ** display_name, char ** description, char ** parameters) {
  int ret = G_OK;
  
  if (name != NULL && parameters != NULL && display_name != NULL && description != NULL) {
    *name = o_strdup("mock");
    *display_name = o_strdup("Mock scheme module");
    *description = o_strdup("Mock scheme module for glewlwyd tests");
    *parameters = o_strdup("{\"mock-value\":{\"type\":\"string\",\"mandatory\":true}}");
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int user_auth_scheme_module_unload(struct config_module * config) {
  return G_OK;
}

int user_auth_scheme_module_init(struct config_module * config, const char * parameters, void ** cls) {
  *cls = o_malloc(sizeof(struct mock_config));
  ((struct mock_config *)*cls)->j_param = json_loads(parameters, JSON_DECODE_ANY, NULL);
  ((struct mock_config *)*cls)->config = config;
  return G_OK;
}

int user_auth_scheme_module_close(struct config_module * config, void * cls) {
  json_decref(((struct mock_config *)cls)->j_param);
  o_free(cls);
  return G_OK;
}

int user_can_use_scheme(const char * username, void * cls) {
  char * str_user = NULL, * key_mock;
  json_t * j_user;
  int ret, result;

  str_user = ((struct mock_config *)cls)->config->glewlwyd_callback_get_user(((struct mock_config *)cls)->config, username, &result);
  if (result == G_OK) {
    j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
    if (j_user != NULL) {
      key_mock = msprintf("mock-%s", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
      if (json_object_get(j_user, key_mock) != NULL) {
        ret = GLEWLWYD_IS_REGISTERED;
      } else {
        ret = GLEWLWYD_IS_AVAILABLE;
      }
      o_free(key_mock);
    } else {
      ret = GLEWLWYD_IS_NOT_AVAILABLE;
    }
    json_decref(j_user);
  } else {
    ret = GLEWLWYD_IS_NOT_AVAILABLE;
  }
  o_free(str_user);
  return ret;
}

int user_auth_scheme_module_register(const char * username, const char * register_data, char ** register_response, void * cls) {
  int ret, result = G_ERROR;
  char * str_user = NULL, * str_user_set, * key_mock;
  json_t * j_user, * j_data;
  
  str_user = ((struct mock_config *)cls)->config->glewlwyd_callback_get_user(((struct mock_config *)cls)->config, username, &result);
  if (result == G_OK) {
    j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
    j_data = json_loads(register_data, JSON_DECODE_ANY, NULL);
    if (j_user != NULL) {
      key_mock = msprintf("mock-%s", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
      if (json_object_get(j_data, "register") == json_true()) {
        json_object_set_new(j_user, key_mock, json_pack("{si}", "counter", 0));
      } else {
        json_object_del(j_user, key_mock);
      }
      str_user_set = json_dumps(j_user, JSON_COMPACT);
      ret = ((struct mock_config *)cls)->config->glewlwyd_callback_set_user(((struct mock_config *)cls)->config, username, str_user_set);
      if (ret == G_OK) {
        *register_response = msprintf("{\"register-code\":\"%s\"}", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
      }
      o_free(str_user_set);
      o_free(key_mock);
    } else {
      ret = G_ERROR;
    }
    json_decref(j_user);
    json_decref(j_data);
  } else {
    ret = G_ERROR;
  }
  o_free(str_user);
  return ret;
}

int user_auth_scheme_module_trigger(const char * username, const char * scheme_trigger, char ** scheme_trigger_response, void * cls) {
  int ret;
  
  if (user_can_use_scheme(username, cls) == GLEWLWYD_IS_REGISTERED) {
    *scheme_trigger_response = msprintf("{\"code\":\"%s\"}", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
    ret = G_OK;
  } else {
    ret = G_ERROR_UNAUTHORIZED;
  }
  return ret;
}

int user_auth_scheme_module_validate(const char * username, const char * scheme_data, void * cls) {
  json_t * j_scheme = json_loads(scheme_data, JSON_DECODE_ANY, NULL), * j_user;
  char * str_user = NULL, * str_user_set, * key_mock;
  int ret, result = G_ERROR;
  
  if (j_scheme != NULL) {
    if (user_can_use_scheme(username, cls) != GLEWLWYD_IS_REGISTERED) {
      ret = G_ERROR_UNAUTHORIZED;
    } else if (json_object_get(j_scheme, "code") != NULL && json_is_string(json_object_get(j_scheme, "code")) && 0 == o_strcmp(json_string_value(json_object_get(j_scheme, "code")), json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")))) {
      str_user = ((struct mock_config *)cls)->config->glewlwyd_callback_get_user(((struct mock_config *)cls)->config, username, &result);
      if (result == G_OK) {
        j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
        if (j_user != NULL) {
          key_mock = msprintf("mock-%s", json_string_value(json_object_get(((struct mock_config *)cls)->j_param, "mock-value")));
          json_object_set_new(j_user, key_mock, json_pack("{si}", "counter", json_integer_value(json_object_get(json_object_get(j_user, key_mock), "counter")) + 1));
          str_user_set = json_dumps(j_user, JSON_COMPACT);
          ret = ((struct mock_config *)cls)->config->glewlwyd_callback_set_user(((struct mock_config *)cls)->config, username, str_user_set);
          o_free(str_user_set);
          o_free(key_mock);
        } else {
          ret = G_ERROR;
        }
        json_decref(j_user);
      } else {
        ret = G_ERROR;
      }
      o_free(str_user);
    } else {
      ret = G_ERROR_UNAUTHORIZED;
    }
  } else {
    ret = G_ERROR_PARAM;
  }
  json_decref(j_scheme);
  return ret;
}

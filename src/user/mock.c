/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Mock user module
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

static int json_has_str_pattern_case(json_t * j_source, const char * pattern) {
  const char * key;
  size_t index;
  json_t * j_element;

  if (j_source != NULL) {
    if (json_is_string(j_source) && o_strcasestr(json_string_value(j_source), pattern) != NULL) {
      return 1;
    } else if (json_is_object(j_source)) {
      json_object_foreach(j_source, key, j_element) {
        if (json_has_str_pattern_case(j_element, pattern)) {
          return 1;
        }
      }
      return 0;
    } else if (json_is_array(j_source)) {
      json_array_foreach(j_source, index, j_element) {
        if (json_has_str_pattern_case(j_element, pattern)) {
          return 1;
        }
      }
      return 0;
    } else {
      return 0;
    }
  } else {
    return 0;
  }
}

int user_module_load(struct config_elements * config, char ** name, char ** display_name, char ** description, char ** parameters) {
  int ret = G_OK;
  if (name != NULL && parameters != NULL && display_name != NULL && description != NULL) {
    *name = o_strdup("mock");
    *display_name = o_strdup("Mock user module");
    *description = o_strdup("Mock user module for glewlwyd tests");
    *parameters = o_strdup("{\"username-prefix\":{\"type\":\"string\",\"mandatory\":false}}");
  } else {
    ret = G_ERROR;
  }
  return ret;
}

int user_module_unload(struct config_elements * config) {
  return G_OK;
}

int user_module_init(struct config_elements * config, const char * parameters, void ** cls) {
  json_t * j_param = json_loads(parameters, 0, NULL);
  if (j_param == NULL) {
    j_param = json_pack("{ss}", "username-prefix", "");
  } else if (!json_is_string(json_object_get(j_param, "username-prefix"))) {
    json_object_set_new(j_param, "username-prefix", json_string(""));
  }
  *cls = (void*)json_pack("[{ss+ ss ss so s[ss]}{ss+ ss ss so s[ssss]}{ss+ ss ss so s[ss]}{ss+ ss ss so s[ssss]}]",
                            "username", 
                            json_string_value(json_object_get(j_param, "username-prefix")),
                            "admin", 
                            "name", 
                            "The Boss", 
                            "email", 
                            "boss@glewlwyd.domain",
                            "enabled",
                            json_true(),
                            "scope",
                              config->admin_scope,
                              config->profile_scope,

                            "username",
                            json_string_value(json_object_get(j_param, "username-prefix")),
                            "user1",
                            "name",
                            "Dave Lopper 1",
                            "email",
                            "dev1@glewlwyd",
                            "enabled",
                            json_true(),
                            "scope",
                              config->profile_scope,
                              "scope1",
                              "scope2",
                              "scope3",

                            "username",
                            json_string_value(json_object_get(j_param, "username-prefix")),
                            "user2",
                            "name",
                            "Dave Lopper 2",
                            "email",
                            "dev2@glewlwyd",
                            "enabled",
                            json_true(),
                            "scope",
                              config->profile_scope,
                              "scope1",

                            "username",
                            json_string_value(json_object_get(j_param, "username-prefix")),
                            "user3",
                            "name",
                            "Dave Lopper 3",
                            "email",
                            "dev3@glewlwyd",
                            "enabled",
                            json_true(),
                            "scope",
                              config->profile_scope,
                              "scope1",
                              "scope2",
                              "scope3");
  json_decref(j_param);
  y_log_message(Y_LOG_LEVEL_DEBUG, "user_module_init - success %s %s", config->profile_scope, config->admin_scope);
  return G_OK;
}

int user_module_close(struct config_elements * config, void * cls) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "user_module_close - success");
  json_decref((json_t *)cls);
  return G_OK;
}

size_t user_module_count_total(void * cls) {
  return json_array_size((json_t *)cls);
}

char * user_module_get_list(const char * pattern, size_t offset, size_t limit, int * result, void * cls) {
  json_t * j_user, * j_array = json_array();
  size_t index, counter = 0;
  char * to_return = NULL;

  if (limit > 0) {  
    if (j_array != NULL) {
      json_array_foreach((json_t *)cls, index, j_user) {
        if (index >= offset && (offset + counter) < json_array_size((json_t *)cls) && (!o_strlen(pattern) || json_has_str_pattern_case(j_user, pattern))) {
          json_array_append(j_array, j_user);
          counter++;
        }
      }
      to_return = json_dumps(j_array, JSON_COMPACT);
      *result = G_OK;
      json_decref(j_array);
    } else {
      *result = G_ERROR;
    }
  } else {
    *result = G_ERROR_PARAM;
  }
  return to_return;
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

char * user_is_valid(const char * username, const char * str_user, int mode, int * result, void * cls) {
  json_t * j_return = NULL, * j_user;
  char * str_return = NULL;

  if ((mode == GLEWLWYD_IS_VALID_MODE_UPDATE || mode == GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) && username == NULL) {
    *result = G_ERROR_PARAM;
    j_return = json_pack("[s]", "username is mandatory on update mode");
  } else {
    j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
    if (j_user != NULL && json_is_object(j_user)) {
      if (mode == GLEWLWYD_IS_VALID_MODE_ADD) {
        if (json_is_string(json_object_get(j_user, "username")) && json_string_length(json_object_get(j_user, "username")) <= 128) {
          *result = G_OK;
        } else {
          *result = G_ERROR_PARAM;
          j_return = json_pack("[s]", "username must be a string value of maximum 128 characters");
        }
      } else {
        *result = G_OK;
      }
    } else {
      *result = G_ERROR_PARAM;
      j_return = json_pack("[s]", "user must be a JSON object");
    }
    json_decref(j_user);
  }

  if (j_return != NULL) {
    str_return = json_dumps(j_return, JSON_COMPACT);
    json_decref(j_return);
  }
  return str_return;
}

int user_module_add(const char * str_new_user, void * cls) {
  json_t * j_user = json_loads(str_new_user, JSON_DECODE_ANY, NULL);
  int ret;
  
  if (j_user != NULL && json_is_object(j_user)) {
    json_array_append((json_t *)cls, j_user);
    ret = G_OK;
  } else {
    ret = G_ERROR_PARAM;
  }
  json_decref(j_user);
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
      ret = G_ERROR_UNAUTHORIZED;
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

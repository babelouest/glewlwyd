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

json_t * user_module_load(struct config_module * config) {
  return json_pack("{sisssssss{s{ssso}s{ssso}}}",
                   "result",
                   G_OK,
                   "name",
                   "mock",
                   "display_name",
                   "Mock scheme module",
                   "description",
                   "Mock scheme module for glewlwyd tests",
                   "parameters",
                     "username-prefix",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                     "password",
                       "type",
                       "string",
                       "mandatory",
                       json_false());
}

int user_module_unload(struct config_module * config) {
  return G_OK;
}

int user_module_init(struct config_module * config, int readonly, json_t * j_parameters, void ** cls) {
  const char * prefix = "", * password = "";
  if (json_string_length(json_object_get(j_parameters, "username-prefix"))) {
    prefix = json_string_value(json_object_get(j_parameters, "username-prefix"));
  }
  if (json_string_length(json_object_get(j_parameters, "password"))) {
    password = json_string_value(json_object_get(j_parameters, "password"));
  }
  *cls = (void*)json_pack("{sss[{ss+ ss ss so s[ss]}{ss+ ss ss so s[ssss]}{ss+ ss ss so s[ss]}{ss+ ss ss so s[ssss]}]}",
                          "password",
                          password,
                          "list",
                            "username", 
                            prefix,
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
                            prefix,
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
                            prefix,
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
                            prefix,
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
  y_log_message(Y_LOG_LEVEL_DEBUG, "user_module_init - success prefix: '%s', profile_scope: '%s', admin_scope: '%s'", prefix, config->profile_scope, config->admin_scope);
  return G_OK;
}

int user_module_close(struct config_module * config, void * cls) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "user_module_close - success");
  json_decref((json_t *)cls);
  return G_OK;
}

size_t user_module_count_total(struct config_module * config, const char * pattern, void * cls) {
  json_t * j_user;
  size_t index, total;

  if (o_strlen(pattern)) {
    total = 0;
    json_array_foreach(json_object_get((json_t *)cls, "list"), index, j_user) {
      if (json_has_str_pattern_case(j_user, pattern)) {
        total++;
      }
    }
  } else {
    total = json_array_size(json_object_get((json_t *)cls, "list"));
  }
  return total;
}

json_t * user_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls) {
  json_t * j_user, * j_array, * j_pattern_array, * j_return;
  size_t index, counter = 0;

  if (limit) {
    if (o_strlen(pattern)) {
      j_pattern_array = json_array();
      json_array_foreach(json_object_get((json_t *)cls, "list"), index, j_user) {
        if (json_has_str_pattern_case(j_user, pattern)) {
          json_array_append_new(j_pattern_array, json_deep_copy(j_user));
        }
      }
    } else {
      j_pattern_array = json_deep_copy(json_object_get((json_t *)cls, "list"));
    }
    j_array = json_array();
    if (j_array != NULL) {
      json_array_foreach(j_pattern_array, index, j_user) {
        if (index >= offset && (offset + counter) < json_array_size(j_pattern_array) && counter < limit) {
          json_array_append(j_array, j_user);
          counter++;
        }
      }
      j_return = json_pack("{sisO}", "result", G_OK, "list", j_array);
      json_decref(j_array);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_pattern_array);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

json_t * user_module_get(struct config_module * config, const char * username, void * cls) {
  json_t * j_user;
  size_t index;
  
  if (username != NULL && o_strlen(username)) {
    json_array_foreach(json_object_get((json_t *)cls, "list"), index, j_user) {
      if (0 == o_strcmp(username, json_string_value(json_object_get(j_user, "username")))) {
        return json_pack("{siso}", "result", G_OK, "user", json_deep_copy(j_user));
        break;
      }
    }
      return json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  } else {
    return json_pack("{si}", "result", G_ERROR);
  }
}

json_t * user_module_get_profile(struct config_module * config, const char * username, void * cls) {
  return user_module_get(config, username, cls);
}

json_t * user_module_is_valid(struct config_module * config, const char * username, json_t * j_user, int mode, void * cls) {
  json_t * j_return = NULL;

  if ((mode == GLEWLWYD_IS_VALID_MODE_UPDATE || mode == GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) && username == NULL) {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "username is mandatory on update mode");
  } else {
    if (mode == GLEWLWYD_IS_VALID_MODE_ADD) {
      if (json_is_string(json_object_get(j_user, "username")) && json_string_length(json_object_get(j_user, "username")) <= 128) {
        j_return = json_pack("{si}", "result", G_OK);
      } else {
        j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "username must be a string value of maximum 128 characters");
      }
    } else {
      j_return = json_pack("{si}", "result", G_OK);
    }
  }
  return j_return;
}

int user_module_add(struct config_module * config, json_t * j_user, void * cls) {
  json_array_append(json_object_get((json_t *)cls, "list"), j_user);
  return G_OK;
}

int user_module_update(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  json_t * j_element, * j_property;
  size_t index;
  int found = 0, ret;
  const char * key;
  
  json_array_foreach(json_object_get((json_t *)cls, "list"), index, j_element) {
    if (0 == o_strcmp(username, json_string_value(json_object_get(j_element, "username")))) {
      json_object_set_new(j_user, "username", json_string(username));
      json_object_foreach(j_user, key, j_property) {
        json_object_set(j_element, key, j_property);
      }
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

int user_module_update_profile(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  return user_module_update(config, username, j_user, cls);
}

int user_module_delete(struct config_module * config, const char * username, void * cls) {
  json_t * j_user;
  size_t index;
  int ret, found = 0;
  
  json_array_foreach(json_object_get((json_t *)cls, "list"), index, j_user) {
    if (0 == o_strcmp(username, json_string_value(json_object_get(j_user, "username")))) {
      json_array_remove(json_object_get((json_t *)cls, "list"), index);
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

int user_module_check_password(struct config_module * config, const char * username, const char * password, void * cls) {
  int ret;
  json_t * j_user = user_module_get(config, username, cls);
  
  if (check_result_value(j_user, G_OK)) {
    if (0 == o_strcmp(password, json_string_value(json_object_get((json_t *)cls, "password")))) {
      ret = G_OK;
    } else {
      ret = G_ERROR_UNAUTHORIZED;
    }
  } else {
    ret = G_ERROR_NOT_FOUND;
  }
  json_decref(j_user);
  return ret;
}

int user_module_update_password(struct config_module * config, const char * username, const char * new_password, void * cls) {
  json_object_set_new((json_t *)cls, "password", json_string(new_password));
  return G_OK;
}

/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Mock client module
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

int client_module_load(struct config_module * config, char ** name, char ** display_name, char ** description, char ** parameters) {
  int ret = G_OK;
  if (name != NULL && parameters != NULL && display_name != NULL && description != NULL) {
    *name = o_strdup("mock");
    *display_name = o_strdup("Mock client module");
    *description = o_strdup("Mock client module for glewlwyd tests");
    *parameters = o_strdup("{\"mock-param-string\":{\"type\":\"string\",\"mandatory\":true},\"mock-param-number\":{\"type\":\"number\",\"mandatory\":true},\"mock-param-boolean\":{\"type\":\"boolean\",\"mandatory\":false},\"mock-param-list\":{\"type\":\"list\",\"values\":[\"elt1\",\"elt2\",\"elt3\"],\"mandatory\":true}}");
  } else {
    ret = G_ERROR;
  }
  return ret;
}

int client_module_unload(struct config_module * config) {
  return G_OK;
}

int client_module_init(struct config_module * config, const char * parameters, void ** cls) {
  json_t * j_param = json_loads(parameters, 0, NULL);
  if (j_param == NULL) {
    j_param = json_pack("{ss}", "client-id-prefix", "");
  } else if (!json_is_string(json_object_get(j_param, "client-id-prefix"))) {
    json_object_set_new(j_param, "client-id-prefix", json_string(""));
  }
  *cls = (void*)json_pack("[{ss+ ss ss so s[ss] s[ss] s[] so}{ss+ ss ss so s[s] s[s] s[] so}{ss+ ss ss so s[ssssss] s[s] s[ss] so}]",
                            "client_id",
                            json_string_value(json_object_get(j_param, "client-id-prefix")),
                            "client1_id",
                            "name",
                            "client1",
                            "description",
                            "Client mock 1",
                            "confidential",
                            json_false(),
                            "authorization_type",
                              "code",
                              "token",
                            "redirect_uri",
                              "../../test-oauth2.html?param=client1_cb1",
                              "../../test-oauth2.html?param=client1_cb2",
                            "scope",
                            "enabled",
                            json_true(),
                            "client_id",
                            json_string_value(json_object_get(j_param, "client-id-prefix")),
                            "client2_id",
                            "name",
                            "client2",
                            "description",
                            "Client mock 2",
                            "confidential",
                            json_false(),
                            "authorization_type",
                              "code",
                            "redirect_uri",
                              "../../test-oauth2.html?param=client2",
                            "scope",
                            "enabled",
                            json_true(),
                            "client_id",
                            json_string_value(json_object_get(j_param, "client-id-prefix")),
                            "client3_id",
                            "name",
                            "client3",
                            "description",
                            "Client mock 3",
                            "confidential",
                            json_true(),
                            "authorization_type",
                              "code",
                              "token",
                              "password",
                              "client_credentials",
                              "refresh_token",
                              "delete_token",
                            "redirect_uri",
                              "../../test-oauth2.html?param=client3",
                            "scope",
                              "scope2",
                              "scope3",
                            "enabled",
                            json_true());
  y_log_message(Y_LOG_LEVEL_DEBUG, "client_module_init - success %s %s", config->profile_scope, config->admin_scope);
  json_decref(j_param);
  return G_OK;
}

int client_module_close(struct config_module * config, void * cls) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "client_module_close - success");
  json_decref((json_t *)cls);
  return G_OK;
}

size_t client_module_count_total(const char * pattern, void * cls) {
  size_t index, total;
  json_t * j_user;

  if (o_strlen(pattern)) {
    total = 0;
    json_array_foreach((json_t *)cls, index, j_user) {
      if (json_has_str_pattern_case(j_user, pattern)) {
        total++;
      }
    }
  } else {
    total = json_array_size((json_t *)cls);
  }
  return total;
}

char * client_module_get_list(const char * pattern, size_t offset, size_t limit, int * result, void * cls) {
  json_t * j_user, * j_array, * j_array_pattern;
  size_t index, counter = 0;
  char * to_return = NULL;

  if (limit > 0) {
    if (o_strlen(pattern)) {
      j_array_pattern = json_array();
      json_array_foreach((json_t *)cls, index, j_user) {
        if (json_has_str_pattern_case(j_user, pattern)) {
          json_array_append(j_array_pattern, j_user);
        }
      }
    } else {
      j_array_pattern = json_copy((json_t *)cls);
    }
    j_array = json_array();
    if (j_array != NULL) {
      json_array_foreach(j_array_pattern, index, j_user) {
        if (index >= offset && (offset + counter) < json_array_size((json_t *)cls) && counter < limit && (!o_strlen(pattern) || json_has_str_pattern_case(j_user, pattern))) {
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
    json_decref(j_array_pattern);
  } else {
    *result = G_ERROR_PARAM;
  }
  return to_return;
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

char * client_is_valid(const char * client_id, const char * str_client, int mode, int * result, void * cls) {
  json_t * j_return = NULL, * j_client;
  char * str_return = NULL;

  if ((mode == GLEWLWYD_IS_VALID_MODE_UPDATE || mode == GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) && client_id == NULL) {
    *result = G_ERROR_PARAM;
    j_return = json_pack("[s]", "client_id is mandatory on update mode");
  } else {
    j_client = json_loads(str_client, JSON_DECODE_ANY, NULL);
    if (j_client != NULL && json_is_object(j_client)) {
      if (mode == GLEWLWYD_IS_VALID_MODE_ADD) {
        if (json_is_string(json_object_get(j_client, "client_id")) && json_string_length(json_object_get(j_client, "client_id")) <= 128) {
          *result = G_OK;
        } else {
          *result = G_ERROR_PARAM;
          j_return = json_pack("[s]", "client_id must be a string value of maximum 128 characters");
        }
      } else {
        *result = G_OK;
      }
    } else {
      *result = G_ERROR_PARAM;
      j_return = json_pack("[s]", "client must be a JSON object");
    }
    json_decref(j_client);
  }

  if (j_return != NULL) {
    str_return = json_dumps(j_return, JSON_COMPACT);
    json_decref(j_return);
  }
  return str_return;
}

int client_module_add(const char * str_new_client, void * cls) {
  json_t * j_client = json_loads(str_new_client, JSON_DECODE_ANY, NULL);
  int ret, result;
  char * str_client;
  
  if (j_client != NULL) {
    str_client = client_module_get(json_string_value(json_object_get(j_client, "client_id")), &result, cls);
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
    if (json_object_get(j_client, "confidential") == json_true() && 0 == o_strcmp(password, "password")) {
      ret = G_OK;
    } else {
      ret = G_ERROR_UNAUTHORIZED;
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


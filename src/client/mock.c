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

json_t * client_module_load(struct config_module * config) {
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

int client_module_unload(struct config_module * config) {
  return G_OK;
}

int client_module_init(struct config_module * config, json_t * j_parameters, void ** cls) {
  const char * prefix = "";
  if (json_string_length(json_object_get(j_parameters, "client-id-prefix"))) {
    prefix = json_string_value(json_object_get(j_parameters, "client-id-prefix"));
  }
  *cls = (void*)json_pack("[{ss+ ss ss so s[ss] s[ss] s[] so}{ss+ ss ss so s[s] s[s] s[] so}{ss+ ss ss so s[ssssss] s[s] s[ss] so}]",
                            "client_id",
                            prefix,
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
                            prefix,
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
                            prefix,
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
  y_log_message(Y_LOG_LEVEL_DEBUG, "client_module_init - success %s %s, prefix: '%s'", config->profile_scope, config->admin_scope, prefix);
  return G_OK;
}

int client_module_close(struct config_module * config, void * cls) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "client_module_close - success");
  json_decref((json_t *)cls);
  return G_OK;
}

size_t client_module_count_total(struct config_module * config, const char * pattern, void * cls) {
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

json_t * client_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls) {
  json_t * j_user, * j_array, * j_array_pattern, * j_return;
  size_t index, counter = 0;

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
        if (index >= offset && (offset + counter) < json_array_size(j_array_pattern) && counter < limit) {
          json_array_append(j_array, j_user);
          counter++;
        }
      }
      j_return = json_pack("{sisO}", "result", G_OK, "list", j_array);
      json_decref(j_array);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_array_pattern);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

json_t * client_module_get(struct config_module * config, const char * client_id, void * cls) {
  json_t * j_client, * j_return = NULL;
  size_t index;
  
  if (client_id != NULL && o_strlen(client_id)) {
    json_array_foreach((json_t *)cls, index, j_client) {
      if (0 == o_strcmp(client_id, json_string_value(json_object_get(j_client, "client_id")))) {
        j_return = json_pack("{sisO}", "result", G_OK, "client", j_client);
        break;
      }
    }
    if (j_return == NULL) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

json_t * client_is_valid(struct config_module * config, const char * client_id, json_t * j_client, int mode, void * cls) {
  json_t * j_return = NULL;

  if ((mode == GLEWLWYD_IS_VALID_MODE_UPDATE || mode == GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) && client_id == NULL) {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "client_id is mandatory on update mode");
  } else {
    if (json_is_object(j_client)) {
      if (mode == GLEWLWYD_IS_VALID_MODE_ADD) {
        if (json_is_string(json_object_get(j_client, "client_id")) && json_string_length(json_object_get(j_client, "client_id")) <= 128) {
          j_return = json_pack("{si}", "result", G_OK);
        } else {
          j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "client_id must be a string value of maximum 128 characters");
        }
      } else {
        j_return = json_pack("{si}", "result", G_OK);
      }
    } else {
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "client must be a JSON object");
    }
  }

  return j_return;
}

int client_module_add(struct config_module * config, json_t * j_client, void * cls) {
  json_array_append((json_t *)cls, j_client);
  return G_OK;
}

int client_module_update(struct config_module * config, const char * client_id, json_t * j_client, void * cls) {
  size_t index;
  int ret, found = 0;
  json_t * j_element;
  
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
  return ret;
}

int client_module_delete(struct config_module * config, const char * client_id, void * cls) {
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

int client_module_check_password(struct config_module * config, const char * client_id, const char * password, void * cls) {
  int ret;
  json_t * j_client = client_module_get(config, client_id, cls);
  
  if (check_result_value(j_client, G_OK)) {
    if (json_object_get(json_object_get(j_client, "client"), "confidential") == json_true() && 0 == o_strcmp(password, "password")) {
      ret = G_OK;
    } else {
      ret = G_ERROR_UNAUTHORIZED;
    }
  } else {
    ret = G_ERROR_NOT_FOUND;
  }
  json_decref(j_client);
  return ret;
}

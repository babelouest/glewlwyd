/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * HTTP basic auth user module
 * 
 * Copyright 2017-2019 Nicolas Mora <mail@babelouest.org>
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
#include <ulfius.h>
#include "../glewlwyd-common.h"

json_t * user_module_load(struct config_module * config) {
  UNUSED(config);
  return json_pack("{sisssssss{s{ssso}s{sssoso}s{sssos[s]}}}",
                   "result",
                   G_OK,
                   "name",
                   "http",
                   "display_name",
                   "HTTP auth backend user module",
                   "description",
                   "Module to store users in the database",
                   "parameters",
                     "url",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                     "check-server-certificate",
                       "type",
                       "boolean",
                       "mandatory",
                       json_false(),
                       "default",
                       json_true(),
                     "default-scope",
                       "type",
                       "array",
                       "mandatory",
                       json_true(),
                       "values",
                        "string");
}

int user_module_unload(struct config_module * config) {
  UNUSED(config);
  return G_OK;
}

json_t * user_module_init(struct config_module * config, int readonly, json_t * j_params, void ** cls) {
  UNUSED(config);
  UNUSED(readonly);
  size_t index = 0;
  json_t * j_element = NULL, * j_return = NULL;
  int ret;
  
  if (json_is_object(j_params)) {
    ret = G_OK;
    if (!json_string_length(json_object_get(j_params, "url"))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init http - parameter url is mandatory must be a non empty string");
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "parameter url is mandatory must be a non empty string");
      ret = G_ERROR_PARAM;
    } else if (json_object_get(j_params, "check-server-certificate") != NULL && !json_is_boolean(json_object_get(j_params, "check-server-certificate"))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init http - parameter check-server-certificate is optional and must be a boolean");
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "parameter check-server-certificate is optional and must be a boolean");
    } else if (json_object_get(j_params, "default-scope") == NULL || !json_is_array(json_object_get(j_params, "default-scope"))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init http - parameter default-scope is mandatory must be an array of non empty strings");
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "parameter default-scope is mandatory must be an array of non empty strings");
      ret = G_ERROR_PARAM;
    } else {
      json_array_foreach(json_object_get(j_params, "default-scope"), index, j_element) {
        if (!json_string_length(j_element)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init http - parameter default-scope is mandatory must be an array of non empty strings");
          if (ret == G_OK) {
            j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "parameter default-scope is mandatory must be an array of non empty strings");
            ret = G_ERROR_PARAM;
          }
        }
      }
    }
    if (ret == G_OK) {
      j_return = json_pack("{si}", "result", G_OK);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init http - parameters must be a JSON object");
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "parameters must be a JSON object");
  }
  if (ret == G_OK) {
    *cls = json_incref(j_params);
  }
  return j_return;
}

int user_module_close(struct config_module * config, void * cls) {
  UNUSED(config);
  json_decref((json_t *)cls);
  return G_OK;
}

size_t user_module_count_total(struct config_module * config, const char * pattern, void * cls) {
  UNUSED(config);
  UNUSED(pattern);
  UNUSED(cls);
  return 0;
}

json_t * user_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls) {
  UNUSED(config);
  UNUSED(pattern);
  UNUSED(offset);
  UNUSED(limit);
  UNUSED(cls);
  return json_pack("{sis[]}", "result", G_OK, "list");
}

json_t * user_module_get(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  return json_pack("{sis{sssOso}}", "result", G_OK, "user", "username", username, "scope", json_object_get((json_t *)cls, "default-scope"), "enabled", json_true());
}

json_t * user_module_get_profile(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  return json_pack("{si}", "result", G_ERROR_NOT_FOUND);
}

json_t * user_module_is_valid(struct config_module * config, const char * username, json_t * j_user, int mode, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(j_user);
  UNUSED(mode);
  UNUSED(cls);
  return json_pack("{si}", "result", G_ERROR_PARAM);
}

int user_module_add(struct config_module * config, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(j_user);
  UNUSED(cls);
  return G_ERROR_PARAM;
}

int user_module_update(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(j_user);
  UNUSED(cls);
  return G_ERROR_PARAM;
}

int user_module_update_profile(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(j_user);
  UNUSED(cls);
  return G_ERROR_PARAM;
}

int user_module_delete(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  return G_ERROR_PARAM;
}

int user_module_check_password(struct config_module * config, const char * username, const char * password, void * cls) {
  UNUSED(config);
  struct _u_request request;
  struct _u_response response;
  int res, ret;
  
  ulfius_init_request(&request);
  ulfius_init_response(&response);
  request.http_verb = o_strdup("GET");
  request.http_url = o_strdup(json_string_value(json_object_get((json_t *)cls, "url")));
  if (json_object_get((json_t *)cls, "check-server-certificate") == json_false()) {
    request.check_server_certificate = 0;
  }
  request.auth_basic_user = o_strdup(username);
  request.auth_basic_password = o_strdup(password);
  
  res = ulfius_send_http_request(&request, &response);
  if (res == H_OK) {
    if (response.status == 200) {
      ret = G_OK;
    } else {
      ret = G_ERROR_UNAUTHORIZED;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_check_password http - Error ulfius_send_http_request");
    ret = G_ERROR;
  }
  
  ulfius_clean_request(&request);
  ulfius_clean_response(&response);
  return ret;
}

int user_module_update_password(struct config_module * config, const char * username, const char * new_password, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(new_password);
  UNUSED(cls);
  return G_ERROR_PARAM;
}

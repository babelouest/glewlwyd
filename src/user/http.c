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

int user_module_load(struct config_module * config, char ** name, char ** display_name, char ** description, char ** parameters) {
  int ret = G_OK;
  if (name != NULL && parameters != NULL && display_name != NULL && description != NULL) {
    *name = o_strdup("http");
    *display_name = o_strdup("HTTP Basic Auth backend user");
    *description = o_strdup("Module to authenticate users via a HTTP service with Basic Auth");
    *parameters = o_strdup("{}");
  } else {
    ret = G_ERROR;
  }
  return ret;
}

int user_module_unload(struct config_module * config) {
  return G_OK;
}

int user_module_init(struct config_module * config, const char * parameters, void ** cls) {
  json_t * j_params = json_loads(parameters, JSON_DECODE_ANY, NULL), * j_element;
  int ret;
  size_t index;
  
  if (j_params != NULL) {
    if (json_is_object(j_params)) {
      ret = G_OK;
      if (!json_string_length(json_object_get(j_params, "url"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init http - parameter url is mandatory must be a non empty string");
        ret = G_ERROR;
      }
      if (json_object_get(j_params, "check-server-certificate") != NULL && !json_is_boolean(json_object_get(j_params, "check-server-certificate"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init http - parameter check-server-certificate is optional and must be a boolean");
        ret = G_ERROR;
      }
      if (json_object_get(j_params, "default-scope") == NULL || !json_is_array(json_object_get(j_params, "default-scope"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init http - parameter default-scope is mandatory must be an array of non empty strings");
        ret = G_ERROR;
      } else {
        json_array_foreach(json_object_get(j_params, "default-scope"), index, j_element) {
          if (!json_string_length(j_element)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init http - parameter default-scope is mandatory must be an array of non empty strings");
            ret = G_ERROR;
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init http - parameters must be a JSON object");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init http - Error parsing parameters");
    ret = G_ERROR;
  }
  if (ret != G_OK) {
    json_decref(j_params);
  } else {
    *cls = j_params;
  }
  return ret;
}

int user_module_close(struct config_module * config, void * cls) {
  json_decref((json_t *)cls);
  return G_OK;
}

size_t user_module_count_total(struct config_module * config, const char * pattern, void * cls) {
  return 0;
}

char * user_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, int * result, void * cls) {
  *result = G_OK;
  return o_strdup("[]");
}

char * user_module_get(struct config_module * config, const char * username, int * result, void * cls) {
  *result = G_OK;
  json_t * j_user = json_pack("{sssO}", "username", username, "scope", json_object_get((json_t *)cls, "default-scope"));
  char * str_user = json_dumps(j_user, JSON_COMPACT);
  json_decref(j_user);
  return str_user;
}

char * user_module_get_profile(struct config_module * config, const char * username, int * result, void * cls) {
  *result = G_ERROR_NOT_FOUND;
  return NULL;
}

char * user_is_valid(struct config_module * config, const char * username, const char * str_user, int mode, int * result, void * cls) {
  *result = G_ERROR_PARAM;
  return NULL;
}

int user_module_add(struct config_module * config, const char * str_new_user, void * cls) {
  return G_ERROR_PARAM;
}

int user_module_update(struct config_module * config, const char * username, const char * str_user, void * cls) {
  return G_ERROR_PARAM;
}

int user_module_update_profile(struct config_module * config, const char * username, const char * str_user, void * cls) {
  return G_ERROR_PARAM;
}

int user_module_delete(struct config_module * config, const char * username, void * cls) {
  return G_ERROR_PARAM;
}

int user_module_check_password(struct config_module * config, const char * username, const char * password, void * cls) {
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
  return G_ERROR_PARAM;
}

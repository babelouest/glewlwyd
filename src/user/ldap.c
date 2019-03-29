/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * LDAP user module
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
#include <ldap.h>
#include <jansson.h>
#include <yder.h>
#include <orcania.h>
#include "../glewlwyd-common.h"

static json_t * is_user_ldap_parameters_valid(json_t * j_params) {
  json_t * j_return, * j_error = json_array(), * j_element;
  const char * field;
  
  if (j_error != NULL) {
    if (!json_is_object(j_params)) {
      json_array_append_new(j_error, json_string("parameters must be a JSON array"));
    } else {
      if (json_object_get(j_params, "uri") == NULL || !json_is_string(json_object_get(j_params, "uri"))) {
        json_array_append_new(j_error, json_string("uri is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "bind-dn") == NULL || !json_is_string(json_object_get(j_params, "bind-dn"))) {
        json_array_append_new(j_error, json_string("bind-dn is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "bind-password") == NULL || !json_is_string(json_object_get(j_params, "bind-password"))) {
        json_array_append_new(j_error, json_string("bind-password is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "search-scope") == NULL || !json_is_string(json_object_get(j_params, "search-scope"))) {
        json_array_append_new(j_error, json_string("search-scope is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "page-size") != NULL && !json_is_string(json_object_get(j_params, "page-size"))) {
        json_array_append_new(j_error, json_string("page-size is optional and must be a string"));
      }
      if (json_object_get(j_params, "base-search") == NULL || !json_is_string(json_object_get(j_params, "base-search"))) {
        json_array_append_new(j_error, json_string("base-search is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "filter") == NULL || !json_is_string(json_object_get(j_params, "filter"))) {
        json_array_append_new(j_error, json_string("filter is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "username-property") == NULL || !json_is_string(json_object_get(j_params, "username-property"))) {
        json_array_append_new(j_error, json_string("username-property is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "scope-property") == NULL || !json_is_string(json_object_get(j_params, "scope-property"))) {
        json_array_append_new(j_error, json_string("scope-property is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "scope-property-match") != NULL && !json_is_string(json_object_get(j_params, "scope-property-match"))) {
        json_array_append_new(j_error, json_string("scope-property-match is optional and must be a string"));
      }
      if (json_object_get(j_params, "name-property") != NULL && !json_is_string(json_object_get(j_params, "name-property"))) {
        json_array_append_new(j_error, json_string("name-property is optional and must be a string"));
      }
      if (json_object_get(j_params, "email-property") != NULL && !json_is_string(json_object_get(j_params, "email-property"))) {
        json_array_append_new(j_error, json_string("email-property is optional and must be a string"));
      }
      if (json_object_get(j_params, "rdn-property") != NULL && !json_is_string(json_object_get(j_params, "rdn-property"))) {
        json_array_append_new(j_error, json_string("rdn-property is optional and must be a string"));
      }
      if (json_object_get(j_params, "password-property") != NULL && !json_is_string(json_object_get(j_params, "password-property"))) {
        json_array_append_new(j_error, json_string("password-property is optional and must be a string"));
      }
      if (json_object_get(j_params, "password-property") != NULL && !json_is_string(json_object_get(j_params, "password-property"))) {
        json_array_append_new(j_error, json_string("password-property is optional and must be a string"));
      }
      if (json_object_get(j_params, "object-class") != NULL && !json_is_string(json_object_get(j_params, "object-class"))) {
        json_array_append_new(j_error, json_string("object-class is optional and must be a string"));
      }
      if (json_object_get(j_params, "data-format") != NULL) {
        if (!json_is_object(json_object_get(j_params, "data-format"))) {
          json_array_append_new(j_error, json_string("data-format is optional and must be a JSON object"));
        } else {
          json_object_foreach(json_object_get(j_params, "data-format"), field, j_element) {
            if (0 == o_strcmp(field, "username") || 0 == o_strcmp(field, "name") || 0 == o_strcmp(field, "email") || 0 == o_strcmp(field, "enabled") || 0 == o_strcmp(field, "password")) {
              json_array_append_new(j_error, json_string("data-format can not have settings for properties 'username', 'name', 'email', 'enabled' or 'password'"));
            } else {
              if (json_object_get(j_element, "multiple") != NULL && !json_is_boolean(json_object_get(j_element, "multiple"))) {
                json_array_append_new(j_error, json_string("multiple is optional and must be a boolean (default: false)"));
              }
              if (json_object_get(j_element, "read") != NULL && !json_is_boolean(json_object_get(j_element, "read"))) {
                json_array_append_new(j_error, json_string("read is optional and must be a boolean (default: true)"));
              }
              if (json_object_get(j_element, "write") != NULL && !json_is_boolean(json_object_get(j_element, "write"))) {
                json_array_append_new(j_error, json_string("write is optional and must be a boolean (default: true)"));
              }
              if (json_object_get(j_element, "profile-read") != NULL && !json_is_boolean(json_object_get(j_element, "profile-read"))) {
                json_array_append_new(j_error, json_string("profile-read is optional and must be a boolean (default: false)"));
              }
              if (json_object_get(j_element, "profile-write") != NULL && !json_is_boolean(json_object_get(j_element, "profile-write"))) {
                json_array_append_new(j_error, json_string("profile-write is optional and must be a boolean (default: false)"));
              }
            }
          }
        }
      }
    }
    if (json_array_size(j_error)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
    } else {
      j_return = json_pack("{si}", "result", G_OK);
    }
    json_decref(j_error);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_user_database_parameters_valid - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

int user_module_load(struct config_module * config, char ** name, char ** display_name, char ** description, char ** parameters) {
  int ret = G_OK;
  if (name != NULL && parameters != NULL && display_name != NULL && description != NULL) {
    *name = o_strdup("ldap");
    *display_name = o_strdup("LDAP backend user");
    *description = o_strdup("Module to use a LDAP server as backend for users");
    *parameters = o_strdup("{"
                           "\"uri\":{\"type\":\"string\",\"mandatory\":true},"
                           "\"bind-dn\":{\"type\":\"string\",\"mandatory\":true},"
                           "\"bind-password\":{\"type\":\"string\",\"mandatory\":true},"
                           "\"search-scope\":{\"type\":\"string\",\"mandatory\":true},"
                           "\"page-size\":{\"type\":\"number\",\"mandatory\":false},"
                           "\"base-search\":{\"type\":\"string\",\"mandatory\":true},"
                           "\"filter\":{\"type\":\"string\",\"mandatory\":true},"
                           "\"username-property\":{\"type\":\"string\",\"mandatory\":true},"
                           "\"scope-property\":{\"type\":\"string\",\"mandatory\":true},"
                           "\"scope-property-match\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"name-property\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"email-property\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"rdn-property\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"password-property\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"password-algorithm\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"object-class\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"data-format\":{"
                            "\"field-name\":{"
                              "\"multiple\":{\"type\":\"boolean\",\"default\":false},"
                              "\"read\":{\"type\":\"boolean\",\"default\":true},"
                              "\"write\":{\"type\":\"boolean\",\"default\":true},"
                              "\"profile-read\":{\"type\":\"boolean\",\"default\":false},"
                              "\"profile-write\":{\"type\":\"boolean\",\"default\":false}"
                            "}"
                           "}"
                           "}");
  } else {
    ret = G_ERROR;
  }
  return ret;
}

int user_module_unload(struct config_module * config) {
  return G_OK;
}

int user_module_init(struct config_module * config, const char * parameters, void ** cls) {
  json_t * j_params = json_loads(parameters, JSON_DECODE_ANY, NULL), * j_result;
  int ret;
  char * error_message;
  
  if (j_params != NULL) {
    j_result = is_user_ldap_parameters_valid(j_params);
    if (check_result_value(j_result, G_OK)) {
      *cls = j_params;
      ret = G_OK;
    } else if (check_result_value(j_result, G_ERROR_PARAM)) {
      error_message = json_dumps(json_object_get(j_result, "error"), JSON_COMPACT);
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error parsing parameters");
      y_log_message(Y_LOG_LEVEL_ERROR, error_message);
      o_free(error_message);
      json_decref(j_params);
      ret = G_ERROR_PARAM;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error is_user_database_parameters_valid");
      json_decref(j_params);
      ret = G_ERROR;
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error parsing parameters");
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int user_module_close(struct config_module * config, void * cls) {
  return G_OK;
}

size_t user_module_count_total(const char * pattern, void * cls) {
  json_t * j_params = (json_t *)cls;
  LDAP * ldap = NULL;
  int i = 0, j;
  json_t * j_result = NULL;
  size_t count = 0;
  
  int result;
  int ldap_version = LDAP_VERSION3;
  char * filter = NULL;
  char * attrs[] = {NULL};
  int attrsonly = 0;
  char * ldap_mech = LDAP_SASL_SIMPLE;
  struct berval cred;
  
  if (ldap_initialize(&ldap, json_string_value(json_object_get(j_params, "uri"))) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_count_total ldap - Error initializing ldap");
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_count_total ldap - Error setting ldap protocol version");
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_count_total ldap - Error setting ldap protocol version");
  }
  return 0;
}

char * user_module_get_list(const char * pattern, size_t offset, size_t limit, int * result, void * cls) {
  return NULL;
}

char * user_module_get(const char * username, int * result, void * cls) {
  return NULL;
}

char * user_module_get_profile(const char * username, int * result, void * cls) {
  return NULL;
}

char * user_is_valid(const char * username, const char * str_user, int mode, int * result, void * cls) {
  return NULL;
}

int user_module_add(const char * str_new_user, void * cls) {
  return G_OK;
}

int user_module_update(const char * username, const char * str_user, void * cls) {
  return G_OK;
}

int user_module_update_profile(const char * username, const char * str_user, void * cls) {
  return G_OK;
}

int user_module_delete(const char * username, void * cls) {
  return G_OK;
}

int user_module_check_password(const char * username, const char * password, void * cls) {
  return G_OK;
}

int user_module_update_password(const char * username, const char * new_password, void * cls) {
  return G_ERROR_PARAM;
}

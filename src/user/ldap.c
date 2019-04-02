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

#define LDAP_DEFAULT_PAGE_SIZE 50

/**
 * 
 * Escapes any special chars (RFC 4515) from a string representing a
 * a search filter assertion value.
 * 
 * You must o_free the returned value after use
 *
 */
static char * escape_ldap(const char * input) {
  char * tmp, * to_return = NULL;
  size_t len, i;
  
  if (input != NULL) {
    to_return = strdup("");
    len = strlen(input);
    for (i=0; i < len && to_return != NULL; i++) {
      unsigned char c = input[i];
      if (c == '*') {
        // escape asterisk
        tmp = msprintf("%s\\2a", to_return);
        o_free(to_return);
        to_return = tmp;
      } else if (c == '(') {
        // escape left parenthesis
        tmp = msprintf("%s\\28", to_return);
        o_free(to_return);
        to_return = tmp;
      } else if (c == ')') {
        // escape right parenthesis
        tmp = msprintf("%s\\29", to_return);
        o_free(to_return);
        to_return = tmp;
      } else if (c == '\\') {
        // escape backslash
        tmp = msprintf("%s\\5c", to_return);
        o_free(to_return);
        to_return = tmp;
      } else if ((c & 0x80) == 0) {
        // regular 1-byte UTF-8 char
        tmp = msprintf("%s%c", to_return, c);
        o_free(to_return);
        to_return = tmp;
      } else if (((c & 0xE0) == 0xC0) && i < (len-2)) { 
        // higher-order 2-byte UTF-8 chars
        tmp = msprintf("%s\\%02x\\%02x", to_return, input[i], input[i+1]);
        o_free(to_return);
        to_return = tmp;
      } else if (((c & 0xF0) == 0xE0) && i < (len-3)) { 
        // higher-order 3-byte UTF-8 chars
        tmp = msprintf("%s\\%02x\\%02x\\%02x", to_return, input[i], input[i+1], input[i+2]);
        o_free(to_return);
        to_return = tmp;
      } else if (((c & 0xF8) == 0xF0) && i < (len-4)) { 
        // higher-order 4-byte UTF-8 chars
        tmp = msprintf("%s\\%02x\\%02x\\%02x\\%02x", to_return, input[i], input[i+1], input[i+2], input[i+3]);
        o_free(to_return);
        to_return = tmp;
      }
    }
  }
  return to_return;
}

static json_t * is_user_ldap_parameters_valid(json_t * j_params) {
  json_t * j_return, * j_error = json_array(), * j_element, * j_element_p;
  size_t index;
  const char * field;
  
  if (j_error != NULL) {
    if (!json_is_object(j_params)) {
      json_array_append_new(j_error, json_string("parameters must be a JSON array"));
    } else {
      if (json_object_get(j_params, "uri") == NULL || !json_is_string(json_object_get(j_params, "uri")) || !json_string_length(json_object_get(j_params, "uri"))) {
        json_array_append_new(j_error, json_string("uri is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "bind-dn") == NULL || !json_is_string(json_object_get(j_params, "bind-dn")) || !json_string_length(json_object_get(j_params, "bind-dn"))) {
        json_array_append_new(j_error, json_string("bind-dn is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "bind-password") == NULL || !json_is_string(json_object_get(j_params, "bind-password")) || !json_string_length(json_object_get(j_params, "bind-password"))) {
        json_array_append_new(j_error, json_string("bind-password is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "search-scope") != NULL && !json_is_string(json_object_get(j_params, "search-scope"))) {
        json_array_append_new(j_error, json_string("search-scope is optional and must be a string"));
      } else if (json_object_get(j_params, "search-scope") == NULL) {
        json_object_set_new(j_params, "search-scope", json_string("one"));
      } else if (0 == o_strcmp("one", json_string_value(json_object_get(j_params, "search-scope"))) || 0 == o_strcmp("subtree", json_string_value(json_object_get(j_params, "search-scope"))) || 0 == o_strcmp("children", json_string_value(json_object_get(j_params, "search-scope")))) {
        json_array_append_new(j_error, json_string("search-scope must have one of the following values: 'one', 'subtree', 'children'"));
      }
      if (json_object_get(j_params, "page-size") != NULL && (!json_is_integer(json_object_get(j_params, "page-size")) || json_integer_value(json_object_get(j_params, "page-size")) > 0)) {
        json_array_append_new(j_error, json_string("page-size is optional and must be a positive integer"));
      } else if (json_object_get(j_params, "page-size") == NULL) {
        json_object_set_new(j_params, "page-size", json_integer(LDAP_DEFAULT_PAGE_SIZE));
      }
      if (json_object_get(j_params, "base-search") == NULL || !json_is_string(json_object_get(j_params, "base-search")) || !json_string_length(json_object_get(j_params, "base-search"))) {
        json_array_append_new(j_error, json_string("base-search is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "filter") == NULL || !json_is_string(json_object_get(j_params, "filter")) || !json_string_length(json_object_get(j_params, "filter"))) {
        json_array_append_new(j_error, json_string("filter is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "username-property") == NULL || !json_is_string(json_object_get(j_params, "username-property")) || !json_string_length(json_object_get(j_params, "username-property")) || !json_is_array(json_object_get(j_params, "username-property"))) {
        json_array_append_new(j_error, json_string("username-property is mandatory and must be a string or an array of string"));
      } else if (json_is_array(json_object_get(j_params, "username-property"))) {
        json_array_foreach(json_object_get(j_params, "username-property"), index, j_element) {
          if (!json_is_string(j_element)) {
            json_array_append_new(j_error, json_string("username-property is mandatory and must be a string or an array of string"));
          }
        }
      }
      if (json_object_get(j_params, "scope-property") == NULL || !json_is_string(json_object_get(j_params, "scope-property")) || !json_string_length(json_object_get(j_params, "scope-property")) || !json_is_array(json_object_get(j_params, "scope-property"))) {
        json_array_append_new(j_error, json_string("scope-property is mandatory and must be a string or an array of string"));
      } else if (json_is_array(json_object_get(j_params, "scope-property"))) {
        json_array_foreach(json_object_get(j_params, "scope-property"), index, j_element) {
          if (!json_is_string(j_element)) {
            json_array_append_new(j_error, json_string("scope-property is mandatory and must be a string or an array of string"));
          }
        }
      }
      if (json_object_get(j_params, "scope-match") != NULL && !json_is_array(json_object_get(j_params, "scope-match"))) {
        json_array_append_new(j_error, json_string("scope-match is optional and must be a JSON array"));
      } else if (json_object_get(j_params, "scope-match") != NULL) {
        json_array_foreach(json_object_get(j_params, "scope-property-match-correspondence"), index, j_element) {
          if (!json_is_string(json_object_get(j_element, "ldap-value"))) {
            json_array_append_new(j_error, json_string("ldap-value is mandatory and must be a string"));
          }
          if (!json_is_string(json_object_get(j_element, "scope-value"))) {
            json_array_append_new(j_error, json_string("scope-value is mandatory and must be a string"));
          }
          if (!json_is_string(json_object_get(j_element, "match")) || 0 != o_strcmp("equals", json_string_value(json_object_get(j_element, "match"))) || 0 != o_strcmp("contains", json_string_value(json_object_get(j_element, "match"))) || 0 != o_strcmp("startswith", json_string_value(json_object_get(j_element, "match"))) || 0 != o_strcmp("endswith", json_string_value(json_object_get(j_element, "match")))) {
            json_array_append_new(j_error, json_string("match is mandatory and must have one of the following values: 'equals', 'contains', 'startswith', 'endswith'"));
          }
        }
      }
      if (json_object_get(j_params, "name-property") != NULL && (!json_is_string(json_object_get(j_params, "name-property")) || !json_is_array(json_object_get(j_params, "name-property")))) {
        json_array_append_new(j_error, json_string("name-property is optional and must be a string or an array of string"));
      } else if (json_is_array(json_object_get(j_params, "name-property"))) {
        json_array_foreach(json_object_get(j_params, "name-property"), index, j_element) {
          if (!json_is_string(j_element)) {
            json_array_append_new(j_error, json_string("name-property is optional and must be a string or an array of string"));
          }
        }
      }
      if (json_object_get(j_params, "email-property") != NULL && !json_is_string(json_object_get(j_params, "email-property"))) {
        json_array_append_new(j_error, json_string("email-property is optional and must be a string"));
      } else if (json_is_array(json_object_get(j_params, "name-property"))) {
        json_array_foreach(json_object_get(j_params, "name-property"), index, j_element) {
          if (!json_is_string(j_element)) {
            json_array_append_new(j_error, json_string("name-property is optional and must be a string or an array of string"));
          }
        }
      }
      if (json_object_get(j_params, "rdn-property") != NULL && !json_is_string(json_object_get(j_params, "rdn-property"))) {
        json_array_append_new(j_error, json_string("rdn-property is optional and must be a string"));
      }
      if (json_object_get(j_params, "password-property") != NULL && !json_is_string(json_object_get(j_params, "password-property"))) {
        json_array_append_new(j_error, json_string("password-property is optional and must be a string"));
      }
      if (json_object_get(j_params, "password-algorithm") != NULL && (!json_is_string(json_object_get(j_params, "password-algorithm")) || (0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "SSHA") && 0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "SHA") && 0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "SMD5") && 0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "MD5") && 0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "PLAIN")))) {
        json_array_append_new(j_error, json_string("password-property is optional and must have one of the following values: 'SSHA', 'SHA', 'SMD5', 'MD5' or 'PLAIN'"));
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
              json_array_append_new(j_error, json_string("data-format can not have settings for properties 'username', 'name', 'email', 'enabled', 'scope' or 'password'"));
            } else {
              if (json_object_get(j_element, "property") == NULL || !json_is_string(json_object_get(j_element, "property")) || !json_string_length(json_object_get(j_element, "property")) || !json_is_array(json_object_get(j_element, "property"))) {
                json_array_append_new(j_error, json_string("property is mandatory and must be a non empty string or an array of string"));
              } else if (json_is_array(json_object_get(j_element, "property"))) {
                json_array_foreach(json_object_get(j_element, "property"), index, j_element_p) {
                  if (!json_is_string(j_element_p)) {
                    json_array_append_new(j_error, json_string("property is mandatory and must be a non empty string or an array of string"));
                  }
                }
              }
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

static LDAP * connect_ldap_server(json_t * j_params) {
  LDAP * ldap = NULL;
  int ldap_version = LDAP_VERSION3;
  int result;
  char * ldap_mech = LDAP_SASL_SIMPLE;
  struct berval cred, * servcred;
  
  cred.bv_val = (char*)json_string_value(json_object_get(j_params, "bind-password"));
  cred.bv_len = o_strlen(json_string_value(json_object_get(j_params, "bind-password")));
  
  if (ldap_initialize(&ldap, json_string_value(json_object_get(j_params, "uri"))) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_count_total ldap - Error initializing ldap");
    ldap = NULL;
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_count_total ldap - Error setting ldap protocol version");
    ldap_unbind_ext(ldap, NULL, NULL);
    ldap = NULL;
  } else if ((result = ldap_sasl_bind_s(ldap, json_string_value(json_object_get(j_params, "bind-dn")), ldap_mech, &cred, NULL, NULL, &servcred)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error binding to ldap server mode %s: %s", ldap_mech, ldap_err2string(result));
    ldap_unbind_ext(ldap, NULL, NULL);
    ldap = NULL;
  }
  
  return ldap;
}

static char * get_ldap_filter_pattern(json_t * j_params, const char * pattern) {
  char * pattern_escaped, * filter, * name_filter, * email_filter;
  
  if (o_strlen(pattern)) {
    pattern_escaped = escape_ldap(pattern);
    if (json_object_get(j_params, "name-property") != NULL) {
      name_filter = msprintf("(%s=*%s*)", json_string_value(json_object_get(j_params, "name-property")), pattern_escaped);
    } else {
      name_filter = o_strdup("");
    }
    if (json_object_get(j_params, "email-property") != NULL) {
      email_filter = msprintf("(%s=*%s*)", json_string_value(json_object_get(j_params, "email-property")), pattern_escaped);
    } else {
      email_filter = o_strdup("");
    }
    filter = msprintf("(&(%s)(|(%s=*%s*)%s%s))", 
                      json_string_value(json_object_get(j_params, "filter")), 
                      json_string_value(json_object_get(j_params, "username-property")),
                      pattern_escaped,
                      name_filter,
                      email_filter);
    o_free(pattern_escaped);
    o_free(name_filter);
    o_free(email_filter);
  } else {
    filter = msprintf("(%s)", json_string_value(json_object_get(j_params, "filter")));
  }
  
  return filter;
}

static const char * get_read_property(json_t * j_params, const char * property) {
  if (json_is_string(json_object_get(j_params, property))) {
    return json_string_value(json_object_get(j_params, property));
  } else if (json_is_array(json_object_get(j_params, property))) {
    return json_string_value(json_array_get(json_object_get(j_params, property), 0));
  } else {
    return NULL;
  }
}

static char ** get_ldap_read_attributes(json_t * j_params, int profile, json_t * j_properties) {
  char ** attrs = NULL;
  size_t i, nb_attrs = 2; // Username, Scope
  json_t * j_element;
  const char * field;
  
  if (j_properties != NULL && json_is_object(j_properties) && !json_object_size(j_properties)) {
    nb_attrs += (json_object_get(j_params, "name-property") != NULL);
    nb_attrs += (json_object_get(j_params, "email-property") != NULL);
    if (json_object_get(j_params, "data-format") != NULL) {
      json_object_foreach(json_object_get(j_params, "data-format"), field, j_element) {
        nb_attrs += ((!profile && json_object_get(j_element, "read") != json_false()) || (profile && json_object_get(j_element, "profile-read") == json_true()));
      }
    }
    attrs = o_malloc((nb_attrs + 1) * sizeof(char *));
    if (attrs != NULL) {
      attrs[nb_attrs] = NULL;
      attrs[0] = (char*)get_read_property(j_params, "username-property");
      json_object_set(j_properties, "username", json_string(get_read_property(j_params, "username-property")));
      attrs[1] = (char*)get_read_property(j_params, "scope-property");
      json_object_set(j_properties, "scope", json_string(get_read_property(j_params, "scope-property")));
      i = 2;
      if (json_object_get(j_params, "name-property") != NULL) {
        attrs[i++] = (char*)get_read_property(j_params, "name-property");
        json_object_set(j_properties, "name", json_string(get_read_property(j_params, "name-property")));
      }
      if (json_object_get(j_params, "email-property") != NULL) {
        attrs[i++] = (char*)get_read_property(j_params, "email-property");
        json_object_set(j_properties, "email", json_string(get_read_property(j_params, "email-property")));
      }
      if (json_object_get(j_params, "data-format") != NULL) {
        json_object_foreach(json_object_get(j_params, "data-format"), field, j_element) {
          if ((!profile && json_object_get(j_element, "read") != json_false()) || (profile && json_object_get(j_element, "profile-read") == json_true())) {
            attrs[i++] = (char*)get_read_property(j_element, "property");
            json_object_set(j_properties, field, json_string(get_read_property(j_element, "property")));
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_read_attributes - Error allocating resources for attrs");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_read_attributes - Error j_properties is not an empty JSON object");
  }
  return attrs;
}

// TODO
static LDAPMod ** get_ldap_write_mod(json_t * j_params, json_t * j_user, int profile, int add, json_t * j_mod_value_free_array) {
  LDAPMod ** mods = NULL;
  size_t nb_attr = 0;
  
  if (j_mod_value_free_array != NULL) {
    // Count attrs
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error j_mod_value_free_array is NULL");
  }
  return mods;
}

static json_t * get_scope_from_ldap(json_t * j_params, const char * ldap_scope_value) {
  json_t * j_element;
  const char * key, * value;
  
  if (json_object_get(j_params, "scope-property-match-correspondence") != NULL) {
    json_object_foreach(json_object_get(j_params, "scope-property-match-correspondence"), key, j_element) {
      value = json_string_value(j_element);
      if ((0 == o_strcmp("equals", json_string_value(json_object_get(j_params, "scope-property-match"))) && 0 == o_strcmp(value, ldap_scope_value)) ||
          (0 == o_strcmp("contains", json_string_value(json_object_get(j_params, "scope-property-match"))) && NULL != o_strstr(ldap_scope_value, value)) ||
          (0 == o_strcmp("starts-with", json_string_value(json_object_get(j_params, "scope-property-match"))) && 0 != o_strncmp(ldap_scope_value, value, o_strlen(value))) ||
          (0 == o_strcmp("ends-with", json_string_value(json_object_get(j_params, "scope-property-match"))) && 0 != strcmp(ldap_scope_value + o_strlen(ldap_scope_value) - o_strlen(value), value))) {
        return json_string(key);
      }
    }
  }
  return json_string(ldap_scope_value);
}

static json_t * get_user_from_result(json_t * j_params, json_t * j_properties_user, LDAP * ldap, LDAPMessage * entry) {
  json_t * j_user = json_object(), * j_property, * j_scope;
  const char * field;
  char * str_scope;
  struct berval ** result_values = NULL;
  int i;
  
  if (j_user != NULL) {
    json_object_foreach(j_properties_user, field, j_property) {
      result_values = ldap_get_values_len(ldap, entry, json_string_value(j_property));
      if (ldap_count_values_len(result_values) > 0) {
        if (0 == o_strcmp(field, "username") || 0 == o_strcmp(field, "name") || 0 == o_strcmp(field, "email") || json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "multiple") != json_true()) {
          json_object_set_new(j_user, field, json_stringn(result_values[0]->bv_val, result_values[0]->bv_len));
        } else if (0 != o_strcmp(field, "scope") && json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "multiple") == json_true()) {
          json_object_set_new(j_user, field, json_array());
          for (i=0; i<ldap_count_values_len(result_values); i++) {
            json_array_append_new(json_object_get(j_user, field), json_stringn(result_values[i]->bv_val, result_values[i]->bv_len));
          }
        } else if (0 == o_strcmp(field, "scope")) {
          json_object_set_new(j_user, field, json_array());
          for (i=0; i<ldap_count_values_len(result_values); i++) {
            str_scope = o_strndup(result_values[i]->bv_val, result_values[i]->bv_len);
            j_scope = get_scope_from_ldap(j_params, str_scope);
            o_free(str_scope);
            if (j_scope != NULL) {
              json_array_append_new(json_object_get(j_user, field), j_scope);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_user_from_result - Error get_scope_from_ldap");
            }
          }
        }
      }
      // A ldap user is always enabled, until I find a standard way to do it
      json_object_set_new(j_user, "enabled", json_true());
      ldap_value_free_len(result_values);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_from_result - Error allocating resources for j_user");
  }
  return j_user;
}

// TODO
static char * get_user_dn_from_username(json_t * j_params, LDAP * ldap, const char * username) {
  return NULL;
}

// TODO
static digest_algorithm get_digest_algorithm(json_t * j_params) {
  return digest_MD5;
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
                           "\"scope-match\":[{\"ldap-value\":{\"type\":\"string\",\"mandatory\":true}},"
                                            "{\"scope-value\":{\"type\":\"string\",\"mandatory\":true}},"
                                            "{\"match\":{\"type\":\"list\",\"mandatory\":true,\"values\":[\"equals\",\"contains\",\"startswith\",\"endswith\"]}}],"
                           "\"name-property\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"email-property\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"rdn-property\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"password-property\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"password-algorithm\":{\"type\":\"list\",\"mandatory\":false,\"values\":[\"SSHA\",\"SHA\",\"SMD5\",\"MD5\",\"PLAIN\"]},"
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
  json_t * j_params = json_loads(parameters, JSON_DECODE_ANY, NULL), * j_properties;
  int ret;
  char * error_message;
  
  if (j_params != NULL) {
    j_properties = is_user_ldap_parameters_valid(j_params);
    if (check_result_value(j_properties, G_OK)) {
      *cls = j_params;
      ret = G_OK;
    } else if (check_result_value(j_properties, G_ERROR_PARAM)) {
      error_message = json_dumps(json_object_get(j_properties, "error"), JSON_COMPACT);
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
    json_decref(j_properties);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error parsing parameters");
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int user_module_close(struct config_module * config, void * cls) {
  json_decref((json_t *)cls);
  return G_OK;
}

size_t user_module_count_total(const char * pattern, void * cls) {
  json_t * j_params = (json_t *)cls;
  LDAP * ldap = connect_ldap_server(j_params);
  LDAPMessage * answer = NULL;
  char * attrs[] = { NULL }, * filter;
  int  attrsonly = 0;
  size_t counter = 0;
  int result, scope = LDAP_SCOPE_ONELEVEL;
  
  if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_SUBTREE;
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_CHILDREN;
  }
  if (ldap != NULL) {
    filter = get_ldap_filter_pattern(j_params, pattern);
    if ((result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search, base search: %s, filter: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(result));
    } else {
      // Looping in results, staring at offset, until the end of the list
      counter = ldap_count_entries(ldap, answer);
    }
    ldap_msgfree(answer);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_count_total ldap - Error connect_ldap_server");
  }
  return counter;
}

char * user_module_get_list(const char * pattern, size_t offset, size_t limit, int * result, void * cls) {
  json_t * j_params = (json_t *)cls, * j_properties_user = NULL, * j_user_list, * j_user;
  LDAP * ldap = connect_ldap_server(j_params);
  LDAPMessage * entry;
  int i = 0;
  char * str_result = NULL;
  
  int  ldap_result;
  int  scope = LDAP_SCOPE_ONELEVEL;
  char * filter = NULL;
  char ** attrs = NULL;
  int  attrsonly = 0;

  /* paged control variables */
  struct berval new_cookie, * cookie = NULL;
  int more_page, l_errcode = 0, l_entries, l_entry_count = 0, l_count;
  LDAPControl * page_control = NULL, * search_controls[2] = { NULL, NULL }, ** returned_controls = NULL;
  LDAPMessage * l_result = NULL;
  ber_int_t total_count;
  
  if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_SUBTREE;
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_CHILDREN;
  }
  if (ldap != NULL) {
    // Connection successful, doing ldap search
    filter = get_ldap_filter_pattern(j_params, pattern);
    attrs = get_ldap_read_attributes(j_params, 0, (j_properties_user = json_object()));
    j_user_list = json_array();
    do {
      *result = G_OK;
      ldap_result = ldap_create_page_control(ldap, json_integer_value(json_object_get(j_params, "page-size")), cookie, 0, &page_control);
      if (ldap_result != LDAP_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error ldap_create_page_control, message: %s", ldap_err2string(ldap_result));
        *result = G_ERROR;
        break;
      }
      
      search_controls[0] = page_control;
      ldap_result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, search_controls, NULL, NULL, 0, &l_result);
      if ((ldap_result != LDAP_SUCCESS) & (ldap_result != LDAP_PARTIAL_RESULTS)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error ldap search, base search: %s, filter: %s, error message: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(ldap_result));
        *result = G_ERROR;
        break;
      }
      
      ldap_result = ldap_parse_result(ldap, l_result, &l_errcode, NULL, NULL, NULL, &returned_controls, 0);
      if (ldap_result != LDAP_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error ldap_parse_result, message: %s", ldap_err2string(ldap_result));
        *result = G_ERROR;
        break;
      }
      
      if (cookie != NULL) {
        ber_bvfree(cookie);
        cookie = NULL;
      }
      
      ldap_result = ldap_parse_pageresponse_control(ldap, *returned_controls, &total_count, &new_cookie);
      if (ldap_result != LDAP_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error ldap_parse_pageresponse_control, message: %s", ldap_err2string(ldap_result));
        *result = G_ERROR;
        break;
      }
      
      cookie = ber_memalloc( sizeof( struct berval ) );
      if (cookie != NULL) {
        *cookie = new_cookie;
        if (cookie->bv_val != NULL && (strlen(cookie->bv_val) > 0)) {
          more_page = 1;
        } else {
          more_page = 0;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error ber_malloc returned NULL");
        *result = G_ERROR;
        break;
      }
      
      if (returned_controls != NULL)
      {
        ldap_controls_free(returned_controls);
        returned_controls = NULL;
      }
      search_controls[0] = NULL;
      ldap_control_free(page_control);
      page_control = NULL;
      
      l_entries = ldap_count_entries(ldap, l_result);
      if (l_entry_count <= offset && offset < (l_entry_count + l_entries)) {
        entry = ldap_first_entry(ldap, l_result);
        l_count = offset - l_entry_count;
        for (;entry !=NULL && l_count > 0; entry = ldap_next_entry(ldap, entry)) {
          l_count--;
        }
        
        while (entry != NULL && i<(offset+limit)) {
          j_user = get_user_from_result(j_params, j_properties_user, ldap, entry);
          if (j_user != NULL) {
            json_array_append_new(j_user_list, j_user);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error get_user_from_result");
          }
          entry = ldap_next_entry(ldap, entry);
          i++;
        }
      }
      if (l_entries > 0) {
        l_entry_count = l_entry_count + l_entries;
        if (l_entry_count >= (offset + limit)) {
          break;
        }
      }
      ldap_msgfree(l_result);
      l_result = NULL;
    } while (more_page);
    ldap_msgfree(l_result);
    l_result = NULL;
    o_free(filter);

    ldap_unbind_ext(ldap, NULL, NULL);
    str_result = json_dumps(j_user_list, JSON_COMPACT);
    json_decref(j_user_list);
    json_decref(j_properties_user);
    o_free(attrs);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error connect_ldap_server");
    *result = G_ERROR;
  }
  return str_result;
}

char * user_module_get(const char * username, int * result, void * cls) {
  json_t * j_params = (json_t *)cls, * j_properties_user = NULL, * j_user;
  LDAP * ldap = connect_ldap_server(j_params);
  LDAPMessage * entry, * answer;
  int ldap_result;
  char * str_result = NULL;
  
  int  scope = LDAP_SCOPE_ONELEVEL;
  char * filter = NULL;
  char ** attrs = NULL;
  int attrsonly = 0;

  if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_SUBTREE;
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_CHILDREN;
  }
  if (ldap != NULL) {
    // Connection successful, doing ldap search
    filter = msprintf("(&(%s)(%s=%s))", json_string_value(json_object_get(j_params, "filter")), json_string_value(json_object_get(j_params, "username-property")), username);
    attrs = get_ldap_read_attributes(j_params, 0, (j_properties_user = json_object()));
    if ((ldap_result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search, base search: %s, filter: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(ldap_result));
      *result = G_ERROR;
    } else {
      // Looping in results, staring at offset, until the end of the list
      if (ldap_count_entries(ldap, answer) > 0) {
        entry = ldap_first_entry(ldap, answer);
        j_user = get_user_from_result(j_params, j_properties_user, ldap, entry);
        if (j_user != NULL) {
          str_result = json_dumps(j_user, JSON_COMPACT);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error get_user_from_result");
        }
        json_decref(j_user);
      } else {
        *result = G_ERROR_NOT_FOUND;
      }
    }
    
    json_decref(j_properties_user);
    o_free(attrs);
    o_free(filter);
    ldap_msgfree(answer);
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error connect_ldap_server");
    *result = G_ERROR;
  }
  return str_result;
}

char * user_module_get_profile(const char * username, int * result, void * cls) {
  json_t * j_params = (json_t *)cls, * j_properties_user = NULL, * j_user;
  LDAP * ldap = connect_ldap_server(j_params);
  LDAPMessage * entry, * answer;
  int ldap_result;
  char * str_result = NULL;
  
  int  scope = LDAP_SCOPE_ONELEVEL;
  char * filter = NULL;
  char ** attrs = NULL;
  int attrsonly = 0;

  if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_SUBTREE;
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_CHILDREN;
  }
  if (ldap != NULL) {
    // Connection successful, doing ldap search
    filter = msprintf("(&(%s)(%s=%s))", json_string_value(json_object_get(j_params, "filter")), json_string_value(json_object_get(j_params, "username-property")), username);
    attrs = get_ldap_read_attributes(j_params, 1, (j_properties_user = json_object()));
    if ((ldap_result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search, base search: %s, filter: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(ldap_result));
      *result = G_ERROR;
    } else {
      // Looping in results, staring at offset, until the end of the list
      if (ldap_count_entries(ldap, answer) > 0) {
        entry = ldap_first_entry(ldap, answer);
        j_user = get_user_from_result(j_params, j_properties_user, ldap, entry);
        if (j_user != NULL) {
          str_result = json_dumps(j_user, JSON_COMPACT);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error get_user_from_result");
        }
        json_decref(j_user);
      } else {
        *result = G_ERROR_NOT_FOUND;
      }
    }
    
    json_decref(j_properties_user);
    o_free(attrs);
    o_free(filter);
    ldap_msgfree(answer);
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error connect_ldap_server");
    *result = G_ERROR;
  }
  return str_result;
}

char * user_is_valid(const char * username, const char * str_user, int mode, int * result, void * cls) {
  json_t * j_params = (json_t *)cls;
  json_t * j_user = json_loads(str_user, JSON_DECODE_ANY, NULL), * j_result = NULL, * j_element, * j_format, * j_value;
  char * str_result = NULL, * message;
  int res;
  size_t index;
  const char * property;
  
  if (j_user != NULL && json_is_object(j_user)) {
    *result = G_OK;
    j_result = json_array();
    if (j_result != NULL) {
      if (mode == GLEWLWYD_IS_VALID_MODE_ADD) {
        if (!json_is_string(json_object_get(j_user, "username")) || !json_string_length(json_object_get(j_user, "username"))) {
          *result = G_ERROR_PARAM;
          json_array_append_new(j_result, json_string("username is mandatory and must be a non empty string"));
        } else {
          o_free(user_module_get(json_string_value(json_object_get(j_user, "username")), &res, cls));
          if (res == G_OK) {
            *result = G_ERROR_PARAM;
            json_array_append_new(j_result, json_string("username already exist"));
          } else if (res != G_ERROR_NOT_FOUND) {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_is_valid database - Error user_module_get");
          }
        }
      } else if ((mode == GLEWLWYD_IS_VALID_MODE_UPDATE || mode == GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) && username == NULL) {
        *result = G_ERROR_PARAM;
        json_array_append_new(j_result, json_string("username is mandatory on update mode"));
      }
      if (mode != GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) {
        if (!json_is_array(json_object_get(j_user, "scope"))) {
          *result = G_ERROR_PARAM;
          json_array_append_new(j_result, json_string("scope must be a JSON array of string"));
        } else {
          json_array_foreach(json_object_get(j_user, "scope"), index, j_element) {
            if (!json_is_string(j_element) || !json_string_length(j_element)) {
              *result = G_ERROR_PARAM;
              json_array_append_new(j_result, json_string("scope must be a JSON array of string"));
            }
          }
        }
      }
      if (mode != GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE && json_object_get(j_user, "password") != NULL && !json_is_string(json_object_get(j_user, "password"))) {
        *result = G_ERROR_PARAM;
        json_array_append_new(j_result, json_string("password must be a string"));
      }
      if (json_object_get(j_user, "name") != NULL && (!json_is_string(json_object_get(j_user, "name")) || !json_string_length(json_object_get(j_user, "name")))) {
        *result = G_ERROR_PARAM;
        json_array_append_new(j_result, json_string("name must be a non empty string"));
      }
      if (json_object_get(j_user, "email") != NULL && (!json_is_string(json_object_get(j_user, "email")) || !json_string_length(json_object_get(j_user, "email")))) {
        *result = G_ERROR_PARAM;
        json_array_append_new(j_result, json_string("email must be a non empty string"));
      }
      if (json_object_get(j_user, "enabled") != NULL && !json_is_boolean(json_object_get(j_user, "enabled"))) {
        *result = G_ERROR_PARAM;
        json_array_append_new(j_result, json_string("enabled must be a boolean"));
      }
      json_object_foreach(j_user, property, j_element) {
        if (0 != o_strcmp(property, "username") && 0 != o_strcmp(property, "name") && 0 != o_strcmp(property, "email") && 0 != o_strcmp(property, "enabled") && 0 != o_strcmp(property, "password") && 0 != o_strcmp(property, "source")) {
          j_format = json_object_get(json_object_get(j_params, "data-format"), property);
          if (json_object_get(j_format, "multiple") == json_true()) {
            if (!json_is_array(j_element)) {
              *result = G_ERROR_PARAM;
              message = msprintf("%s must be an array", property);
              json_array_append_new(j_result, json_string(message));
              o_free(message);
            } else {
              json_array_foreach(j_element, index, j_value) {
                if (!json_is_string(j_value) || !json_string_length(j_value)) {
                  *result = G_ERROR_PARAM;
                  message = msprintf("%s must contain a non empty string value", property);
                  json_array_append_new(j_result, json_string(message));
                  o_free(message);
                }
              }
            }
          } else {
            if (!json_is_string(j_element) || !json_string_length(j_element)) {
              *result = G_ERROR_PARAM;
              message = msprintf("%s must contain a non empty string value", property);
              json_array_append_new(j_result, json_string(message));
              o_free(message);
            }
          }
        }
      }
    }
  } else {
    *result = G_ERROR_PARAM;
    j_result = json_string("user must be a valid JSON object");
  }
  json_decref(j_user);
  if (*result != G_OK) {
    str_result = json_dumps(j_result, JSON_COMPACT);
  }
  json_decref(j_result);
  return str_result;
}

int user_module_add(const char * str_new_user, void * cls) {
  json_t * j_params = (json_t *)cls, * j_user, * j_mod_value_free_array = NULL, * j_element;
  LDAP * ldap = connect_ldap_server(j_params);
  int ret, i, result;
  LDAPMod ** mods = NULL;
  char * new_dn;
  size_t index;
  
  if (ldap != NULL) {
    j_user = json_loads(str_new_user, JSON_DECODE_ANY, NULL);
    if (j_user != NULL) {
      mods = get_ldap_write_mod(j_params, j_user, 0, 1, (j_mod_value_free_array = json_array()));
      if (mods != NULL) {
        new_dn = msprintf("%s=%s,%s", json_string_value(json_object_get(j_params, "rdn-property")), json_string_value(json_object_get(j_user, "username")), json_string_value(json_object_get(j_params, "base-search")));
        if (new_dn != NULL) {
          if ((result = ldap_add_ext_s(ldap, new_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
            y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add ldap - Error adding new user %s in the ldap backend: %s", new_dn, ldap_err2string(result));
            ret = G_ERROR;
          } else {
            ret = G_OK;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add ldap - Error allocating resources for new_dn");
          ret = G_ERROR;
        }
        json_array_foreach(j_mod_value_free_array, index, j_element) {
          for (i=0; mods[index]->mod_values[i] != NULL; i++) {
            o_free(mods[index]->mod_values[i]);
          }
        }
        json_decref(j_mod_value_free_array);
        for (i=0; mods[i] != NULL; i++) {
          o_free(mods[i]->mod_values);
          o_free(mods[i]);
        }
        o_free(mods);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add ldap - Error get_ldap_write_mod");
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add ldap - Error parsing user into JSON");
      ret = G_ERROR;
    }
    json_decref(j_user);
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add ldap - Error connect_ldap_server");
    ret = G_ERROR;
  }
  return ret;
}

int user_module_update(const char * username, const char * str_user, void * cls) {
  json_t * j_params = (json_t *)cls, * j_user, * j_mod_value_free_array, * j_element;
  LDAP * ldap = connect_ldap_server(j_params);
  int ret, i, result;
  LDAPMod ** mods = NULL;
  char * cur_dn;
  size_t index;
  
  if (ldap != NULL) {
    j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
    if (j_user != NULL) {
      mods = get_ldap_write_mod(j_params, j_user, 0, 0, (j_mod_value_free_array = json_array()));
      if (mods != NULL) {
        cur_dn = get_user_dn_from_username(j_params, ldap, username);
        if (cur_dn != NULL) {
          if ((result = ldap_modify_ext_s(ldap, cur_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Error setting new user %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
            ret = G_ERROR;
          } else {
            ret = G_OK;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error get_user_dn_from_username");
          ret = G_ERROR;
        }
        o_free(cur_dn);
        json_array_foreach(j_mod_value_free_array, index, j_element) {
          for (i=0; mods[index]->mod_values[i] != NULL; i++) {
            o_free(mods[index]->mod_values[i]);
          }
        }
        json_decref(j_mod_value_free_array);
        for (i=0; mods[i] != NULL; i++) {
          o_free(mods[i]->mod_values);
          o_free(mods[i]);
        }
        o_free(mods);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error get_ldap_write_mod");
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error parsing user into JSON");
      ret = G_ERROR;
    }
    json_decref(j_user);
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error connect_ldap_server");
    ret = G_ERROR;
  }
  return ret;
}

int user_module_update_profile(const char * username, const char * str_user, void * cls) {
  json_t * j_params = (json_t *)cls, * j_user, * j_mod_value_free_array, * j_element;
  LDAP * ldap = connect_ldap_server(j_params);
  int ret, i, result;
  LDAPMod ** mods = NULL;
  char * cur_dn;
  size_t index;
  
  if (ldap != NULL) {
    j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
    if (j_user != NULL) {
      mods = get_ldap_write_mod(j_params, j_user, 1, 0, (j_mod_value_free_array = json_array()));
      if (mods != NULL) {
        cur_dn = get_user_dn_from_username(j_params, ldap, username);
        if (cur_dn != NULL) {
          if ((result = ldap_modify_ext_s(ldap, cur_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Error setting new user %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
            ret = G_ERROR;
          } else {
            ret = G_OK;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error get_user_dn_from_username");
          ret = G_ERROR;
        }
        o_free(cur_dn);
        json_array_foreach(j_mod_value_free_array, index, j_element) {
          for (i=0; mods[index]->mod_values[i] != NULL; i++) {
            o_free(mods[index]->mod_values[i]);
          }
        }
        for (i=0; mods[i] != NULL; i++) {
          o_free(mods[i]->mod_values);
          o_free(mods[i]);
        }
        o_free(mods);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error get_ldap_write_mod");
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error parsing user into JSON");
      ret = G_ERROR;
    }
    json_decref(j_user);
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error connect_ldap_server");
    ret = G_ERROR;
  }
  return ret;
}

int user_module_delete(const char * username, void * cls) {
  json_t * j_params = (json_t *)cls;
  LDAP * ldap = connect_ldap_server(j_params);
  int ret, result;
  char * cur_dn;
  
  if (ldap != NULL) {
    cur_dn = get_user_dn_from_username(j_params, ldap, username);
    if (cur_dn != NULL) {
      if ((result = ldap_delete_ext_s(ldap, cur_dn, NULL, NULL)) != LDAP_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "Error setting new user %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
        ret = G_ERROR;
      } else {
        ret = G_OK;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error get_user_dn_from_username");
      ret = G_ERROR;
    }
    o_free(cur_dn);
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error connect_ldap_server");
    ret = G_ERROR;
  }
  return ret;
}

int user_module_check_password(const char * username, const char * password, void * cls) {
  json_t * j_params = (json_t *)cls;
  LDAP * ldap = connect_ldap_server(j_params);
  LDAPMessage * entry, * answer;
  int ldap_result, result_login, result;
  char * user_dn = NULL;
  
  int  scope = LDAP_SCOPE_ONELEVEL;
  char * filter = NULL;
  char * attrs[] = {"memberOf", NULL, NULL};
  int attrsonly = 0;
  char * ldap_mech = LDAP_SASL_SIMPLE;
  struct berval cred;
  struct berval *servcred;

  if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_SUBTREE;
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_CHILDREN;
  }
  if (ldap != NULL) {
    // Connection successful, doing ldap search
    filter = msprintf("(&(%s)(%s=%s))", json_string_value(json_object_get(j_params, "filter")), json_string_value(json_object_get(j_params, "username-property")), username);
    if ((ldap_result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_check_password ldap - Error ldap search, base search: %s, filter: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(ldap_result));
      result = G_ERROR;
    } else {
      if (ldap_count_entries(ldap, answer) > 0) {
        // Testing the first result to username with the given password
        entry = ldap_first_entry(ldap, answer);
        user_dn = ldap_get_dn(ldap, entry);
        cred.bv_val = (char *)password;
        cred.bv_len = strlen(password);
        result_login = ldap_sasl_bind_s(ldap, user_dn, ldap_mech, &cred, NULL, NULL, &servcred);
        ldap_memfree(user_dn);
        if (result_login == LDAP_SUCCESS) {
          result = G_OK;
        } else {
          result = G_ERROR_UNAUTHORIZED;
        }
      } else {
        result = G_ERROR_NOT_FOUND;
      }
    }
    
    o_free(filter);
    ldap_msgfree(answer);
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_check_password ldap - Error connect_ldap_server");
    result = G_ERROR;
  }
  return result;
}

int user_module_update_password(const char * username, const char * new_password, void * cls) {
  json_t * j_params = (json_t *)cls;
  LDAP * ldap = connect_ldap_server(j_params);
  int ret, result;
  LDAPMod * mods[2] = {NULL, NULL};
  char * cur_dn;
  
  if (ldap != NULL) {
    mods[0] = o_malloc(sizeof(LDAPMod));
    if (mods[0] != NULL) {
      mods[0]->mod_values = o_malloc(2 * sizeof(char *));
      mods[0]->mod_op     = LDAP_MOD_REPLACE;
      mods[0]->mod_type   = (char *)json_string_value(json_object_get(j_params, "password-property"));
      mods[0]->mod_values[0] = generate_hash(get_digest_algorithm(j_params), new_password);
      cur_dn = get_user_dn_from_username(j_params, ldap, username);
      if (cur_dn != NULL) {
        if ((result = ldap_modify_ext_s(ldap, cur_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update_password ldap - Error setting new user %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
          ret = G_ERROR;
        } else {
          ret = G_OK;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update_password ldap - Error get_user_dn_from_username");
        ret = G_ERROR;
      }
      o_free(cur_dn);
      o_free(mods[0]->mod_values[0]);
      o_free(mods[0]->mod_values);
      o_free(mods[0]);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update_password ldap - Error allocating resources for mods");
      ret = G_ERROR;
    }
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update_password ldap - Error connect_ldap_server");
    ret = G_ERROR;
  }
  return ret;
}

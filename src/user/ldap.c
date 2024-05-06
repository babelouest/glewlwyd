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
 * Copyright 2016-2020 Nicolas Mora <mail@babelouest.org>
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
#include "glewlwyd-common.h"

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
    len = o_strlen(input);
    for (i=0; i < len && to_return != NULL; i++) {
      unsigned char c = (unsigned char)input[i];
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

static json_t * is_user_ldap_parameters_valid(json_t * j_params, int readonly) {
  json_t * j_return, * j_error = json_array(), * j_element = NULL, * j_element_p = NULL;
  size_t index = 0;
  const char * field;

  if (j_error != NULL) {
    if (!json_is_object(j_params)) {
      json_array_append_new(j_error, json_string("parameters must be a JSON object"));
    } else {
      if (json_object_get(j_params, "uri") == NULL || !json_is_string(json_object_get(j_params, "uri")) || json_string_null_or_empty(json_object_get(j_params, "uri"))) {
        json_array_append_new(j_error, json_string("uri is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "bind-dn") == NULL || !json_is_string(json_object_get(j_params, "bind-dn")) || json_string_null_or_empty(json_object_get(j_params, "bind-dn"))) {
        json_array_append_new(j_error, json_string("bind-dn is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "bind-password") == NULL || !json_is_string(json_object_get(j_params, "bind-password")) || json_string_null_or_empty(json_object_get(j_params, "bind-password"))) {
        json_array_append_new(j_error, json_string("bind-password is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "search-scope") != NULL && !json_is_string(json_object_get(j_params, "search-scope"))) {
        json_array_append_new(j_error, json_string("search-scope is optional and must be a string"));
      } else if (json_object_get(j_params, "search-scope") == NULL) {
        json_object_set_new(j_params, "search-scope", json_string("one"));
      } else if (0 != o_strcmp("one", json_string_value(json_object_get(j_params, "search-scope"))) && 0 != o_strcmp("subtree", json_string_value(json_object_get(j_params, "search-scope"))) && 0 != o_strcmp("children", json_string_value(json_object_get(j_params, "search-scope")))) {
        json_array_append_new(j_error, json_string("search-scope must have one of the following values: 'one', 'subtree', 'children'"));
      }
      if (json_object_get(j_params, "page-size") != NULL && (!json_is_integer(json_object_get(j_params, "page-size")) || json_integer_value(json_object_get(j_params, "page-size")) <= 0)) {
        json_array_append_new(j_error, json_string("page-size is optional and must be a positive integer"));
      } else if (json_object_get(j_params, "page-size") == NULL) {
        json_object_set_new(j_params, "page-size", json_integer(LDAP_DEFAULT_PAGE_SIZE));
      }
      if (json_object_get(j_params, "base-search") == NULL || !json_is_string(json_object_get(j_params, "base-search")) || json_string_null_or_empty(json_object_get(j_params, "base-search"))) {
        json_array_append_new(j_error, json_string("base-search is mandatory and must be a string"));
      }
      if (json_object_get(j_params, "filter") == NULL || !json_is_string(json_object_get(j_params, "filter")) || json_string_null_or_empty(json_object_get(j_params, "filter"))) {
        json_array_append_new(j_error, json_string("filter is mandatory and must be a string"));
      }
      if (readonly) {
        if (json_object_get(j_params, "username-property") == NULL || json_string_null_or_empty(json_object_get(j_params, "username-property"))) {
          json_array_append_new(j_error, json_string("username-property is mandatory and must be a non empty string"));
        }
      } else {
        if (json_object_get(j_params, "username-property") == NULL || (!json_is_string(json_object_get(j_params, "username-property")) && !json_is_array(json_object_get(j_params, "username-property")))) {
          json_array_append_new(j_error, json_string("username-property is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_string(json_object_get(j_params, "username-property")) && json_string_null_or_empty(json_object_get(j_params, "username-property"))) {
          json_array_append_new(j_error, json_string("username-property is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_array(json_object_get(j_params, "username-property"))) {
          json_array_foreach(json_object_get(j_params, "username-property"), index, j_element) {
            if (json_string_null_or_empty(j_element)) {
              json_array_append_new(j_error, json_string("username-property is mandatory and must be a non empty string or an array of non empty strings"));
            }
          }
        }
      }
      if (readonly) {
        if (json_string_null_or_empty(json_object_get(j_params, "scope-property"))) {
          json_array_append_new(j_error, json_string("scope-property is mandatory and must be a non empty string"));
        }
      } else {
        if (json_object_get(j_params, "scope-property") == NULL || (!json_is_string(json_object_get(j_params, "scope-property")) && !json_is_array(json_object_get(j_params, "scope-property")))) {
          json_array_append_new(j_error, json_string("scope-property is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_string(json_object_get(j_params, "scope-property")) && json_string_null_or_empty(json_object_get(j_params, "scope-property"))) {
          json_array_append_new(j_error, json_string("scope-property is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_array(json_object_get(j_params, "scope-property"))) {
          json_array_foreach(json_object_get(j_params, "scope-property"), index, j_element) {
            if (json_string_null_or_empty(j_element)) {
              json_array_append_new(j_error, json_string("scope-property is mandatory and must be a non empty string or an array of non empty strings"));
            }
          }
        }
      }
      if (json_object_get(j_params, "scope-match") != NULL && !json_is_array(json_object_get(j_params, "scope-match"))) {
        json_array_append_new(j_error, json_string("scope-match is optional and must be a JSON array"));
      } else if (json_object_get(j_params, "scope-match") != NULL) {
        json_array_foreach(json_object_get(j_params, "scope-match"), index, j_element) {
          if (!json_is_string(json_object_get(j_element, "ldap-value"))) {
            json_array_append_new(j_error, json_string("ldap-value is mandatory and must be a string"));
          }
          if (!json_is_string(json_object_get(j_element, "scope-value"))) {
            json_array_append_new(j_error, json_string("scope-value is mandatory and must be a string"));
          }
          if (!json_is_string(json_object_get(j_element, "match")) || (0 != o_strcmp("equals", json_string_value(json_object_get(j_element, "match"))) && 0 != o_strcmp("contains", json_string_value(json_object_get(j_element, "match"))) && 0 != o_strcmp("startswith", json_string_value(json_object_get(j_element, "match"))) && 0 != o_strcmp("endswith", json_string_value(json_object_get(j_element, "match"))))) {
            json_array_append_new(j_error, json_string("match is mandatory and must have one of the following values: 'equals', 'contains', 'startswith', 'endswith'"));
          }
        }
      }
      if (readonly) {
        if (json_object_get(j_params, "name-property") == NULL ||  json_string_null_or_empty(json_object_get(j_params, "name-property"))) {
          json_array_append_new(j_error, json_string("name-property is mandatory and must be a non empty string"));
        }
      } else {
        if (json_object_get(j_params, "name-property") == NULL || (!json_is_string(json_object_get(j_params, "name-property")) && !json_is_array(json_object_get(j_params, "name-property")))) {
          json_array_append_new(j_error, json_string("name-property is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_string(json_object_get(j_params, "name-property")) && json_string_null_or_empty(json_object_get(j_params, "name-property"))) {
          json_array_append_new(j_error, json_string("name-property is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_array(json_object_get(j_params, "name-property"))) {
          json_array_foreach(json_object_get(j_params, "name-property"), index, j_element) {
            if (json_string_null_or_empty(j_element)) {
              json_array_append_new(j_error, json_string("name-property is mandatory and must be a non empty string or an array of non empty strings"));
            }
          }
        }
      }
      if (readonly) {
        if (json_object_get(j_params, "email-property") == NULL || !json_is_string(json_object_get(j_params, "email-property"))) {
          json_array_append_new(j_error, json_string("email-property is optional and must be a string"));
        }
      } else {
        if (json_object_get(j_params, "email-property") != NULL && !json_is_string(json_object_get(j_params, "email-property")) && !json_is_array(json_object_get(j_params, "email-property"))) {
          json_array_append_new(j_error, json_string("email-property is optional and must be a string or an array of strings"));
        } else if (json_is_array(json_object_get(j_params, "email-property"))) {
          json_array_foreach(json_object_get(j_params, "email-property"), index, j_element) {
            if (!json_is_string(j_element)) {
              json_array_append_new(j_error, json_string("email-property is optional and must be a string or an array of strings"));
            }
          }
        }
      }
      if (!readonly) {
        if (json_object_get(j_params, "rdn-property") == NULL || json_string_null_or_empty(json_object_get(j_params, "rdn-property"))) {
          json_array_append_new(j_error, json_string("rdn-property is mandatory and must be a non empty string"));
        }
        if (json_object_get(j_params, "password-property") == NULL || json_string_null_or_empty(json_object_get(j_params, "password-property"))) {
          json_array_append_new(j_error, json_string("password-property is mandatory and must be a non empty string"));
        }
        if (json_object_get(j_params, "password-algorithm") == NULL ||
          (0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "SHA") &&
           //0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "SHA256") &&
           //0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "SHA384") &&
           //0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "SHA512") &&
           0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "SSHA") &&
           //0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "SSHA256") &&
           //0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "SSHA384") &&
           //0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "SSHA512") &&
           0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "SMD5") &&
           0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "MD5") &&
           //0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "PKCS5S2") &&
           0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "CRYPT") &&
           0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "CRYPT_MD5") &&
           0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "CRYPT_SHA256") &&
           0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "CRYPT_SHA512") &&
           0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "PLAIN"))) {
          //json_array_append_new(j_error, json_string("password-property is mandatory and must have one of the following values: 'SHA', 'SHA256', 'SHA284', 'SHA512', 'SSHA', "
          //                                           "'SSHA256', 'SSHA384', 'SSHA512', 'SMD5', 'MD5', 'PKCS5S2', 'PLAIN'"));
          json_array_append_new(j_error, json_string("password-property is mandatory and must have one of the following values: 'SHA', 'SSHA', 'SMD5', 'MD5', 'CRYPT', 'CRYPT_MD5', 'CRYPT_SHA256', 'CRYPT_SHA512', 'PLAIN'"));
        }
        if (json_object_get(j_params, "object-class") == NULL || (!json_is_string(json_object_get(j_params, "object-class")) && !json_is_array(json_object_get(j_params, "object-class")))) {
          json_array_append_new(j_error, json_string("object-class is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_string(json_object_get(j_params, "object-class")) && json_string_null_or_empty(json_object_get(j_params, "object-class"))) {
          json_array_append_new(j_error, json_string("object-class is mandatory and must be a non empty string or an array of non empty strings"));
        } else {
          json_array_foreach(json_object_get(j_params, "object-class"), index, j_element) {
            if (json_string_null_or_empty(j_element)) {
              json_array_append_new(j_error, json_string("object-class is mandatory and must be a non empty string or an array of non empty strings"));
            }
          }
        }
      }
      if (json_object_get(j_params, "data-format") != NULL) {
        if (!json_is_object(json_object_get(j_params, "data-format"))) {
          json_array_append_new(j_error, json_string("data-format is optional and must be a JSON object"));
        } else {
          json_object_foreach(json_object_get(j_params, "data-format"), field, j_element) {
            if (0 == o_strcmp(field, "username") || 0 == o_strcmp(field, "name") || 0 == o_strcmp(field, "email") || 0 == o_strcmp(field, "enabled") || 0 == o_strcmp(field, "password") || 0 == o_strcmp(field, "scope")) {
              json_array_append_new(j_error, json_string("data-format can't have settings for properties 'username', 'name', 'email', 'enabled', 'scope' or 'password'"));
            } else {
              if (readonly) {
                if (json_object_get(j_element, "property") == NULL || json_string_null_or_empty(json_object_get(j_element, "property"))) {
                  json_array_append_new(j_error, json_string("property is mandatory and must be a non empty string"));
                }
              } else {
                if (json_object_get(j_element, "property") == NULL || ((!json_is_string(json_object_get(j_element, "property")) || json_string_null_or_empty(json_object_get(j_element, "property"))) && !json_is_array(json_object_get(j_element, "property")))) {
                  json_array_append_new(j_error, json_string("property is mandatory and must be a non empty string or an array of non empty string"));
                } else if (json_is_array(json_object_get(j_element, "property"))) {
                  json_array_foreach(json_object_get(j_element, "property"), index, j_element_p) {
                    if (json_string_null_or_empty(j_element_p)) {
                      json_array_append_new(j_error, json_string("property is mandatory and must be a non empty string or an array of non empty string"));
                    }
                  }
                }
              }
              if (json_object_get(j_element, "multiple") != NULL && !json_is_boolean(json_object_get(j_element, "multiple"))) {
                json_array_append_new(j_error, json_string("multiple is optional and must be a boolean (default: false)"));
              }
              if (json_object_get(j_element, "convert") != NULL && 0 != o_strcmp("base64", json_string_value(json_object_get(j_element, "convert")))) {
                json_array_append_new(j_error, json_string("convert is optional and must have one of the following values: 'base64'"));
              }
              if (json_object_get(j_element, "read") != NULL && !json_is_boolean(json_object_get(j_element, "read"))) {
                json_array_append_new(j_error, json_string("read is optional and must be a boolean (default: true)"));
              }
              if (!readonly && json_object_get(j_element, "write") != NULL && !json_is_boolean(json_object_get(j_element, "write"))) {
                json_array_append_new(j_error, json_string("write is optional and must be a boolean (default: true)"));
              }
              if (json_object_get(j_element, "profile-read") != NULL && !json_is_boolean(json_object_get(j_element, "profile-read"))) {
                json_array_append_new(j_error, json_string("profile-read is optional and must be a boolean (default: false)"));
              }
              if (!readonly && json_object_get(j_element, "profile-write") != NULL && !json_is_boolean(json_object_get(j_element, "profile-write"))) {
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
    y_log_message(Y_LOG_LEVEL_ERROR, "connect_ldap_server ldap - Error initializing ldap");
    ldap = NULL;
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "connect_ldap_server ldap - Error setting ldap protocol version");
    ldap_unbind_ext(ldap, NULL, NULL);
    ldap = NULL;
  } else if ((result = ldap_sasl_bind_s(ldap, json_string_value(json_object_get(j_params, "bind-dn")), ldap_mech, &cred, NULL, NULL, &servcred)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "connect_ldap_server - Error binding to ldap server mode %s: %s", ldap_mech, ldap_err2string(result));
    ldap_unbind_ext(ldap, NULL, NULL);
    ldap = NULL;
  }

  return ldap;
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

static char * get_ldap_filter_pattern(json_t * j_params, const char * pattern) {
  char * pattern_escaped, * filter, * name_filter, * email_filter;

  if (!o_strnullempty(pattern)) {
    pattern_escaped = escape_ldap(pattern);
    if (json_object_get(j_params, "name-property") != NULL) {
      name_filter = msprintf("(%s=*%s*)", get_read_property(j_params, "name-property"), pattern_escaped);
    } else {
      name_filter = o_strdup("");
    }
    if (json_object_get(j_params, "email-property") != NULL) {
      email_filter = msprintf("(%s=*%s*)", get_read_property(j_params, "email-property"), pattern_escaped);
    } else {
      email_filter = o_strdup("");
    }
    filter = msprintf("(&(%s)(|(%s=*%s*)%s%s))",
                      json_string_value(json_object_get(j_params, "filter")),
                      get_read_property(j_params, "username-property"),
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

static char ** get_ldap_read_attributes(json_t * j_params, int profile, json_t * j_properties) {
  char ** attrs = NULL;
  size_t i, nb_attrs = 2; // Username, Scope
  json_t * j_element = NULL;
  const char * field = NULL;

  if (j_properties != NULL && json_is_object(j_properties) && !json_object_size(j_properties)) {
    nb_attrs += (json_object_get(j_params, "name-property") != NULL);
    nb_attrs += (json_object_get(j_params, "email-property") != NULL);
    nb_attrs += (json_object_get(j_params, "multiple_passwords") == json_true() && json_object_get(j_params, "password-property") != NULL);
    if (json_object_get(j_params, "data-format") != NULL) {
      json_object_foreach(json_object_get(j_params, "data-format"), field, j_element) {
        nb_attrs += ((!profile && json_object_get(j_element, "read") != json_false()) || (profile && json_object_get(j_element, "profile-read") == json_true()));
      }
    }
    attrs = o_malloc((nb_attrs + 1) * sizeof(char *));
    if (attrs != NULL) {
      attrs[nb_attrs] = NULL;
      attrs[0] = (char*)get_read_property(j_params, "username-property");
      json_object_set_new(j_properties, "username", json_string(get_read_property(j_params, "username-property")));
      attrs[1] = (char*)get_read_property(j_params, "scope-property");
      json_object_set_new(j_properties, "scope", json_string(get_read_property(j_params, "scope-property")));
      i = 2;
      if (json_object_get(j_params, "name-property") != NULL) {
        attrs[i++] = (char*)get_read_property(j_params, "name-property");
        json_object_set_new(j_properties, "name", json_string(get_read_property(j_params, "name-property")));
      }
      if (json_object_get(j_params, "email-property") != NULL) {
        attrs[i++] = (char*)get_read_property(j_params, "email-property");
        json_object_set_new(j_properties, "email", json_string(get_read_property(j_params, "email-property")));
      }
      if (json_object_get(j_params, "multiple_passwords") == json_true() && json_object_get(j_params, "password-property") != NULL) {
        attrs[i++] = (char*)get_read_property(j_params, "password-property");
      }
      if (json_object_get(j_params, "data-format") != NULL) {
        json_object_foreach(json_object_get(j_params, "data-format"), field, j_element) {
          if ((!profile && json_object_get(j_element, "read") != json_false()) || (profile && json_object_get(j_element, "profile-read") == json_true())) {
            attrs[i++] = (char*)get_read_property(j_element, "property");
            json_object_set_new(j_properties, field, json_string(get_read_property(j_element, "property")));
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

static size_t count_properties(json_t * j_params, const char * property) {
  if (json_object_get(j_params, property) != NULL) {
    if (json_is_string(json_object_get(j_params, property))) {
      return 1;
    } else {
      return json_array_size(json_object_get(j_params, property));
    }
  } else {
    return 0;
  }
}

static digest_algorithm get_digest_algorithm(json_t * j_params) {
  if (0 == o_strcmp("SHA", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_SHA1;
  } else if (0 == o_strcmp("SSHA", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_SSHA1;
  } else if (0 == o_strcmp("SHA224", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_SHA224;
  } else if (0 == o_strcmp("SSHA224", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_SSHA224;
  } else if (0 == o_strcmp("SHA256", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_SHA256;
  } else if (0 == o_strcmp("SSHA256", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_SSHA256;
  } else if (0 == o_strcmp("SHA384", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_SHA384;
  } else if (0 == o_strcmp("SSHA384", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_SSHA384;
  } else if (0 == o_strcmp("SHA512", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_SHA512;
  } else if (0 == o_strcmp("SSHA512", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_SSHA512;
  } else if (0 == o_strcmp("PBKDF2", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_PBKDF2_SHA256;
  } else if (0 == o_strcmp("MD5", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_MD5;
  } else if (0 == o_strcmp("SMD5", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_SMD5;
  } else if (0 == o_strcmp("CRYPT", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_CRYPT;
  } else if (0 == o_strcmp("CRYPT_MD5", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_CRYPT_MD5;
  } else if (0 == o_strcmp("CRYPT_SHA256", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_CRYPT_SHA256;
  } else if (0 == o_strcmp("CRYPT_SHA512", json_string_value(json_object_get(j_params, "password-algorithm")))) {
    return digest_CRYPT_SHA512;
  } else {
    return digest_PLAIN;
  }
}

static int set_update_password_mod(json_t * j_params, LDAP * ldap, const char * username, const char ** new_passwords, size_t new_passwords_len, LDAPMod * mod, int add) {
  LDAPMessage * entry, * answer;
  int ldap_result, nb_values, ret = G_OK, i;
  struct berval ** result_values = NULL;
  size_t counter;
  char * escaped = escape_ldap(username);

  int  scope = LDAP_SCOPE_ONELEVEL;
  char * filter = NULL;
  char * attrs[2] = {(char *)json_string_value(json_object_get(j_params, "password-property")), NULL};
  int attrsonly = 0;

  if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_SUBTREE;
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_CHILDREN;
  }
  if (!add) {
    // Connection successful, doing ldap search
    filter = msprintf("(&(%s)(%s=%s))", json_string_value(json_object_get(j_params, "filter")), get_read_property(j_params, "username-property"), escaped);
    if ((ldap_result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "set_update_password_mod - Error ldap search, base search: %s, filter: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(ldap_result));
      ret = G_ERROR;
    } else {
      // Looping in results, staring at offset, until the end of the list
      if (ldap_count_entries(ldap, answer) == 1) {
        entry = ldap_first_entry(ldap, answer);
        result_values = ldap_get_values_len(ldap, entry, json_string_value(json_object_get(j_params, "password-property")));
        nb_values = ldap_count_values_len(result_values);
        if ((mod->mod_values = o_malloc((new_passwords_len+1)*sizeof(char *))) != NULL) {
          for (i=0; i<(int)new_passwords_len+1; i++) {
            mod->mod_values[i] = NULL;
          }
          counter = 0;
          for (i=0; i<(int)new_passwords_len; i++) {
            if (!o_strnullempty(new_passwords[i])) {
              mod->mod_values[counter] = generate_hash(get_digest_algorithm(j_params), new_passwords[i]);
              counter++;
            } else if (new_passwords[i] != NULL && i < nb_values) {
              mod->mod_values[counter] = o_strndup(result_values[i]->bv_val, result_values[i]->bv_len);
              counter++;
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "set_update_password_mod - Error allocating resources for mod->mod_values");
          ret = G_ERROR_MEMORY;
        }
        ldap_value_free_len(result_values);
      }
    }

    o_free(filter);
    ldap_msgfree(answer);
  } else {
    if ((mod->mod_values = o_malloc((new_passwords_len+1)*sizeof(char *))) != NULL) {
      for (i=0; i<(int)new_passwords_len+1; i++) {
        mod->mod_values[i] = NULL;
      }
      counter = 0;
      for (i=0; i<(int)new_passwords_len; i++) {
        if (!o_strnullempty(new_passwords[i])) {
          mod->mod_values[counter] = generate_hash(get_digest_algorithm(j_params), new_passwords[i]);
          counter++;
        } else {
          mod->mod_values[counter] = o_strdup("");
          counter++;
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "set_update_password_mod - Error allocating resources for mod->mod_values");
      ret = G_ERROR_MEMORY;
    }
  }
  o_free(escaped);
  return ret;
}

static LDAPMod ** get_ldap_write_mod(json_t * j_params, LDAP * ldap, const char * username, json_t * j_user, int profile, int add) {
  LDAPMod ** mods = NULL;
  size_t nb_attr = 0;
  json_t * j_format, * j_property = NULL, * j_property_value, * j_scope;
  const char * field = NULL;
  size_t index = 0, index_scope = 0, i, j;
  int has_error = 0, mod_op = add?LDAP_MOD_ADD:LDAP_MOD_REPLACE;
  unsigned char * value_dec = NULL;
  size_t value_dec_len = 0;
  const char ** passwords = NULL;
  struct _o_datum dat = {0, NULL};

  // Count attrs
  if (add) {
    nb_attr += count_properties(j_params, "username-property") + 1;
  }
  if (!add || !json_string_null_or_empty(json_object_get(j_user, "name"))) {
    nb_attr += count_properties(j_params, "name-property");
  }
  if (!profile) {
    if (!add || json_array_size(json_object_get(j_user, "scope"))) {
      nb_attr += count_properties(j_params, "scope-property");
    }
    if (!add || !json_string_null_or_empty(json_object_get(j_user, "email"))) {
      nb_attr += count_properties(j_params, "email-property");
    }
    if (!add || !json_string_null_or_empty(json_object_get(j_user, "password")) || json_array_size(json_object_get(j_user, "password"))) {
      nb_attr++;
    }
  }
  json_object_foreach(j_user, field, j_property) {
    if (0 != o_strcmp(field, "username") &&
        0 != o_strcmp(field, "name") &&
        0 != o_strcmp(field, "password") &&
        0 != o_strcmp(field, "scope") &&
        0 != o_strcmp(field, "email") &&
        0 != o_strcmp(field, "enabled")) {
      if (!add || !json_string_null_or_empty(j_property) || json_array_size(j_property)) {
        if ((j_format = json_object_get(json_object_get(j_params, "data-format"), field)) != NULL) {
          if (!profile || (profile && json_object_get(j_format, "profile-write") == json_true())) {
            nb_attr += count_properties(j_format, "property");
          }
        }
      }
    }
  }
  mods = o_malloc((nb_attr + 1)*sizeof(LDAPMod *));
  for (i=0; i<=nb_attr; i++) {
    mods[i] = NULL;
  }

  // Fill mods
  i=0;
  if (mods != NULL) {
    if (add) {
      mods[i] = o_malloc(sizeof(LDAPMod));
      if (mods[i] != NULL) {
        mods[i]->mod_values = o_malloc((json_array_size(json_object_get(j_params, "object-class")) + 1) * sizeof(char *));
        if (mods[i]->mod_values != NULL) {
          mods[i]->mod_op = mod_op;
          mods[i]->mod_type = "objectClass";
          json_array_foreach(json_object_get(j_params, "object-class"), index, j_property_value) {
            mods[i]->mod_values[index] = o_strdup(json_string_value(j_property_value));
          }
          mods[i]->mod_values[json_array_size(json_object_get(j_params, "object-class"))] = NULL;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (objectClass)", i);
          has_error = 1;
        }
        i++;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (objectClass)", i);
        has_error = 1;
      }
      
      if (json_is_array(json_object_get(j_params, "username-property"))) {
        json_array_foreach(json_object_get(j_params, "username-property"), index, j_property) {
          mods[i] = o_malloc(sizeof(LDAPMod));
          if (mods[i] != NULL) {
            mods[i]->mod_values = o_malloc(2 * sizeof(char *));
            if (mods[i]->mod_values != NULL) {
              mods[i]->mod_op = mod_op;
              mods[i]->mod_type = (char *)json_string_value(j_property);
              mods[i]->mod_values[0] = o_strdup(json_string_value(json_object_get(j_user, "username")));
              mods[i]->mod_values[1] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (username)", i);
              has_error = 1;
            }
            i++;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (username)", i);
            has_error = 1;
          }
        }
      } else {
        mods[i] = o_malloc(sizeof(LDAPMod));
        if (mods[i] != NULL) {
          mods[i]->mod_values = o_malloc(2 * sizeof(char *));
          if (mods[i]->mod_values != NULL) {
            mods[i]->mod_op = mod_op;
            mods[i]->mod_type = (char *)get_read_property(j_params, "username-property");
            mods[i]->mod_values[0] = o_strdup(json_string_value(json_object_get(j_user, "username")));
            mods[i]->mod_values[1] = NULL;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (username)", i);
            has_error = 1;
          }
          i++;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (username)", i);
          has_error = 1;
        }
      }
    }

    if (!json_string_null_or_empty(json_object_get(j_user, "name"))) {
      if (json_is_array(json_object_get(j_params, "name-property"))) {
        json_array_foreach(json_object_get(j_params, "name-property"), index, j_property) {
          mods[i] = o_malloc(sizeof(LDAPMod));
          if (mods[i] != NULL) {
            mods[i]->mod_values = o_malloc(2 * sizeof(char *));
            if (mods[i]->mod_values != NULL) {
              mods[i]->mod_op = mod_op;
              mods[i]->mod_type = (char *)json_string_value(j_property);
              mods[i]->mod_values[0] = o_strdup(json_string_value(json_object_get(j_user, "name")));
              mods[i]->mod_values[1] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (name)", i);
              has_error = 1;
            }
            i++;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (name)", i);
            has_error = 1;
          }
        }
      } else {
        mods[i] = o_malloc(sizeof(LDAPMod));
        if (mods[i] != NULL) {
          mods[i]->mod_values = o_malloc(2 * sizeof(char *));
          if (mods[i]->mod_values != NULL) {
            mods[i]->mod_op = mod_op;
            mods[i]->mod_type = (char *)json_string_value(json_object_get(j_params, "name-property"));
            mods[i]->mod_values[0] = o_strdup(json_string_value(json_object_get(j_user, "name")));
            mods[i]->mod_values[1] = NULL;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (name)", i);
            has_error = 1;
          }
          i++;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (name)", i);
          has_error = 1;
        }
      }
    } else if (!add) {
      if (json_is_array(json_object_get(j_params, "name-property"))) {
        json_array_foreach(json_object_get(j_params, "name-property"), index, j_property) {
          mods[i] = o_malloc(sizeof(LDAPMod));
          if (mods[i] != NULL) {
            if ((mods[i]->mod_values = o_malloc(sizeof(char *))) != NULL) {
              mods[i]->mod_op = mod_op;
              mods[i]->mod_type = o_strdup(json_string_value(j_property));
              mods[i]->mod_values[0] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (name)", i);
              has_error = 1;
            }
            i++;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (name)", i);
            has_error = 1;
          }
        }
      } else {
        mods[i] = o_malloc(sizeof(LDAPMod));
        if (mods[i] != NULL) {
          if ((mods[i]->mod_values = o_malloc(sizeof(char *))) != NULL) {
            mods[i]->mod_op = mod_op;
            mods[i]->mod_type = o_strdup(json_string_value(json_object_get(j_params, "name-property")));
            mods[i]->mod_values[0] = NULL;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (name)", i);
            has_error = 1;
          }
          i++;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (name)", i);
          has_error = 1;
        }
      }
    }
    if (!profile) {
      if (!json_string_null_or_empty(json_object_get(j_user, "email"))) {
        if (json_is_array(json_object_get(j_params, "email-property"))) {
          json_array_foreach(json_object_get(j_params, "email-property"), index, j_property) {
            mods[i] = o_malloc(sizeof(LDAPMod));
            if (mods[i] != NULL) {
              mods[i]->mod_values = o_malloc(2 * sizeof(char *));
              if (mods[i]->mod_values != NULL) {
                mods[i]->mod_op = mod_op;
                mods[i]->mod_type = (char *)json_string_value(j_property);
                mods[i]->mod_values[0] = o_strdup(json_string_value(json_object_get(j_user, "email")));
                mods[i]->mod_values[1] = NULL;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (email)", i);
                has_error = 1;
              }
              i++;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (email)", i);
              has_error = 1;
            }
          }
        } else {
          mods[i] = o_malloc(sizeof(LDAPMod));
          if (mods[i] != NULL) {
            mods[i]->mod_values = o_malloc(2 * sizeof(char *));
            if (mods[i]->mod_values != NULL) {
              mods[i]->mod_op = mod_op;
              mods[i]->mod_type = (char *)json_string_value(json_object_get(j_params, "email-property"));
              mods[i]->mod_values[0] = o_strdup(json_string_value(json_object_get(j_user, "email")));
              mods[i]->mod_values[1] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (email)", i);
              has_error = 1;
            }
            i++;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (email)", i);
            has_error = 1;
          }
        }
      } else if (!add) {
        if (json_is_array(json_object_get(j_params, "email-property"))) {
          json_array_foreach(json_object_get(j_params, "email-property"), index, j_property) {
            mods[i] = o_malloc(sizeof(LDAPMod));
            if (mods[i] != NULL) {
              if ((mods[i]->mod_values = o_malloc(sizeof(char *))) != NULL) {
                mods[i]->mod_op = mod_op;
                mods[i]->mod_type = (char *)json_string_value(j_property);
                mods[i]->mod_values[0] = NULL;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (email)", i);
                has_error = 1;
              }
              i++;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (email)", i);
              has_error = 1;
            }
          }
        } else {
          mods[i] = o_malloc(sizeof(LDAPMod));
          if (mods[i] != NULL) {
            if ((mods[i]->mod_values = o_malloc(sizeof(char *))) != NULL) {
              mods[i]->mod_op = mod_op;
              mods[i]->mod_type = (char *)json_string_value(json_object_get(j_params, "email-property"));
              mods[i]->mod_values[0] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (email)", i);
              has_error = 1;
            }
            i++;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (email)", i);
            has_error = 1;
          }
        }
      }
      if (json_array_size(json_object_get(j_user, "scope"))) {
        if (json_is_array(json_object_get(j_params, "scope-property"))) {
          json_array_foreach(json_object_get(j_params, "scope-property"), index, j_property) {
            mods[i] = o_malloc(sizeof(LDAPMod));
            if (mods[i] != NULL) {
              mods[i]->mod_values = o_malloc((json_array_size(json_object_get(j_user, "scope")) + 1) * sizeof(char *));
              if (mods[i]->mod_values != NULL) {
                mods[i]->mod_op = mod_op;
                mods[i]->mod_type = (char *)json_string_value(j_property);
                json_array_foreach(json_object_get(j_user, "scope"), index_scope, j_scope) {
                  mods[i]->mod_values[index_scope] = o_strdup(json_string_value(j_scope));
                }
                mods[i]->mod_values[(json_array_size(json_object_get(j_user, "scope")))] = NULL;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (scope)", i);
                has_error = 1;
              }
              i++;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (scope)", i);
              has_error = 1;
            }
          }
        } else {
          mods[i] = o_malloc(sizeof(LDAPMod));
          if (mods[i] != NULL) {
            mods[i]->mod_values = o_malloc((json_array_size(json_object_get(j_user, "scope")) + 1) * sizeof(char *));
            if (mods[i]->mod_values != NULL) {
              mods[i]->mod_op = mod_op;
              mods[i]->mod_type = (char *)json_string_value(json_object_get(j_params, "scope-property"));
              json_array_foreach(json_object_get(j_user, "scope"), index_scope, j_scope) {
                mods[i]->mod_values[index_scope] = o_strdup(json_string_value(j_scope));
              }
              mods[i]->mod_values[(json_array_size(json_object_get(j_user, "scope")))] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (scope)", i);
              has_error = 1;
            }
            i++;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (scope)", i);
            has_error = 1;
          }
        }
      } else if (!add) {
        if (json_is_array(json_object_get(j_params, "scope-property"))) {
          json_array_foreach(json_object_get(j_params, "scope-property"), index, j_property) {
            mods[i] = o_malloc(sizeof(LDAPMod));
            if (mods[i] != NULL) {
              if ((mods[i]->mod_values = o_malloc(sizeof(char *))) != NULL) {
                mods[i]->mod_op = mod_op;
                mods[i]->mod_type = (char *)json_string_value(j_property);
                mods[i]->mod_values[0] = NULL;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (scope)", i);
                has_error = 1;
              }
              i++;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (scope)", i);
              has_error = 1;
            }
          }
        } else {
          mods[i] = o_malloc(sizeof(LDAPMod));
          if (mods[i] != NULL) {
            if ((mods[i]->mod_values = o_malloc(sizeof(char *))) != NULL) {
              mods[i]->mod_op = mod_op;
              mods[i]->mod_type = (char *)json_string_value(json_object_get(j_params, "scope-property"));
              mods[i]->mod_values[0] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (scope)", i);
              has_error = 1;
            }
            i++;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (scope)", i);
            has_error = 1;
          }
        }
      }

      if (json_object_get(j_params, "multiple_passwords") == json_true()) {
        if (json_array_size(json_object_get(j_user, "password"))) {
          if ((passwords = o_malloc(json_array_size(json_object_get(j_user, "password"))*sizeof(char *))) != NULL) {
            mods[i] = o_malloc(sizeof(LDAPMod));
            if (mods[i] != NULL) {
              json_array_foreach(json_object_get(j_user, "password"), index, j_property) {
                passwords[index] = json_string_value(j_property);
              }
              if (set_update_password_mod(j_params, ldap, username, passwords, json_array_size(json_object_get(j_user, "password")), mods[i], add) == G_OK) {
                mods[i]->mod_op = mod_op;
                mods[i]->mod_type = (char *)json_string_value(json_object_get(j_params, "password-property"));
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error set_update_password_mod for mods[%zu]", i);
                has_error = 1;
              }
              i++;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (password)", i);
              has_error = 1;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (passwords)", i);
            has_error = 1;
          }
          o_free(passwords);
        }
      } else {
        if (!json_string_null_or_empty(json_object_get(j_user, "password"))) {
          mods[i] = o_malloc(sizeof(LDAPMod));
          if (mods[i] != NULL) {
            mods[i]->mod_values = o_malloc(2 * sizeof(char *));
            if (mods[i]->mod_values != NULL) {
              mods[i]->mod_op = mod_op;
              mods[i]->mod_type = (char *)json_string_value(json_object_get(j_params, "password-property"));
              mods[i]->mod_values[0] = json_string_length(json_object_get(j_user, "password"))?generate_hash(get_digest_algorithm(j_params), json_string_value(json_object_get(j_user, "password"))):NULL;
              mods[i]->mod_values[1] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (password)", i);
              has_error = 1;
            }
            i++;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (password)", i);
            has_error = 1;
          }
        }
      }
    }
    json_object_foreach(j_user, field, j_property) {
      if (0 != o_strcmp(field, "username") &&
          0 != o_strcmp(field, "name") &&
          0 != o_strcmp(field, "password") &&
          0 != o_strcmp(field, "scope") &&
          0 != o_strcmp(field, "email") &&
          0 != o_strcmp(field, "enabled")) {
        if ((j_format = json_object_get(json_object_get(j_params, "data-format"), field)) != NULL) {
          if (!profile || (profile && json_object_get(j_format, "profile-write") == json_true())) {
            if (json_array_size(j_property) && json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "multiple") == json_true()) {
              mods[i] = o_malloc(sizeof(LDAPMod));
              if (mods[i] != NULL) {
                mods[i]->mod_values = o_malloc((json_array_size(j_property) + 1) * sizeof(char *));
                if (mods[i]->mod_values != NULL) {
                  mods[i]->mod_op = mod_op;
                  mods[i]->mod_type = (char *)json_string_value(json_object_get(j_format, "property"));
                  json_array_foreach(j_property, index_scope, j_property_value) {
                    if (0 == o_strcmp("base64", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert")))) {
                      if (o_base64_decode_alloc((const unsigned char *)json_string_value(j_property_value), json_string_length(j_property_value), &dat)) {
                        mods[i]->mod_values[index_scope] = o_strndup((const char *)dat.data, dat.size);
                        o_free(dat.data);
                        dat.data = NULL;
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error o_base64_decode_alloc for LDAP property '%s' (1-1)", json_string_value(j_property_value));
                        has_error = 1;
                      }
                    } else {
                      mods[i]->mod_values[index_scope] = o_strdup(json_string_value(j_property_value));
                    }
                  }
                  mods[i]->mod_values[json_array_size(j_property)] = NULL;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (%s)", i, json_string_value(json_object_get(j_format, "property")));
                  has_error = 1;
                }
                i++;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (%s)", i, json_string_value(json_object_get(j_format, "property")));
                has_error = 1;
              }
            } else if (json_string_length(j_property) && json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "multiple") != json_true()) {
              mods[i] = o_malloc(sizeof(LDAPMod));
              if (mods[i] != NULL) {
                mods[i]->mod_values = o_malloc(2 * sizeof(char *));
                if (mods[i]->mod_values != NULL) {
                  mods[i]->mod_op = mod_op;
                  mods[i]->mod_type = (char *)json_string_value(json_object_get(j_format, "property"));
                  if (0 == o_strcmp("base64", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert")))) {
                    if (o_base64_decode_alloc((const unsigned char *)json_string_value(j_property), json_string_length(j_property), &dat)) {
                      value_dec[value_dec_len] = '\0';
                      mods[i]->mod_values[0] = o_strndup((const char *)dat.data, dat.size);
                      o_free(dat.data);
                      dat.data = NULL;
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error o_base64_decode_alloc for LDAP property '%s' (2-1)", json_string_value(j_property));
                      has_error = 1;
                    }
                  } else {
                    mods[i]->mod_values[0] = o_strdup(json_string_value(j_property));
                  }
                  mods[i]->mod_values[1] = NULL;
                  i++;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (%s)", i, json_string_value(json_object_get(j_format, "property")));
                  has_error = 1;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (%s)", i, json_string_value(json_object_get(j_format, "property")));
                has_error = 1;
              }
            } else if (!add) {
              mods[i] = o_malloc(sizeof(LDAPMod));
              if (mods[i] != NULL) {
                if ((mods[i]->mod_values = o_malloc(sizeof(char *))) != NULL) {
                  mods[i]->mod_op = mod_op;
                  mods[i]->mod_type = (char *)json_string_value(json_object_get(j_format, "property"));
                  mods[i]->mod_values[0] = NULL;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu]->mod_values (%s)", i, json_string_value(json_object_get(j_format, "property")));
                  has_error = 1;
                }
                i++;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%zu] (%s)", i, json_string_value(json_object_get(j_format, "property")));
                has_error = 1;
              }
            }
          }
        }
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods");
    has_error = 1;
  }
  if (has_error) {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - mods has error, cleaning memory");
    for (i=0; mods[i]!=NULL; i++) {
      for (j=0; mods[i]->mod_values[j] != NULL; j++) {
        o_free(mods[i]->mod_values[j]);
      }
      o_free(mods[i]->mod_values);
      o_free(mods[i]);
    }
    o_free(mods);
    mods = NULL;
  }
  return mods;
}

static json_t * get_scope_from_ldap(json_t * j_params, const char * ldap_scope_value) {
  json_t * j_element = NULL;
  size_t index = 0;
  const char * value, * scope, * match;

  if (json_object_get(j_params, "scope-match") != NULL) {
    json_array_foreach(json_object_get(j_params, "scope-match"), index, j_element) {
      value = json_string_value(json_object_get(j_element, "ldap-value"));
      scope = json_string_value(json_object_get(j_element, "scope-value"));
      match = json_string_value(json_object_get(j_element, "match"));
      if ((0 == o_strcmp("equals", match) && 0 == o_strcmp(value, ldap_scope_value)) ||
          (0 == o_strcmp("contains", match) && NULL != o_strstr(ldap_scope_value, value)) ||
          (0 == o_strcmp("starts-with", match) && 0 != o_strncmp(ldap_scope_value, value, o_strlen(value))) ||
          (0 == o_strcmp("ends-with", match) && 0 != o_strcmp(ldap_scope_value + o_strlen(ldap_scope_value) - o_strlen(value), value))) {
        return json_string(scope);
      }
    }
  }
  return json_string(ldap_scope_value);
}

static json_t * get_user_from_result(json_t * j_params, json_t * j_properties_user, LDAP * ldap, LDAPMessage * entry) {
  json_t * j_user = json_object(), * j_property = NULL, * j_scope;
  const char * field = NULL;
  char * str_scope;
  struct berval ** result_values = NULL;
  int i;
  struct _o_datum dat = {0, NULL};

  if (j_user != NULL) {
    json_object_foreach(j_properties_user, field, j_property) {
      result_values = ldap_get_values_len(ldap, entry, json_string_value(j_property));
      if (ldap_count_values_len(result_values) > 0) {
        if (0 == o_strcmp(field, "scope")) {
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
        } else if (0 == o_strcmp(field, "username") || 0 == o_strcmp(field, "name") || 0 == o_strcmp(field, "email") || (json_object_get(json_object_get(j_params, "data-format"), field) != NULL &&json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "multiple") != json_true())) {
          json_object_set_new(j_user, field, json_stringn(result_values[0]->bv_val, result_values[0]->bv_len));
          if (0 == o_strcmp("base64", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert")))) {
            if (o_base64_encode_alloc((const unsigned char *)result_values[0]->bv_val, result_values[0]->bv_len, &dat)) {
              json_object_set_new(j_user, field, json_stringn((const char *)dat.data, dat.size));
              o_free(dat.data);
              dat.data = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_WARNING, "get_user_from_result - Error o_base64_encode_alloc for LDAP property '%s' (1)", json_string_value(j_property));
            }
          } else {
            json_object_set_new(j_user, field, json_stringn(result_values[0]->bv_val, result_values[0]->bv_len));
          }
        } else if (json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "multiple") == json_true()) {
          json_object_set_new(j_user, field, json_array());
          for (i=0; i<ldap_count_values_len(result_values); i++) {
            if (0 == o_strcmp("base64", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert")))) {
              if (o_base64_encode_alloc((const unsigned char *)result_values[i]->bv_val, result_values[i]->bv_len, &dat)) {
                json_array_append_new(json_object_get(j_user, field), json_stringn((const char *)dat.data, dat.size));
                o_free(dat.data);
                dat.data = NULL;
              } else {
                y_log_message(Y_LOG_LEVEL_WARNING, "get_user_from_result - Error o_base64_encode_alloc for LDAP property '%s' (1)", json_string_value(j_property));
              }
            } else {
              json_array_append_new(json_object_get(j_user, field), json_stringn(result_values[i]->bv_val, result_values[i]->bv_len));
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

static char * get_user_dn_from_username(json_t * j_params, LDAP * ldap, const char * username) {
  char * user_dn, * filter, * escaped = escape_ldap(username);
  int  result;
  char * attrs[] = {NULL};
  int  attrsonly = 0;
  LDAPMessage * answer = NULL, * entry;
  char * str_result = NULL;
  int  scope = LDAP_SCOPE_ONELEVEL;

  if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_SUBTREE;
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_CHILDREN;
  }
  filter = msprintf("(&(%s)(%s=%s))", json_string_value(json_object_get(j_params, "filter")), get_read_property(j_params, "username-property"), escaped);
  if ((result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_dn_from_username - Error ldap search, base search: %s, filter, error message: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(result));
  } else {
    if (ldap_count_entries(ldap, answer) == 1) {
      entry = ldap_first_entry(ldap, answer);
      user_dn = ldap_get_dn(ldap, entry);
      str_result = o_strdup(user_dn);
      ldap_memfree(user_dn);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_user_dn_from_username - Error username not found '%s'", username);
    }
    ldap_msgfree(answer);
  }
  o_free(filter);
  o_free(escaped);
  return str_result;
}

json_t * user_module_load(struct config_module * config) {
  UNUSED(config);
  return json_pack("{si ss ss ss sf}",
                   "result", G_OK,
                   "name", "ldap",
                   "display_name", "LDAP backend user module",
                   "description", "Module to store users in a LDAP server",
                   "api_version", 2.5);
}

int user_module_unload(struct config_module * config) {
  UNUSED(config);
  return G_OK;
}

json_t * user_module_init(struct config_module * config, int readonly, int multiple_passwords, json_t * j_parameters, void ** cls) {
  UNUSED(config);
  json_t * j_properties, * j_return;
  char * error_message;

  j_properties = is_user_ldap_parameters_valid(j_parameters, readonly);
  if (check_result_value(j_properties, G_OK)) {
    json_object_set(j_parameters, "multiple_passwords", multiple_passwords?json_true():json_false());
    *cls = json_incref(j_parameters);
    j_return = json_pack("{si}", "result", G_OK);
  } else if (check_result_value(j_properties, G_ERROR_PARAM)) {
    error_message = json_dumps(json_object_get(j_properties, "error"), JSON_COMPACT);
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error parsing parameters");
    y_log_message(Y_LOG_LEVEL_ERROR, error_message);
    o_free(error_message);
    j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", json_object_get(j_properties, "error"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error is_user_database_parameters_valid");
    j_return = json_pack("{sis[s]}", "result", G_ERROR, "error", "internal error");
  }
  json_decref(j_properties);
  return j_return;
}

int user_module_close(struct config_module * config, void * cls) {
  UNUSED(config);
  json_decref((json_t *)cls);
  return G_OK;
}

size_t user_module_count_total(struct config_module * config, const char * pattern, void * cls) {
  UNUSED(config);
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
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_count_total ldap - Error ldap search, base search: %s, filter: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(result));
    } else {
      counter = (size_t)ldap_count_entries(ldap, answer);
    }
    ldap_msgfree(answer);
    ldap_unbind_ext(ldap, NULL, NULL);
    o_free(filter);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_count_total ldap - Error connect_ldap_server");
  }
  return counter;
}

json_t * user_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls, * j_properties_user = NULL, * j_user_list, * j_user, * j_return;
  LDAP * ldap = connect_ldap_server(j_params);
  LDAPMessage * entry;

  int  ldap_result;
  int  scope = LDAP_SCOPE_ONELEVEL;
  char * filter = NULL;
  char ** attrs = NULL;
  int  attrsonly = 0;
  struct berval ** result_values = NULL;

  /* paged control variables */
  struct berval new_cookie, * cookie = NULL;
  int more_page, l_errcode = 0;
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
      ldap_result = ldap_create_page_control(ldap, (ber_int_t)json_integer_value(json_object_get(j_params, "page-size")), cookie, 0, &page_control);
      if (ldap_result != LDAP_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error ldap_create_page_control, message: %s", ldap_err2string(ldap_result));
        break;
      }

      search_controls[0] = page_control;
      ldap_result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, search_controls, NULL, NULL, 0, &l_result);
      if ((ldap_result != LDAP_SUCCESS) & (ldap_result != LDAP_PARTIAL_RESULTS)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error ldap search, base search: %s, filter: %s, error message: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(ldap_result));
        break;
      }

      ldap_result = ldap_parse_result(ldap, l_result, &l_errcode, NULL, NULL, NULL, &returned_controls, 0);
      if (ldap_result != LDAP_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error ldap_parse_result, message: %s", ldap_err2string(ldap_result));
        break;
      }

      if (cookie != NULL) {
        ber_bvfree(cookie);
        cookie = NULL;
      }

      if (returned_controls != NULL) {
        ldap_result = ldap_parse_pageresponse_control(ldap, *returned_controls, &total_count, &new_cookie);
        ldap_controls_free(returned_controls);
        returned_controls = NULL;
        if (ldap_result != LDAP_SUCCESS) {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error ldap_parse_pageresponse_control, message: %s", ldap_err2string(ldap_result));
          break;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error returned_controls is NULL");
        break;
      }

      cookie = ber_memalloc( sizeof( struct berval ) );
      if (cookie != NULL) {
        *cookie = new_cookie;
        if (cookie->bv_val != NULL && (o_strlen(cookie->bv_val) > 0)) {
          more_page = 1;
        } else {
          more_page = 0;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error ber_malloc returned NULL");
        break;
      }

      search_controls[0] = NULL;
      ldap_control_free(page_control);
      page_control = NULL;

      entry = ldap_first_entry(ldap, l_result);
      for (;entry !=NULL && offset > 0; entry = ldap_next_entry(ldap, entry)) {
        offset--;
      }

      while (entry != NULL && limit) {
        j_user = get_user_from_result(j_params, j_properties_user, ldap, entry);
        if (j_user != NULL) {
          if (json_object_get(j_params, "multiple_passwords") == json_true()) {
            result_values = ldap_get_values_len(ldap, entry, json_string_value(json_object_get(j_params, "password-property")));
            json_object_set_new(j_user, "password", json_integer(ldap_count_values_len(result_values)));
            ldap_value_free_len(result_values);
          }
          json_array_append_new(j_user_list, j_user);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error get_user_from_result");
        }
        entry = ldap_next_entry(ldap, entry);
        limit--;
      }

      ldap_msgfree(l_result);
      l_result = NULL;
    } while (more_page && limit);
    ldap_msgfree(l_result);
    l_result = NULL;
    o_free(filter);
    ber_bvfree(cookie);
    cookie = NULL;
    if (page_control != NULL) {
      ldap_control_free(page_control);
      page_control = NULL;
    }

    ldap_unbind_ext(ldap, NULL, NULL);
    j_return = json_pack("{sisO}", "result", G_OK, "list", j_user_list);
    json_decref(j_user_list);
    json_decref(j_properties_user);
    o_free(attrs);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap - Error connect_ldap_server");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

json_t * user_module_get(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls, * j_properties_user = NULL, * j_user, * j_return;
  LDAP * ldap = connect_ldap_server(j_params);
  LDAPMessage * entry, * answer;
  int ldap_result;
  struct berval ** result_values = NULL;
  char * escaped = escape_ldap(username);

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
    filter = msprintf("(&(%s)(%s=%s))", json_string_value(json_object_get(j_params, "filter")), get_read_property(j_params, "username-property"), escaped);
    attrs = get_ldap_read_attributes(j_params, 0, (j_properties_user = json_object()));
    if ((ldap_result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get user - Error ldap search, base search: %s, filter: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(ldap_result));
      j_return = json_pack("{si}", "result", G_ERROR);
    } else {
      // Looping in results, staring at offset, until the end of the list
      if (ldap_count_entries(ldap, answer) == 1) {
        entry = ldap_first_entry(ldap, answer);
        j_user = get_user_from_result(j_params, j_properties_user, ldap, entry);
        if (j_user != NULL) {
          if (json_object_get(j_params, "multiple_passwords") == json_true()) {
            result_values = ldap_get_values_len(ldap, entry, json_string_value(json_object_get(j_params, "password-property")));
            json_object_set_new(j_user, "password", json_integer(ldap_count_values_len(result_values)));
            ldap_value_free_len(result_values);
          }
          j_return = json_pack("{sisO}", "result", G_OK, "user", j_user);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap user - Error get_user_from_result");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_user);
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
    }

    json_decref(j_properties_user);
    o_free(attrs);
    o_free(filter);
    ldap_msgfree(answer);
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get ldap user - Error connect_ldap_server");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  o_free(escaped);
  return j_return;
}

json_t * user_module_get_profile(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls, * j_properties_user = NULL, * j_user, * j_return;
  LDAP * ldap = connect_ldap_server(j_params);
  LDAPMessage * entry, * answer;
  int ldap_result;
  struct berval ** result_values = NULL;
  char * escaped = escape_ldap(username);

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
    filter = msprintf("(&(%s)(%s=%s))", json_string_value(json_object_get(j_params, "filter")), get_read_property(j_params, "username-property"), escaped);
    attrs = get_ldap_read_attributes(j_params, 1, (j_properties_user = json_object()));
    if ((ldap_result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_profile ldap user - Error ldap search, base search: %s, filter: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(ldap_result));
      j_return = json_pack("{si}", "result", G_ERROR);
    } else {
      if (ldap_count_entries(ldap, answer) == 1) {
        entry = ldap_first_entry(ldap, answer);
        j_user = get_user_from_result(j_params, j_properties_user, ldap, entry);
        if (j_user != NULL) {
          if (json_object_get(j_params, "multiple_passwords") == json_true()) {
            result_values = ldap_get_values_len(ldap, entry, json_string_value(json_object_get(j_params, "password-property")));
            json_object_set_new(j_user, "password", json_integer(ldap_count_values_len(result_values)));
            ldap_value_free_len(result_values);
          }
          j_return = json_pack("{sisO}", "result", G_OK, "user", j_user);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_list ldap user - Error get_user_from_result");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_user);
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
    }

    json_decref(j_properties_user);
    o_free(attrs);
    o_free(filter);
    ldap_msgfree(answer);
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_get_profile ldap user - Error connect_ldap_server");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  o_free(escaped);
  return j_return;
}

json_t * user_module_is_valid(struct config_module * config, const char * username, json_t * j_user, int mode, void * cls) {
  json_t * j_params = (json_t *)cls;
  json_t * j_result = json_array(), * j_element = NULL, * j_format, * j_value, * j_return, * j_cur_user;
  char * message;
  size_t index = 0, len = 0;
  const char * property;

  if (j_result != NULL) {
    if (mode == GLEWLWYD_IS_VALID_MODE_ADD) {
      if (json_string_null_or_empty(json_object_get(j_user, "username"))) {
        json_array_append_new(j_result, json_string("username is mandatory and must be a non empty string"));
      } else {
        j_cur_user = user_module_get(config, json_string_value(json_object_get(j_user, "username")), cls);
        if (check_result_value(j_cur_user, G_OK)) {
          json_array_append_new(j_result, json_string("username already exist"));
        } else if (!check_result_value(j_cur_user, G_ERROR_NOT_FOUND)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_is_valid database - Error user_module_get");
        }
        json_decref(j_cur_user);
      }
    } else if ((mode == GLEWLWYD_IS_VALID_MODE_UPDATE || mode == GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) && username == NULL) {
      json_array_append_new(j_result, json_string("username is mandatory on update mode"));
    }
    if (mode != GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) {
      if (json_object_get(j_user, "scope") != NULL) {
        if (!json_is_array(json_object_get(j_user, "scope"))) {
          json_array_append_new(j_result, json_string("scope must be a JSON array of string"));
        } else {
          json_array_foreach(json_object_get(j_user, "scope"), index, j_element) {
            if (!json_is_string(j_element) || json_string_null_or_empty(j_element)) {
              json_array_append_new(j_result, json_string("scope must be a JSON array of string"));
            }
          }
        }
      }
    }
    if (json_object_get(j_params, "multiple_passwords") == json_true()) {
      if (mode != GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE && json_object_get(j_user, "password") != NULL && !json_is_array(json_object_get(j_user, "password"))) {
        json_array_append_new(j_result, json_string("password must be an array"));
      }
    } else {
      if (mode != GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE && json_object_get(j_user, "password") != NULL && !json_is_string(json_object_get(j_user, "password"))) {
        json_array_append_new(j_result, json_string("password must be a string"));
      }
    }
    if (json_object_get(j_user, "name") != NULL && !json_is_string(json_object_get(j_user, "name"))) {
      json_array_append_new(j_result, json_string("name must be a non empty string"));
    }
    if (json_object_get(j_user, "email") != NULL && !json_is_string(json_object_get(j_user, "email"))) {
      json_array_append_new(j_result, json_string("email must be a non empty string"));
    }
    if (json_object_get(j_user, "enabled") != NULL && !json_is_boolean(json_object_get(j_user, "enabled"))) {
      json_array_append_new(j_result, json_string("enabled must be a boolean"));
    }
    json_object_foreach(j_user, property, j_element) {
      if (0 != o_strcmp(property, "username") &&
          0 != o_strcmp(property, "name") &&
          0 != o_strcmp(property, "email") &&
          0 != o_strcmp(property, "enabled") &&
          0 != o_strcmp(property, "password") &&
          0 != o_strcmp(property, "source") &&
          0 != o_strcmp(property, "scope")) {
        j_format = json_object_get(json_object_get(j_params, "data-format"), property);
        if (json_object_get(j_format, "multiple") == json_true()) {
          if (!json_is_array(j_element)) {
            message = msprintf("%s must be an array", property);
            json_array_append_new(j_result, json_string(message));
            o_free(message);
          } else {
            json_array_foreach(j_element, index, j_value) {
              if (!json_is_string(j_value)) {
                message = msprintf("%s must contain a non empty string value", property);
                json_array_append_new(j_result, json_string(message));
                o_free(message);
              } else if (json_string_length(j_value) && 0 == o_strcmp("base64", json_string_value(json_object_get(j_format, "convert")))) {
                if (!o_base64_decode((const unsigned char *)json_string_value(j_value), json_string_length(j_value), NULL, &len)) {
                  message = msprintf("%s must contain a base64 encoded string value", property);
                  json_array_append_new(j_result, json_string(message));
                  o_free(message);
                }
              }
            }
          }
        } else {
          if (!json_is_string(j_element)) {
            message = msprintf("%s must contain a string value", property);
            json_array_append_new(j_result, json_string(message));
            o_free(message);
          } else if (json_string_length(j_element) && 0 == o_strcmp("base64", json_string_value(json_object_get(j_format, "convert")))) {
            if (!o_base64_decode((const unsigned char *)json_string_value(j_element), json_string_length(j_element), NULL, &len)) {
              message = msprintf("%s must contain a base64 encoded string value", property);
              json_array_append_new(j_result, json_string(message));
              o_free(message);
            }
          }
        }
      }
    }
    if (json_array_size(j_result)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_result);
    } else {
      j_return = json_pack("{si}", "result", G_OK);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_is_valid ldap - Error allocating resources for j_result");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

int user_module_add(struct config_module * config, json_t * j_user, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls;
  LDAP * ldap = connect_ldap_server(j_params);
  int ret, result;
  LDAPMod ** mods = NULL;
  char * new_dn;
  size_t i, j;

  if (ldap != NULL) {
    mods = get_ldap_write_mod(j_params, ldap, json_string_value(json_object_get(j_user, "username")), j_user, 0, 1);
    if (mods != NULL) {
      new_dn = msprintf("%s=%s,%s", json_string_value(json_object_get(j_params, "rdn-property")), json_string_value(json_object_get(j_user, "username")), json_string_value(json_object_get(j_params, "base-search")));
      if (new_dn != NULL) {
        if ((result = ldap_add_ext_s(ldap, new_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add ldap - Error adding new user %s in the ldap backend: %s", new_dn, ldap_err2string(result));
          ret = G_ERROR;
        } else {
          ret = G_OK;
        }
        o_free(new_dn);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add ldap - Error allocating resources for new_dn");
        ret = G_ERROR;
      }
      for (i=0; mods[i]!=NULL; i++) {
        for (j=0; mods[i]->mod_values[j] != NULL; j++) {
          o_free(mods[i]->mod_values[j]);
        }
        o_free(mods[i]->mod_values);
        o_free(mods[i]);
      }
      o_free(mods);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add ldap - Error get_ldap_write_mod");
      ret = G_ERROR;
    }
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_add ldap - Error connect_ldap_server");
    ret = G_ERROR;
  }
  return ret;
}

int user_module_update(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls;
  LDAP * ldap = connect_ldap_server(j_params);
  int ret, result;
  LDAPMod ** mods = NULL;
  char * cur_dn;
  size_t i, j;

  if (ldap != NULL) {
    mods = get_ldap_write_mod(j_params, ldap, username, j_user, 0, 0);
    if (mods != NULL) {
      cur_dn = get_user_dn_from_username(j_params, ldap, username);
      if (cur_dn != NULL) {
        if ((result = ldap_modify_ext_s(ldap, cur_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update user - Error update user %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
          ret = G_ERROR;
        } else {
          ret = G_OK;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error get_user_dn_from_username");
        ret = G_ERROR;
      }
      o_free(cur_dn);
      for (i=0; mods[i]!=NULL; i++) {
        for (j=0; mods[i]->mod_values[j] != NULL; j++) {
          o_free(mods[i]->mod_values[j]);
        }
        o_free(mods[i]->mod_values);
        o_free(mods[i]);
      }
      o_free(mods);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error get_ldap_write_mod");
      ret = G_ERROR;
    }
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error connect_ldap_server");
    ret = G_ERROR;
  }
  return ret;
}

int user_module_update_profile(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls;
  LDAP * ldap = connect_ldap_server(j_params);
  int ret, result;
  LDAPMod ** mods = NULL;
  char * cur_dn;
  size_t i, j;

  if (ldap != NULL) {
    mods = get_ldap_write_mod(j_params, ldap, username, j_user, 1, 0);
    if (mods != NULL) {
      cur_dn = get_user_dn_from_username(j_params, ldap, username);
      if (cur_dn != NULL) {
        if ((result = ldap_modify_ext_s(ldap, cur_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update_profile user - Error update user profile %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
          ret = G_ERROR;
        } else {
          ret = G_OK;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error get_user_dn_from_username");
        ret = G_ERROR;
      }
      o_free(cur_dn);
      for (i=0; mods[i]!=NULL; i++) {
        for (j=0; mods[i]->mod_values[j] != NULL; j++) {
          o_free(mods[i]->mod_values[j]);
        }
        o_free(mods[i]->mod_values);
        o_free(mods[i]);
      }
      o_free(mods);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error get_ldap_write_mod");
      ret = G_ERROR;
    }
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update ldap - Error connect_ldap_server");
    ret = G_ERROR;
  }
  return ret;
}

int user_module_delete(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls;
  LDAP * ldap = connect_ldap_server(j_params);
  int ret, result;
  char * cur_dn;

  if (ldap != NULL) {
    cur_dn = get_user_dn_from_username(j_params, ldap, username);
    if (cur_dn != NULL) {
      if ((result = ldap_delete_ext_s(ldap, cur_dn, NULL, NULL)) != LDAP_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_module_delete user - Error delete user %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
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

int user_module_check_password(struct config_module * config, const char * username, const char * password, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls;
  LDAP * ldap = connect_ldap_server(j_params);
  LDAPMessage * entry, * answer;
  int ldap_result, result_login, result;
  char * user_dn = NULL;

  int  scope = LDAP_SCOPE_ONELEVEL;
  char * filter = NULL;
  char * attrs[] = {"memberOf", NULL, NULL};
  int attrsonly = 0;
  char * ldap_mech = LDAP_SASL_SIMPLE, * escaped = escape_ldap(username);
  struct berval cred;
  struct berval * servcred;

  if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_SUBTREE;
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_CHILDREN;
  }
  if (ldap != NULL) {
    // Connection successful, doing ldap search
    filter = msprintf("(&(%s)(%s=%s))", json_string_value(json_object_get(j_params, "filter")), get_read_property(j_params, "username-property"), escaped);
    if ((ldap_result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_check_password ldap - Error ldap search, base search: %s, filter: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(ldap_result));
      result = G_ERROR;
    } else {
      if (ldap_count_entries(ldap, answer) == 1) {
        // Testing the first result to username with the given password
        entry = ldap_first_entry(ldap, answer);
        user_dn = ldap_get_dn(ldap, entry);
        cred.bv_val = (char *)password;
        cred.bv_len = o_strlen(password);
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
  o_free(escaped);
  return result;
}

int user_module_update_password(struct config_module * config, const char * username, const char ** new_passwords, size_t new_passwords_len, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls;
  LDAP * ldap = connect_ldap_server(j_params);
  int ret, result, i;
  LDAPMod * mods[2] = {NULL, NULL};
  char * cur_dn;

  if (ldap != NULL) {
    mods[0] = o_malloc(sizeof(LDAPMod));
    if (mods[0] != NULL) {
      if (json_object_get(j_params, "multiple_passwords") == json_true()) {
        mods[0]->mod_op     = LDAP_MOD_REPLACE;
        mods[0]->mod_type   = (char *)json_string_value(json_object_get(j_params, "password-property"));
        mods[1] = NULL;
        if (set_update_password_mod(j_params, ldap, username, new_passwords, new_passwords_len, mods[0], 0) == G_OK) {
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
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_update_password ldap - Error set_update_password_mod");
          ret = G_ERROR;
        }
        for (i=0; mods[0]->mod_values[i]!=NULL; i++) {
          o_free(mods[0]->mod_values[i]);
        }
        o_free(mods[0]->mod_values);
        o_free(mods[0]);
      } else {
        mods[0]->mod_values = o_malloc(2 * sizeof(char *));
        mods[0]->mod_op     = LDAP_MOD_REPLACE;
        mods[0]->mod_type   = (char *)json_string_value(json_object_get(j_params, "password-property"));
        mods[0]->mod_values[0] = o_strlen(new_passwords[0])?generate_hash(get_digest_algorithm(j_params), new_passwords[0]):NULL;
        mods[0]->mod_values[1] = NULL;
        mods[1] = NULL;
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
      }
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

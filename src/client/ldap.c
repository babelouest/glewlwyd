/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Clients are authenticated via various backend available: database, ldap
 * 
 * LDAP client module
 * 
 * Copyright 2019 Nicolas Mora <mail@babelouest.org>
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

static json_t * is_client_ldap_parameters_valid(json_t * j_params, int readonly) {
  json_t * j_return, * j_error = json_array(), * j_element = NULL, * j_element_p;
  size_t index = 0;
  const char * field = NULL;
  char * message;
  
  if (j_error != NULL) {
    if (!json_is_object(j_params)) {
      json_array_append_new(j_error, json_string("parameters must be a JSON object"));
    } else {
      if (!json_string_length(json_object_get(j_params, "uri"))) {
        json_array_append_new(j_error, json_string("uri is mandatory and must be a string"));
      }
      if (!json_string_length(json_object_get(j_params, "bind-dn"))) {
        json_array_append_new(j_error, json_string("bind-dn is mandatory and must be a string"));
      }
      if (!json_string_length(json_object_get(j_params, "bind-password"))) {
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
      if (!json_string_length(json_object_get(j_params, "base-search"))) {
        json_array_append_new(j_error, json_string("base-search is mandatory and must be a string"));
      }
      if (!json_string_length(json_object_get(j_params, "filter"))) {
        json_array_append_new(j_error, json_string("filter is mandatory and must be a string"));
      }
      if (readonly) {
        if (!json_string_length(json_object_get(j_params, "client_id-property"))) {
          json_array_append_new(j_error, json_string("client_id-property is mandatory and must be a non empty string"));
        }
      } else {
        if (json_object_get(j_params, "client_id-property") == NULL || (!json_is_string(json_object_get(j_params, "client_id-property")) && !json_is_array(json_object_get(j_params, "client_id-property")))) {
          json_array_append_new(j_error, json_string("client_id-property is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_string(json_object_get(j_params, "client_id-property")) && !json_string_length(json_object_get(j_params, "client_id-property"))) {
          json_array_append_new(j_error, json_string("client_id-property is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_array(json_object_get(j_params, "client_id-property"))) {
          json_array_foreach(json_object_get(j_params, "client_id-property"), index, j_element) {
            if (!json_string_length(j_element)) {
              json_array_append_new(j_error, json_string("client_id-property is mandatory and must be a non empty string or an array of non empty strings"));
            }
          }
        }
      }
      if (readonly) {
        if (!json_string_length(json_object_get(j_params, "scope-property"))) {
          json_array_append_new(j_error, json_string("scope-property is mandatory and must be a non empty string"));
        }
      } else {
        if (json_object_get(j_params, "scope-property") == NULL || (!json_is_string(json_object_get(j_params, "scope-property")) && !json_is_array(json_object_get(j_params, "scope-property")))) {
          json_array_append_new(j_error, json_string("scope-property is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_string(json_object_get(j_params, "scope-property")) && !json_string_length(json_object_get(j_params, "scope-property"))) {
          json_array_append_new(j_error, json_string("scope-property is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_array(json_object_get(j_params, "scope-property"))) {
          json_array_foreach(json_object_get(j_params, "scope-property"), index, j_element) {
            if (!json_string_length(j_element)) {
              json_array_append_new(j_error, json_string("scope-property is mandatory and must be a non empty string or an array of non empty strings"));
            }
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
      if (readonly) {
        if (!json_string_length(json_object_get(j_params, "name-property"))) {
          json_array_append_new(j_error, json_string("name-property is mandatory and must be a non empty string"));
        }
      } else {
        if (json_object_get(j_params, "name-property") == NULL || (!json_is_string(json_object_get(j_params, "name-property")) && !json_is_array(json_object_get(j_params, "name-property")))) {
          json_array_append_new(j_error, json_string("name-property is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_string(json_object_get(j_params, "name-property")) && !json_string_length(json_object_get(j_params, "name-property"))) {
          json_array_append_new(j_error, json_string("name-property is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_array(json_object_get(j_params, "name-property"))) {
          json_array_foreach(json_object_get(j_params, "name-property"), index, j_element) {
            if (!json_string_length(j_element)) {
              json_array_append_new(j_error, json_string("name-property is mandatory and must be a non empty string or an array of non empty strings"));
            }
          }
        }
      }
      if (readonly) {
        if (!json_string_length(json_object_get(j_params, "description-property"))) {
          json_array_append_new(j_error, json_string("description-property is optional and must be a non empty string"));
        }
      } else {
        if (json_object_get(j_params, "description-property") != NULL && !json_is_string(json_object_get(j_params, "description-property")) && !json_is_array(json_object_get(j_params, "description-property"))) {
          json_array_append_new(j_error, json_string("description-property is optional and must be a non empty string or an array of non empty strings"));
        } else if (json_is_string(json_object_get(j_params, "description-property")) && !json_string_length(json_object_get(j_params, "description-property"))) {
          json_array_append_new(j_error, json_string("description-property is optional and must be a non empty string or an array of non empty strings"));
        } else if (json_is_array(json_object_get(j_params, "description-property"))) {
          json_array_foreach(json_object_get(j_params, "description-property"), index, j_element) {
            if (!json_string_length(j_element)) {
              json_array_append_new(j_error, json_string("description-property is optional and must be a non empty string or an array of non empty strings"));
            }
          }
        }
      }
      if (readonly) {
        if (!json_string_length(json_object_get(j_params, "confidential-property"))) {
          json_array_append_new(j_error, json_string("confidential-property is mandatory and must be a non empty string"));
        }
      } else {
        if (json_object_get(j_params, "confidential-property") == NULL || (!json_string_length(json_object_get(j_params, "confidential-property")) && !json_is_array(json_object_get(j_params, "confidential-property")))) {
          json_array_append_new(j_error, json_string("confidential-property is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_array(json_object_get(j_params, "confidential-property"))) {
          json_array_foreach(json_object_get(j_params, "confidential-property"), index, j_element) {
            if (!json_string_length(j_element)) {
              json_array_append_new(j_error, json_string("confidential-property is mandatory and must be a non empty string or an array of non empty strings"));
            }
          }
        }
      }
      if (!readonly) {
        if (!json_string_length(json_object_get(j_params, "rdn-property"))) {
          json_array_append_new(j_error, json_string("rdn-property is mandatory and must be a non empty string"));
        }
        if (!json_string_length(json_object_get(j_params, "password-property"))) {
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
           0 != o_strcmp(json_string_value(json_object_get(j_params, "password-algorithm")), "PLAIN"))) {
          //json_array_append_new(j_error, json_string("password-algorithm is mandatory and must have one of the following values: 'SHA', 'SHA256', 'SHA284', 'SHA512', 'SSHA', "
          //                                           "'SSHA256', 'SSHA384', 'SSHA512', 'SMD5', 'MD5', 'PKCS5S2', 'PLAIN'"));
          json_array_append_new(j_error, json_string("password-algorithm is mandatory and must have one of the following values: 'SHA', 'SSHA', 'SMD5', 'MD5', 'PLAIN'"));
        }
        if (json_object_get(j_params, "object-class") == NULL || (!json_is_string(json_object_get(j_params, "object-class")) && !json_is_array(json_object_get(j_params, "object-class")))) {
          json_array_append_new(j_error, json_string("object-class is mandatory and must be a non empty string or an array of non empty strings"));
        } else if (json_is_string(json_object_get(j_params, "object-class")) && !json_string_length(json_object_get(j_params, "object-class"))) {
          json_array_append_new(j_error, json_string("object-class is mandatory and must be a non empty string or an array of non empty strings"));
        } else {
          json_array_foreach(json_object_get(j_params, "object-class"), index, j_element) {
            if (!json_string_length(j_element)) {
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
            if (0 == o_strcmp(field, "client_id") || 0 == o_strcmp(field, "name") || 0 == o_strcmp(field, "description") || 0 == o_strcmp(field, "enabled") || 0 == o_strcmp(field, "confidential") || 0 == o_strcmp(field, "password") || 0 == o_strcmp(field, "scope")) {
              json_array_append_new(j_error, json_string("data-format can not have settings for properties 'client_id', 'name', 'description', 'enabled', 'confidential', 'scope' or 'password'"));
            } else {
              if (readonly) {
                if (json_object_get(j_element, "property") == NULL || !json_string_length(json_object_get(j_element, "property"))) {
                  message = msprintf("property %s is mandatory and must be a non empty string or an array of non empty string", field);
                  json_array_append_new(j_error, json_string(message));
                  o_free(message);
                }
              } else {
                if (json_object_get(j_element, "property") == NULL || ((!json_is_string(json_object_get(j_element, "property")) || !json_string_length(json_object_get(j_element, "property"))) && !json_is_array(json_object_get(j_element, "property")))) {
                  message = msprintf("property %s is mandatory and must be a non empty string or an array of non empty string", field);
                  json_array_append_new(j_error, json_string(message));
                  o_free(message);
                } else if (json_is_array(json_object_get(j_element, "property"))) {
                  json_array_foreach(json_object_get(j_element, "property"), index, j_element_p) {
                    if (!json_string_length(j_element_p)) {
                      message = msprintf("property %s is mandatory and must be a non empty string or an array of non empty string", field);
                      json_array_append_new(j_error, json_string(message));
                      o_free(message);
                    }
                  }
                }
              }
              if (json_object_get(j_element, "multiple") != NULL && !json_is_boolean(json_object_get(j_element, "multiple"))) {
                json_array_append_new(j_error, json_string("multiple is optional and must be a boolean (default: false)"));
              }
              if (json_object_get(j_element, "convert") != NULL && 0 != o_strcmp("base64", json_string_value(json_object_get(j_element, "convert"))) && 0 != o_strcmp("jwk", json_string_value(json_object_get(j_element, "convert")))) {
                json_array_append_new(j_error, json_string("convert is optional and must have one of the following values: 'base64', 'jwk'"));
              }
              if (json_object_get(j_element, "read") != NULL && !json_is_boolean(json_object_get(j_element, "read"))) {
                json_array_append_new(j_error, json_string("read is optional and must be a boolean (default: true)"));
              }
              if (!readonly && json_object_get(j_element, "write") != NULL && !json_is_boolean(json_object_get(j_element, "write"))) {
                json_array_append_new(j_error, json_string("write is optional and must be a boolean (default: true)"));
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
    y_log_message(Y_LOG_LEVEL_ERROR, "is_client_database_parameters_valid - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

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

static LDAP * connect_ldap_server(json_t * j_params) {
  LDAP * ldap = NULL;
  int ldap_version = LDAP_VERSION3;
  int result;
  char * ldap_mech = LDAP_SASL_SIMPLE;
  struct berval cred, * servcred;
  
  cred.bv_val = (char*)json_string_value(json_object_get(j_params, "bind-password"));
  cred.bv_len = o_strlen(json_string_value(json_object_get(j_params, "bind-password")));
  
  if (ldap_initialize(&ldap, json_string_value(json_object_get(j_params, "uri"))) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_count_total ldap - Error initializing ldap");
    ldap = NULL;
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_count_total ldap - Error setting ldap protocol version");
    ldap_unbind_ext(ldap, NULL, NULL);
    ldap = NULL;
  } else if ((result = ldap_sasl_bind_s(ldap, json_string_value(json_object_get(j_params, "bind-dn")), ldap_mech, &cred, NULL, NULL, &servcred)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "connect_ldap_server client - Error binding to ldap server mode %s: %s", ldap_mech, ldap_err2string(result));
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
  char * pattern_escaped, * filter, * name_filter, * description_filter;
  
  if (o_strlen(pattern)) {
    pattern_escaped = escape_ldap(pattern);
    if (json_object_get(j_params, "name-property") != NULL) {
      name_filter = msprintf("(%s=*%s*)", get_read_property(j_params, "name-property"), pattern_escaped);
    } else {
      name_filter = o_strdup("");
    }
    if (json_object_get(j_params, "description-property") != NULL) {
      description_filter = msprintf("(%s=*%s*)", get_read_property(j_params, "description-property"), pattern_escaped);
    } else {
      description_filter = o_strdup("");
    }
    filter = msprintf("(&(%s)(|(%s=*%s*)%s%s))", 
                      json_string_value(json_object_get(j_params, "filter")), 
                      get_read_property(j_params, "client_id-property"),
                      pattern_escaped,
                      name_filter,
                      description_filter);
    o_free(pattern_escaped);
    o_free(name_filter);
    o_free(description_filter);
  } else {
    filter = msprintf("(%s)", json_string_value(json_object_get(j_params, "filter")));
  }
  
  return filter;
}

static char ** get_ldap_read_attributes(json_t * j_params, int profile, json_t * j_properties) {
  char ** attrs = NULL;
  size_t i, nb_attrs = 2; // Clientname, Scope
  json_t * j_element = NULL;
  const char * field = NULL;
  
  if (j_properties != NULL && json_is_object(j_properties) && !json_object_size(j_properties)) {
    nb_attrs += (json_object_get(j_params, "name-property") != NULL);
    nb_attrs += (json_object_get(j_params, "description-property") != NULL);
    nb_attrs += (json_object_get(j_params, "confidential-property") != NULL);
    if (json_object_get(j_params, "data-format") != NULL) {
      json_object_foreach(json_object_get(j_params, "data-format"), field, j_element) {
        nb_attrs += ((!profile && json_object_get(j_element, "read") != json_false()) || (profile && json_object_get(j_element, "profile-read") == json_true()));
      }
    }
    attrs = o_malloc((nb_attrs + 1) * sizeof(char *));
    if (attrs != NULL) {
      attrs[nb_attrs] = NULL;
      attrs[0] = (char*)get_read_property(j_params, "client_id-property");
      json_object_set_new(j_properties, "client_id", json_string(get_read_property(j_params, "client_id-property")));
      attrs[1] = (char*)get_read_property(j_params, "scope-property");
      json_object_set_new(j_properties, "scope", json_string(get_read_property(j_params, "scope-property")));
      i = 2;
      if (json_object_get(j_params, "name-property") != NULL) {
        attrs[i++] = (char*)get_read_property(j_params, "name-property");
        json_object_set_new(j_properties, "name", json_string(get_read_property(j_params, "name-property")));
      }
      if (json_object_get(j_params, "description-property") != NULL) {
        attrs[i++] = (char*)get_read_property(j_params, "description-property");
        json_object_set_new(j_properties, "description", json_string(get_read_property(j_params, "description-property")));
      }
      if (json_object_get(j_params, "confidential-property") != NULL) {
        attrs[i++] = (char*)get_read_property(j_params, "confidential-property");
        json_object_set_new(j_properties, "confidential", json_string(get_read_property(j_params, "confidential-property")));
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
  } else {
    return digest_PLAIN;
  }
}

static LDAPMod ** get_ldap_write_mod(json_t * j_params, json_t * j_client, int add, json_t * j_mod_value_free_array) {
  LDAPMod ** mods = NULL;
  size_t nb_attr = 0;
  json_t * j_format, * j_property = NULL, * j_property_value, * j_scope;
  const char * field = NULL;
  unsigned int i;
  size_t index = 0, index_scope = 0;
  int has_error = 0;
  unsigned char * value_enc = NULL;
  size_t value_enc_len = 0;
  
  if (j_mod_value_free_array != NULL) {
    // Count attrs
    if (add) {
      nb_attr += count_properties(j_params, "client_id-property") + 2;
    }
    if (json_object_get(j_client, "name") != NULL) {
      nb_attr += count_properties(j_params, "name-property");
    }
    if (json_object_get(j_client, "scope") != NULL) {
      nb_attr += count_properties(j_params, "scope-property");
    }
    if (json_object_get(j_client, "description") != NULL) {
      nb_attr += count_properties(j_params, "description-property");
    }
    if (json_object_get(j_client, "confidential") != NULL) {
      nb_attr += count_properties(j_params, "confidential-property");
    }
    if (json_string_length(json_object_get(j_client, "password"))) {
      nb_attr++;
    }
    json_object_foreach(j_client, field, j_property) {
      if (0 != o_strcmp(field, "client_id") && 
          0 != o_strcmp(field, "name") && 
          0 != o_strcmp(field, "password") && 
          0 != o_strcmp(field, "scope") && 
          0 != o_strcmp(field, "description") && 
          0 != o_strcmp(field, "enabled") && 
          0 != o_strcmp(field, "confidential")) {
        if ((j_format = json_object_get(json_object_get(j_params, "data-format"), field)) != NULL) {
          if (json_object_get(j_format, "write") != json_false()) {
            nb_attr += count_properties(j_format, "property");
          }
        }
      }
    }
    mods = o_malloc((nb_attr + 1)*sizeof(LDAPMod *));
    for (i=0; i<(nb_attr+1); i++) {
      mods[i] = NULL;
    }
    
    // Fill mods
    i=0;
    if (mods != NULL) {
      if (add) {
        mods[i] = o_malloc(sizeof(LDAPMod));
        if (mods[i] != NULL) {
          if (json_is_array(json_object_get(j_params, "object-class"))) {
            mods[i]->mod_values = o_malloc((json_array_size(json_object_get(j_params, "object-class")) + 1) * sizeof(char *));
            if (mods[i]->mod_values != NULL) {
              mods[i]->mod_op = LDAP_MOD_ADD;
              mods[i]->mod_type = "objectClass";
              json_array_foreach(json_object_get(j_params, "object-class"), index, j_property_value) {
                mods[i]->mod_values[index] = (char *)json_string_value(j_property_value);
              }
              mods[i]->mod_values[json_array_size(json_object_get(j_params, "object-class"))] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (objectClass)", i);
              has_error = 1;
            }
          } else {
            mods[i]->mod_values = o_malloc(2 * sizeof(char *));
            if (mods[i]->mod_values != NULL) {
              mods[i]->mod_op = LDAP_MOD_ADD;
              mods[i]->mod_type = "objectClass";
              mods[i]->mod_values[0] = (char *)json_string_value(json_object_get(j_params, "object-class"));
              mods[i]->mod_values[1] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (objectClass)", i);
              has_error = 1;
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (objectClass)", i);
          has_error = 1;
        }
        i++;
        if (json_is_array(json_object_get(j_params, "client_id-property"))) {
          json_array_foreach(json_object_get(j_params, "client_id-property"), index, j_property) {
            mods[i] = o_malloc(sizeof(LDAPMod));
            if (mods[i] != NULL) {
              mods[i]->mod_values = o_malloc(2 * sizeof(char *));
              if (mods[i]->mod_values != NULL) {
                mods[i]->mod_op = LDAP_MOD_ADD;
                mods[i]->mod_type = (char *)json_string_value(j_property);
                mods[i]->mod_values[0] = (char *)json_string_value(json_object_get(j_client, "client_id"));
                mods[i]->mod_values[1] = NULL;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (client_id)", i);
                has_error = 1;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (client_id)", i);
              has_error = 1;
            }
          }
        } else {
          mods[i] = o_malloc(sizeof(LDAPMod));
          if (mods[i] != NULL) {
            mods[i]->mod_values = o_malloc(2 * sizeof(char *));
            if (mods[i]->mod_values != NULL) {
              mods[i]->mod_op = add?LDAP_MOD_ADD:LDAP_MOD_REPLACE;
              mods[i]->mod_type = (char *)get_read_property(j_params, "client_id-property");
              mods[i]->mod_values[0] = (char *)json_string_value(json_object_get(j_client, "client_id"));
              mods[i]->mod_values[1] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (client_id)", i);
              has_error = 1;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (client_id)", i);
            has_error = 1;
          }
        }
        i++;
      }
      if (json_object_get(j_client, "name") != NULL) {
        if (json_is_array(json_object_get(j_params, "name-property"))) {
          json_array_foreach(json_object_get(j_params, "name-property"), index, j_property) {
            mods[i] = o_malloc(sizeof(LDAPMod));
            if (mods[i] != NULL) {
              mods[i]->mod_values = o_malloc(2 * sizeof(char *));
              if (mods[i]->mod_values != NULL) {
                mods[i]->mod_op = add?LDAP_MOD_ADD:LDAP_MOD_REPLACE;
                mods[i]->mod_type = (char *)json_string_value(j_property);
                mods[i]->mod_values[0] = (char *)json_string_value(json_object_get(j_client, "name"));
                mods[i]->mod_values[1] = NULL;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (name)", i);
                has_error = 1;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (name)", i);
              has_error = 1;
            }
          }
        } else {
          mods[i] = o_malloc(sizeof(LDAPMod));
          if (mods[i] != NULL) {
            mods[i]->mod_values = o_malloc(2 * sizeof(char *));
            if (mods[i]->mod_values != NULL) {
              mods[i]->mod_op = add?LDAP_MOD_ADD:LDAP_MOD_REPLACE;
              mods[i]->mod_type = (char *)json_string_value(json_object_get(j_params, "name-property"));
              mods[i]->mod_values[0] = (char *)json_string_value(json_object_get(j_client, "name"));
              mods[i]->mod_values[1] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (name)", i);
              has_error = 1;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (name)", i);
            has_error = 1;
          }
        }
        i++;
      }
      if (json_object_get(j_client, "description") != NULL) {
        if (json_is_array(json_object_get(j_params, "description-property"))) {
          json_array_foreach(json_object_get(j_params, "description-property"), index, j_property) {
            mods[i] = o_malloc(sizeof(LDAPMod));
            if (mods[i] != NULL) {
              mods[i]->mod_values = o_malloc(2 * sizeof(char *));
              if (mods[i]->mod_values != NULL) {
                mods[i]->mod_op = add?LDAP_MOD_ADD:LDAP_MOD_REPLACE;
                mods[i]->mod_type = (char *)json_string_value(j_property);
                mods[i]->mod_values[0] = (char *)json_string_value(json_object_get(j_client, "description"));
                mods[i]->mod_values[1] = NULL;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (description)", i);
                has_error = 1;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (description)", i);
              has_error = 1;
            }
          }
        } else {
          mods[i] = o_malloc(sizeof(LDAPMod));
          if (mods[i] != NULL) {
            mods[i]->mod_values = o_malloc(2 * sizeof(char *));
            if (mods[i]->mod_values != NULL) {
              mods[i]->mod_op = add?LDAP_MOD_ADD:LDAP_MOD_REPLACE;
              mods[i]->mod_type = (char *)json_string_value(json_object_get(j_params, "description-property"));
              mods[i]->mod_values[0] = (char *)json_string_value(json_object_get(j_client, "description"));
              mods[i]->mod_values[1] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (description)", i);
              has_error = 1;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (description)", i);
            has_error = 1;
          }
        }
        i++;
      }
      if (json_object_get(j_client, "confidential") != NULL) {
        if (json_is_array(json_object_get(j_params, "confidential-property"))) {
          json_array_foreach(json_object_get(j_params, "confidential-property"), index, j_property) {
            mods[i] = o_malloc(sizeof(LDAPMod));
            if (mods[i] != NULL) {
              mods[i]->mod_values = o_malloc(2 * sizeof(char *));
              if (mods[i]->mod_values != NULL) {
                mods[i]->mod_op = add?LDAP_MOD_ADD:LDAP_MOD_REPLACE;
                mods[i]->mod_type = (char *)json_string_value(j_property);
                mods[i]->mod_values[0] = json_object_get(j_client, "confidential")==json_true()?"1":"0";
                mods[i]->mod_values[1] = NULL;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (confidential)", i);
                has_error = 1;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (confidential)", i);
              has_error = 1;
            }
          }
        } else {
          mods[i] = o_malloc(sizeof(LDAPMod));
          if (mods[i] != NULL) {
            mods[i]->mod_values = o_malloc(2 * sizeof(char *));
            if (mods[i]->mod_values != NULL) {
              mods[i]->mod_op = add?LDAP_MOD_ADD:LDAP_MOD_REPLACE;
              mods[i]->mod_type = (char *)json_string_value(json_object_get(j_params, "confidential-property"));
              mods[i]->mod_values[0] = json_object_get(j_client, "confidential")==json_true()?"1":"0";
              mods[i]->mod_values[1] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (confidential)", i);
              has_error = 1;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (confidential)", i);
            has_error = 1;
          }
        }
        i++;
      }
      if (json_object_get(j_client, "scope") != NULL) {
        if (json_is_array(json_object_get(j_params, "scope-property"))) {
          json_array_foreach(json_object_get(j_params, "scope-property"), index, j_property) {
            mods[i] = o_malloc(sizeof(LDAPMod));
            if (mods[i] != NULL) {
              mods[i]->mod_values = o_malloc((json_array_size(json_object_get(j_client, "scope")) + 1) * sizeof(char *));
              if (mods[i]->mod_values != NULL) {
                mods[i]->mod_op = add?LDAP_MOD_ADD:LDAP_MOD_REPLACE;
                mods[i]->mod_type = (char *)json_string_value(j_property);
                json_array_foreach(json_object_get(j_client, "scope"), index_scope, j_scope) {
                  mods[i]->mod_values[index_scope] = (char *)json_string_value(j_scope);
                }
                mods[i]->mod_values[(json_array_size(json_object_get(j_client, "scope")))] = NULL;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (scope)", i);
                has_error = 1;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (scope)", i);
              has_error = 1;
            }
          }
        } else {
          mods[i] = o_malloc(sizeof(LDAPMod));
          if (mods[i] != NULL) {
            mods[i]->mod_values = o_malloc((json_array_size(json_object_get(j_client, "scope")) + 1) * sizeof(char *));
            if (mods[i]->mod_values != NULL) {
              mods[i]->mod_op = add?LDAP_MOD_ADD:LDAP_MOD_REPLACE;
              mods[i]->mod_type = (char *)json_string_value(json_object_get(j_params, "scope-property"));
              json_array_foreach(json_object_get(j_client, "scope"), index_scope, j_scope) {
                mods[i]->mod_values[index_scope] = (char *)json_string_value(j_scope);
              }
              mods[i]->mod_values[(json_array_size(json_object_get(j_client, "scope")))] = NULL;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (scope)", i);
              has_error = 1;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (scope)", i);
            has_error = 1;
          }
        }
        i++;
      }
      if (json_string_length(json_object_get(j_client, "password"))) {
        mods[i] = o_malloc(sizeof(LDAPMod));
        if (mods[i] != NULL) {
          mods[i]->mod_values = o_malloc(2 * sizeof(char *));
          if (mods[i]->mod_values != NULL) {
            mods[i]->mod_op = add?LDAP_MOD_ADD:LDAP_MOD_REPLACE;
            mods[i]->mod_type = (char *)json_string_value(json_object_get(j_params, "password-property"));
            mods[i]->mod_values[0] = json_string_length(json_object_get(j_client, "password"))?generate_hash(get_digest_algorithm(j_params), json_string_value(json_object_get(j_client, "password"))):NULL;
            mods[i]->mod_values[1] = NULL;
            json_array_append_new(j_mod_value_free_array, json_integer(i));
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (password)", i);
            has_error = 1;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (password)", i);
          has_error = 1;
        }
        i++;
      }
      json_object_foreach(j_client, field, j_property) {
        if (0 != o_strcmp(field, "client_id") && 0 != o_strcmp(field, "name") && 0 != o_strcmp(field, "password") && 0 != o_strcmp(field, "scope") && 0 != o_strcmp(field, "description") && 0 != o_strcmp(field, "enabled") && 0 != o_strcmp(field, "confidential")) {
          if ((j_format = json_object_get(json_object_get(j_params, "data-format"), field)) != NULL) {
            if (json_object_get(j_format, "write") != json_false()) {
              if (json_is_array(j_property) && json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "multiple") == json_true()) {
                mods[i] = o_malloc(sizeof(LDAPMod));
                if (mods[i] != NULL) {
                  mods[i]->mod_values = o_malloc((json_array_size(j_property) + 1) * sizeof(char *));
                  if (mods[i]->mod_values != NULL) {
                    mods[i]->mod_op = add?LDAP_MOD_ADD:LDAP_MOD_REPLACE;
                    mods[i]->mod_type = (char *)json_string_value(json_object_get(j_format, "property"));
                    json_array_foreach(j_property, index_scope, j_property_value) {
                      if (0 == o_strcmp("base64", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert")))) {
                        if (o_base64_decode((const unsigned char *)json_string_value(j_property_value), json_string_length(j_property_value), NULL, &value_enc_len)) {
                          if ((value_enc = o_malloc(value_enc_len+1)) != NULL) {
                            if (o_base64_decode((const unsigned char *)json_string_value(j_property_value), json_string_length(j_property_value), value_enc, &value_enc_len)) {
                              value_enc[value_enc_len] = '\0';
                              mods[i]->mod_values[index_scope] = (char *)value_enc;
                            } else {
                              y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error o_base64_decode for LDAP property '%s' (1-2)", json_string_value(j_property_value));
                              has_error = 1;
                            }
                          } else {
                            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for value_enc (1)");
                          }
                        } else {
                          y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error o_base64_decode for LDAP property '%s' (1-1)", json_string_value(j_property_value));
                          has_error = 1;
                        }
                      } else if (0 == o_strcmp("jwk", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert")))) {
                        mods[i]->mod_values[index_scope] = json_dumps(j_property_value, JSON_COMPACT);
                      } else {
                        mods[i]->mod_values[index_scope] = (char *)json_string_value(j_property_value);
                      }
                    }
                    mods[i]->mod_values[json_array_size(j_property)] = NULL;
                    if (0 == o_strcmp("base64", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert"))) || 0 == o_strcmp("jwk", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert")))) {
                      json_array_append_new(j_mod_value_free_array, json_integer(i));
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (%s)", json_string_value(json_object_get(j_format, "property")), i);
                    has_error = 1;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (%s)", json_string_value(json_object_get(j_format, "property")), i);
                  has_error = 1;
                }
              } else if (json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "multiple") != json_true()) {
                mods[i] = o_malloc(sizeof(LDAPMod));
                if (mods[i] != NULL) {
                  mods[i]->mod_values = o_malloc(2 * sizeof(char *));
                  if (mods[i]->mod_values != NULL) {
                    mods[i]->mod_op = add?LDAP_MOD_ADD:LDAP_MOD_REPLACE;
                    mods[i]->mod_type = (char *)json_string_value(json_object_get(j_format, "property"));
                    if (0 == o_strcmp("base64", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert")))) {
                      if (o_base64_decode((const unsigned char *)json_string_value(j_property), json_string_length(j_property), NULL, &value_enc_len)) {
                        if ((value_enc = o_malloc(value_enc_len+1)) != NULL) {
                          if (o_base64_decode((const unsigned char *)json_string_value(j_property), json_string_length(j_property), value_enc, &value_enc_len)) {
                            value_enc[value_enc_len] = '\0';
                            mods[i]->mod_values[0] = (char *)value_enc;
                          } else {
                            y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error o_base64_decode for LDAP property '%s' (2-2)", json_string_value(j_property));
                            has_error = 1;
                          }
                        } else {
                          y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for value_enc (2)");
                        }
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error o_base64_decode for LDAP property '%s' (2-1)", json_string_value(j_property));
                        has_error = 1;
                      }
                      json_array_append_new(j_mod_value_free_array, json_integer(i));
                    } else if (0 == o_strcmp("jwk", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert")))) {
                      mods[i]->mod_values[0] = json_dumps(j_property, JSON_COMPACT);
                      json_array_append_new(j_mod_value_free_array, json_integer(i));
                    } else {
                      mods[i]->mod_values[0] = (char *)json_string_value(j_property);
                    }
                    mods[i]->mod_values[1] = NULL;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d]->mod_values (%s)", json_string_value(json_object_get(j_format, "property")), i);
                    has_error = 1;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error allocating resources for mods[%d] (%s)", json_string_value(json_object_get(j_format, "property")), i);
                  has_error = 1;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_WARNING, "get_ldap_write_mod - Error field '%s' has invalid format", field);
              }
              i++;
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
      json_array_foreach(j_mod_value_free_array, index, j_property) {
        for (i=0; mods[json_integer_value(j_property)]->mod_values[i] != NULL; i++) {
          o_free(mods[json_integer_value(j_property)]->mod_values[i]);
        }
      }
      for (i=0; i<nb_attr; i++) {
        o_free(mods[i]);
      }
      o_free(mods);
      mods = NULL;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_ldap_write_mod - Error j_mod_value_free_array is NULL");
  }
  return mods;
}

static json_t * get_scope_from_ldap(json_t * j_params, const char * ldap_scope_value) {
  json_t * j_element = NULL;
  const char * key = NULL, * value;
  
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

static json_t * get_client_from_result(json_t * j_params, json_t * j_properties_client, LDAP * ldap, LDAPMessage * entry) {
  json_t * j_client = json_object(), * j_property = NULL, * j_scope;
  const char * field = NULL;
  char * str_scope;
  struct berval ** result_values = NULL;
  int i;
  unsigned char * value_enc = NULL;
  size_t value_enc_len = 0;
  
  if (j_client != NULL) {
    json_object_foreach(j_properties_client, field, j_property) {
      result_values = ldap_get_values_len(ldap, entry, json_string_value(j_property));
      if (ldap_count_values_len(result_values) > 0) {
        if (0 == o_strcmp(field, "scope")) {
          json_object_set_new(j_client, field, json_array());
          for (i=0; i<ldap_count_values_len(result_values); i++) {
            str_scope = o_strndup(result_values[i]->bv_val, result_values[i]->bv_len);
            j_scope = get_scope_from_ldap(j_params, str_scope);
            o_free(str_scope);
            if (j_scope != NULL) {
              json_array_append_new(json_object_get(j_client, field), j_scope);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_client_from_result - Error get_scope_from_ldap");
            }
          }
        } else if (0 == o_strcmp(field, "client_id") || 0 == o_strcmp(field, "name") || 0 == o_strcmp(field, "description") || (json_object_get(json_object_get(j_params, "data-format"), field) != NULL && json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "multiple") != json_true())) {
          if (0 == o_strcmp("base64", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert")))) {
            if (o_base64_encode((const unsigned char *)result_values[0]->bv_val, result_values[0]->bv_len, NULL, &value_enc_len)) {
              if ((value_enc = o_malloc(value_enc_len+1)) != NULL) {
                if (o_base64_encode((const unsigned char *)result_values[0]->bv_val, result_values[0]->bv_len, value_enc, &value_enc_len)) {
                  value_enc[value_enc_len] = '\0';
                  json_object_set_new(j_client, field, json_stringn((const char *)value_enc, value_enc_len));
                } else {
                  y_log_message(Y_LOG_LEVEL_WARNING, "get_client_from_result - Error o_base64_encode for LDAP property '%s' (2)", json_string_value(j_property));
                }
                o_free(value_enc);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_client_from_result - Error allocating resources for value_enc");
              }
            } else {
              y_log_message(Y_LOG_LEVEL_WARNING, "get_client_from_result - Error o_base64_encode for LDAP property '%s' (1)", json_string_value(j_property));
            }
          } else if (0 == o_strcmp("jwk", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert")))) {
            if (json_object_set_new(j_client, field, json_loads(result_values[0]->bv_val, JSON_DECODE_ANY, NULL))) {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_client_from_result - Error parsing value into JSON");
            }
          } else {
            json_object_set_new(j_client, field, json_stringn(result_values[0]->bv_val, result_values[0]->bv_len));
          }
        } else if (0 == o_strcmp(field, "confidential")) {
          json_object_set_new(j_client, field, (result_values[0]->bv_val[0]=='1'?json_true():json_false()));
        } else if (json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "multiple") == json_true()) {
          json_object_set_new(j_client, field, json_array());
          for (i=0; i<ldap_count_values_len(result_values); i++) {
            if (0 == o_strcmp("base64", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert")))) {
              if (o_base64_encode((const unsigned char *)result_values[i]->bv_val, result_values[i]->bv_len, NULL, &value_enc_len)) {
                if ((value_enc = o_malloc(value_enc_len+1)) != NULL) {
                  if (o_base64_encode((const unsigned char *)result_values[i]->bv_val, result_values[i]->bv_len, value_enc, &value_enc_len)) {
                    value_enc[value_enc_len] = '\0';
                    json_array_append_new(json_object_get(j_client, field), json_stringn((const char *)value_enc, value_enc_len));
                  } else {
                    y_log_message(Y_LOG_LEVEL_WARNING, "get_client_from_result - Error o_base64_encode for LDAP property '%s' (2)", json_string_value(j_property));
                  }
                  o_free(value_enc);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "get_client_from_result - Error allocating resources for value_enc");
                }
              } else {
                y_log_message(Y_LOG_LEVEL_WARNING, "get_client_from_result - Error o_base64_encode for LDAP property '%s' (1)", json_string_value(j_property));
              }
            } else if (0 == o_strcmp("jwk", json_string_value(json_object_get(json_object_get(json_object_get(j_params, "data-format"), field), "convert")))) {
              if (json_array_append_new(json_object_get(j_client, field), json_loads(result_values[i]->bv_val, JSON_DECODE_ANY, NULL))) {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_client_from_result - Error parsing value into JSON");
              }
            } else {
              json_array_append_new(json_object_get(j_client, field), json_stringn(result_values[i]->bv_val, result_values[i]->bv_len));
            }
          }
        }
      }
      // A ldap client is always enabled, until I find a standard way to do it
      json_object_set_new(j_client, "enabled", json_true());
      ldap_value_free_len(result_values);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_client_from_result - Error allocating resources for j_client");
  }
  return j_client;
}

static char * get_client_dn_from_client_id(json_t * j_params, LDAP * ldap, const char * client_id) {
  char * client_dn, * filter;
  int  result;
  char * attrs[]      = {NULL};
  int  attrsonly      = 0;
  LDAPMessage * answer = NULL, * entry;
  char * str_result = NULL;
  int  scope = LDAP_SCOPE_ONELEVEL;
  
  if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_SUBTREE;
  } else if (0 == o_strcmp(json_string_value(json_object_get(j_params, "search-scope")), "subtree")) {
    scope = LDAP_SCOPE_CHILDREN;
  }
  filter = msprintf("(&(%s)(%s=%s))", json_string_value(json_object_get(j_params, "filter")), get_read_property(j_params, "client_id-property"), client_id);
  if ((result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_client_dn_from_client_id - Error ldap search, base search: %s, filter, error message: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(result));
  } else {
    if (ldap_count_entries(ldap, answer) > 0) {
      entry = ldap_first_entry(ldap, answer);
      client_dn = ldap_get_dn(ldap, entry);
      str_result = o_strdup(client_dn);
      ldap_memfree(client_dn);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_client_dn_from_client_id - Error client_id not found '%s'", client_id);
    }
    ldap_msgfree(answer);
  }
  o_free(filter);
  return str_result;
}

json_t * client_module_load(struct config_module * config) {
  UNUSED(config);
  return json_pack("{si ss ss ss s{ s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s[{s{ssso} s{ssso} s{sssos[ssss]}}] s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{sssos[sssss]} s{ssso} s{s{s{ssso} s{ssso} s{ssso} s{ssso} s{ssso}}}}}",
                   "result",
                   G_OK,
                   
                   "name",
                   "ldap",
                   
                   "display_name",
                   "LDAP backend client module",
                   
                   "description",
                   "Module to store clients in a LDAP server",
                   
                   "parameters",
                     "uri",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       
                     "bind-dn",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       
                     "bind-password",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       
                     "base-search",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       
                     "filter",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       
                     "client_id-property",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       
                     "scope-property",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       
                     "page-size",
                       "type",
                       "number",
                       "mandatory",
                       json_false(),
                       
                     "search-scope",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                       
                     "scope-match",
                       "ldap-value",
                         "type",
                         "string",
                         "mandatory",
                         json_true(),
                         
                       "scope-value",
                         "type",
                         "string",
                         "mandatory",
                         json_true(),
                         
                       "match",
                         "type",
                         "list",
                         "mandatory",
                         json_true(),
                         "values",
                           "equals",
                           "contains",
                           "startswith",
                           "endswith",
                           
                     "name-property",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                       
                     "description-property",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                       
                     "confidential-property",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                       
                     "rdn-property",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                       
                     "password-property",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                       
                     "password-algorithm",
                       "type",
                       "list",
                       "mandatory",
                       json_false(),
                       "values",
                         "SSHA",
                         "SHA",
                         "SMS5",
                         "MD5",
                         "PLAIN",
                         
                     "object-class",
                       "type",
                       "string",
                       "mandatory",
                       json_false(),
                       
                     "data-format",
                       "field-name",
                         "multiple",
                           "type",
                           "boolean",
                           "default",
                           json_false(),
                           
                         "read",
                           "type",
                           "boolean",
                           "default",
                           json_true(),
                           
                         "write",
                           "type",
                           "boolean",
                           "default",
                           json_true(),
                           
                         "profile-read",
                           "type",
                           "boolean",
                           "default",
                           json_false(),
                           
                         "profile-write",
                           "type",
                           "boolean",
                           "default",
                           json_false());
}

int client_module_unload(struct config_module * config) {
  UNUSED(config);
  return G_OK;
}

json_t * client_module_init(struct config_module * config, int readonly, json_t * j_parameters, void ** cls) {
  UNUSED(config);
  json_t * j_properties, * j_return;
  char * error_message;
  
  j_properties = is_client_ldap_parameters_valid(j_parameters, readonly);
  if (check_result_value(j_properties, G_OK)) {
    *cls = json_incref(j_parameters);
    j_return = json_pack("{si}", "result", G_OK);
  } else if (check_result_value(j_properties, G_ERROR_PARAM)) {
    error_message = json_dumps(json_object_get(j_properties, "error"), JSON_COMPACT);
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_init database - Error parsing parameters");
    y_log_message(Y_LOG_LEVEL_ERROR, error_message);
    o_free(error_message);
    j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", json_object_get(j_properties, "error"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_init database - Error is_client_database_parameters_valid");
    j_return = json_pack("{sis[s]}", "result", G_ERROR, "error", "internal error");
  }
  json_decref(j_properties);
  return j_return;
}

int client_module_close(struct config_module * config, void * cls) {
  UNUSED(config);
  json_decref((json_t *)cls);
  return G_OK;
}

size_t client_module_count_total(struct config_module * config, const char * pattern, void * cls) {
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
      y_log_message(Y_LOG_LEVEL_ERROR, "client_module_count_total ldap - Error ldap search, base search: %s, filter: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(result));
    } else {
      counter = ldap_count_entries(ldap, answer);
    }
    ldap_msgfree(answer);
    ldap_unbind_ext(ldap, NULL, NULL);
    o_free(filter);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_count_total ldap - Error connect_ldap_server");
  }
  return counter;
}

json_t * client_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls, * j_properties_client = NULL, * j_client_list, * j_client, * j_return;
  LDAP * ldap = connect_ldap_server(j_params);
  LDAPMessage * entry;
  
  int  ldap_result;
  int  scope = LDAP_SCOPE_ONELEVEL;
  char * filter = NULL;
  char ** attrs = NULL;
  int  attrsonly = 0;

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
    attrs = get_ldap_read_attributes(j_params, 0, (j_properties_client = json_object()));
    j_client_list = json_array();
    do {
      ldap_result = ldap_create_page_control(ldap, json_integer_value(json_object_get(j_params, "page-size")), cookie, 0, &page_control);
      if (ldap_result != LDAP_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get_list ldap - Error ldap_create_page_control, message: %s", ldap_err2string(ldap_result));
        break;
      }
      
      search_controls[0] = page_control;
      ldap_result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, search_controls, NULL, NULL, 0, &l_result);
      if ((ldap_result != LDAP_SUCCESS) & (ldap_result != LDAP_PARTIAL_RESULTS)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get_list ldap - Error ldap search, base search: %s, filter: %s, error message: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(ldap_result));
        break;
      }
      
      ldap_result = ldap_parse_result(ldap, l_result, &l_errcode, NULL, NULL, NULL, &returned_controls, 0);
      if (ldap_result != LDAP_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get_list ldap - Error ldap_parse_result, message: %s", ldap_err2string(ldap_result));
        break;
      }
      
      if (cookie != NULL) {
        ber_bvfree(cookie);
        cookie = NULL;
      }
      
      if (returned_controls != NULL) {
        ldap_result = ldap_parse_pageresponse_control(ldap, *returned_controls, &total_count, &new_cookie);
        if (ldap_result != LDAP_SUCCESS) {
          y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get_list ldap - Error ldap_parse_pageresponse_control, message: %s", ldap_err2string(ldap_result));
          break;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get_list ldap - Error returned_controls is NULL");
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
        y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get_list ldap - Error ber_malloc returned NULL");
        break;
      }
      
      if (returned_controls != NULL) {
        ldap_controls_free(returned_controls);
        returned_controls = NULL;
      }
      search_controls[0] = NULL;
      ldap_control_free(page_control);
      page_control = NULL;
      
      entry = ldap_first_entry(ldap, l_result);
      for (;entry !=NULL && offset > 0; entry = ldap_next_entry(ldap, entry)) {
        offset--;
      }
      
      while (entry != NULL && limit) {
        j_client = get_client_from_result(j_params, j_properties_client, ldap, entry);
        if (j_client != NULL) {
          json_array_append_new(j_client_list, j_client);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get_list ldap - Error get_client_from_result");
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
    
    ldap_unbind_ext(ldap, NULL, NULL);
    j_return = json_pack("{sisO}", "result", G_OK, "list", j_client_list);
    json_decref(j_client_list);
    json_decref(j_properties_client);
    o_free(attrs);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get_list ldap - Error connect_ldap_server");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

json_t * client_module_get(struct config_module * config, const char * client_id, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls, * j_properties_client = NULL, * j_client, * j_return;
  LDAP * ldap = connect_ldap_server(j_params);
  LDAPMessage * entry, * answer;
  int ldap_result;
  
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
    filter = msprintf("(&(%s)(%s=%s))", json_string_value(json_object_get(j_params, "filter")), get_read_property(j_params, "client_id-property"), client_id);
    attrs = get_ldap_read_attributes(j_params, 0, (j_properties_client = json_object()));
    if ((ldap_result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get ldap - Error ldap search, base search: %s, filter: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(ldap_result));
      j_return = json_pack("{si}", "result", G_ERROR);
    } else {
      // Looping in results, staring at offset, until the end of the list
      if (ldap_count_entries(ldap, answer) > 0) {
        entry = ldap_first_entry(ldap, answer);
        j_client = get_client_from_result(j_params, j_properties_client, ldap, entry);
        if (j_client != NULL) {
          j_return = json_pack("{sisO}", "result", G_OK, "client", j_client);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get_list ldap - Error get_client_from_result");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_client);
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
    }
    
    json_decref(j_properties_client);
    o_free(attrs);
    o_free(filter);
    ldap_msgfree(answer);
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_get_list ldap - Error connect_ldap_server");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

json_t * client_module_is_valid(struct config_module * config, const char * client_id, json_t * j_client, int mode, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls;
  json_t * j_result = json_array(), * j_element, * j_format, * j_value, * j_return, * j_cur_client;
  char * message;
  size_t index = 0, len = 0;
  const char * property;
  
  if (j_result != NULL) {
    if (mode == GLEWLWYD_IS_VALID_MODE_ADD) {
      if (!json_is_string(json_object_get(j_client, "client_id")) || !json_string_length(json_object_get(j_client, "client_id"))) {
        json_array_append_new(j_result, json_string("client_id is mandatory and must be a non empty string"));
      } else {
        j_cur_client = client_module_get(config, json_string_value(json_object_get(j_client, "client_id")), cls);
        if (check_result_value(j_cur_client, G_OK)) {
          json_array_append_new(j_result, json_string("client_id already exist"));
        } else if (!check_result_value(j_cur_client, G_ERROR_NOT_FOUND)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "client_module_is_valid database - Error client_module_get");
        }
        json_decref(j_cur_client);
      }
    } else if ((mode == GLEWLWYD_IS_VALID_MODE_UPDATE || mode == GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE) && client_id == NULL) {
      json_array_append_new(j_result, json_string("client_id is mandatory on update mode"));
    }
    if (mode != GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE && json_object_get(j_client, "scope") != NULL) {
      if (!json_is_array(json_object_get(j_client, "scope"))) {
        json_array_append_new(j_result, json_string("scope must be a JSON array of string"));
      } else {
        json_array_foreach(json_object_get(j_client, "scope"), index, j_element) {
          if (!json_is_string(j_element) || !json_string_length(j_element)) {
            json_array_append_new(j_result, json_string("scope must be a JSON array of string"));
          }
        }
      }
    }
    if (mode != GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE && json_object_get(j_client, "password") != NULL && !json_is_string(json_object_get(j_client, "password"))) {
      json_array_append_new(j_result, json_string("password must be a string"));
    }
    if (json_object_get(j_client, "name") != NULL && (!json_is_string(json_object_get(j_client, "name")) || !json_string_length(json_object_get(j_client, "name")))) {
      json_array_append_new(j_result, json_string("name must be a non empty string"));
    }
    if (json_object_get(j_client, "description") != NULL && (!json_is_string(json_object_get(j_client, "description")) || !json_string_length(json_object_get(j_client, "description")))) {
      json_array_append_new(j_result, json_string("description must be a non empty string"));
    }
    if (json_object_get(j_client, "enabled") != NULL && !json_is_boolean(json_object_get(j_client, "enabled"))) {
      json_array_append_new(j_result, json_string("enabled must be a boolean"));
    }
    if (json_object_get(j_client, "confidential") != NULL && !json_is_boolean(json_object_get(j_client, "confidential"))) {
      json_array_append_new(j_result, json_string("confidential must be a boolean"));
    }
    json_object_foreach(j_client, property, j_element) {
      if (0 != o_strcmp(property, "client_id") && 
          0 != o_strcmp(property, "name") && 
          0 != o_strcmp(property, "description") && 
          0 != o_strcmp(property, "enabled") && 
          0 != o_strcmp(property, "confidential") && 
          0 != o_strcmp(property, "password") &&
          0 != o_strcmp(property, "client_secret") && 
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
              if ((!json_is_string(j_value) || !json_string_length(j_value)) && 0 != o_strcmp("jwk", json_string_value(json_object_get(j_format, "convert")))) {
                message = msprintf("%s must contain a non empty string value", property);
                json_array_append_new(j_result, json_string(message));
                o_free(message);
              } else if (0 == o_strcmp("base64", json_string_value(json_object_get(j_format, "convert")))) {
                if (!o_base64_decode((const unsigned char *)json_string_value(j_value), json_string_length(j_value), NULL, &len)) {
                  message = msprintf("%s must contain a base64 encoded string value", property);
                  json_array_append_new(j_result, json_string(message));
                  o_free(message);
                }
              }
            }
          }
        } else {
          if (!json_is_string(j_element) && 0 != o_strcmp("jwk", json_string_value(json_object_get(j_format, "convert")))) {
            message = msprintf("%s must contain a string value", property);
            json_array_append_new(j_result, json_string(message));
            o_free(message);
          } else if (0 == o_strcmp("base64", json_string_value(json_object_get(j_format, "convert"))) && json_string_length(j_element)) {
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
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_is_valid ldap - Error allocating resources for j_result");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

int client_module_add(struct config_module * config, json_t * j_client, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls, * j_mod_value_free_array = NULL, * j_element = NULL;
  LDAP * ldap = connect_ldap_server(j_params);
  int ret, i, result;
  LDAPMod ** mods = NULL;
  char * new_dn;
  size_t index = 0;
  
  if (ldap != NULL) {
    mods = get_ldap_write_mod(j_params, j_client, 1, (j_mod_value_free_array = json_array()));
    if (mods != NULL) {
      new_dn = msprintf("%s=%s,%s", json_string_value(json_object_get(j_params, "rdn-property")), json_string_value(json_object_get(j_client, "client_id")), json_string_value(json_object_get(j_params, "base-search")));
      if (new_dn != NULL) {
        if ((result = ldap_add_ext_s(ldap, new_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
          y_log_message(Y_LOG_LEVEL_ERROR, "client_module_add ldap - Error adding new client %s in the ldap backend: %s", new_dn, ldap_err2string(result));
          ret = G_ERROR;
        } else {
          ret = G_OK;
        }
        o_free(new_dn);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "client_module_add ldap - Error allocating resources for new_dn");
        ret = G_ERROR;
      }
      json_array_foreach(j_mod_value_free_array, index, j_element) {
        for (i=0; mods[json_integer_value(j_element)]->mod_values[i] != NULL; i++) {
          o_free(mods[json_integer_value(j_element)]->mod_values[i]);
        }
      }
      json_decref(j_mod_value_free_array);
      for (i=0; mods[i] != NULL; i++) {
        o_free(mods[i]->mod_values);
        o_free(mods[i]);
      }
      o_free(mods);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_module_add ldap - Error get_ldap_write_mod");
      ret = G_ERROR;
    }
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_add ldap - Error connect_ldap_server");
    ret = G_ERROR;
  }
  return ret;
}

int client_module_update(struct config_module * config, const char * client_id, json_t * j_client, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls, * j_mod_value_free_array, * j_element = NULL;
  LDAP * ldap = connect_ldap_server(j_params);
  int ret, i, result;
  LDAPMod ** mods = NULL;
  char * cur_dn;
  size_t index = 0;
  
  if (ldap != NULL) {
    mods = get_ldap_write_mod(j_params, j_client, 0, (j_mod_value_free_array = json_array()));
    if (mods != NULL) {
      cur_dn = get_client_dn_from_client_id(j_params, ldap, client_id);
      if (cur_dn != NULL) {
        if ((result = ldap_modify_ext_s(ldap, cur_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
          y_log_message(Y_LOG_LEVEL_ERROR, "client_module_update ldap - Error updating client %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
          ret = G_ERROR;
        } else {
          ret = G_OK;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "client_module_update ldap - Error get_client_dn_from_client_id");
        ret = G_ERROR;
      }
      o_free(cur_dn);
      json_array_foreach(j_mod_value_free_array, index, j_element) {
        for (i=0; mods[json_integer_value(j_element)]->mod_values[i] != NULL; i++) {
          o_free(mods[json_integer_value(j_element)]->mod_values[i]);
        }
      }
      json_decref(j_mod_value_free_array);
      for (i=0; mods[i] != NULL; i++) {
        o_free(mods[i]->mod_values);
        o_free(mods[i]);
      }
      o_free(mods);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_module_update ldap - Error get_ldap_write_mod");
      ret = G_ERROR;
    }
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_update ldap - Error connect_ldap_server");
    ret = G_ERROR;
  }
  return ret;
}

int client_module_delete(struct config_module * config, const char * client_id, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls;
  LDAP * ldap = connect_ldap_server(j_params);
  int ret, result;
  char * cur_dn;
  
  if (ldap != NULL) {
    cur_dn = get_client_dn_from_client_id(j_params, ldap, client_id);
    if (cur_dn != NULL) {
      if ((result = ldap_delete_ext_s(ldap, cur_dn, NULL, NULL)) != LDAP_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "client_module_delete ldap - Error deleting client %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
        ret = G_ERROR;
      } else {
        ret = G_OK;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_module_update ldap - Error get_client_dn_from_client_id");
      ret = G_ERROR;
    }
    o_free(cur_dn);
    ldap_unbind_ext(ldap, NULL, NULL);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_update ldap - Error connect_ldap_server");
    ret = G_ERROR;
  }
  return ret;
}

int client_module_check_password(struct config_module * config, const char * client_id, const char * password, void * cls) {
  UNUSED(config);
  json_t * j_params = (json_t *)cls;
  LDAP * ldap = connect_ldap_server(j_params);
  LDAPMessage * entry, * answer;
  int ldap_result, result_login, result;
  char * client_dn = NULL;
  
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
    filter = msprintf("(&(%s)(%s=%s))", json_string_value(json_object_get(j_params, "filter")), get_read_property(j_params, "client_id-property"), client_id);
    if ((ldap_result = ldap_search_ext_s(ldap, json_string_value(json_object_get(j_params, "base-search")), scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_module_check_password ldap - Error ldap search, base search: %s, filter: %s: %s", json_string_value(json_object_get(j_params, "base-search")), filter, ldap_err2string(ldap_result));
      result = G_ERROR;
    } else {
      if (ldap_count_entries(ldap, answer) > 0) {
        // Testing the first result to client_id with the given password
        entry = ldap_first_entry(ldap, answer);
        client_dn = ldap_get_dn(ldap, entry);
        cred.bv_val = (char *)password;
        cred.bv_len = o_strlen(password);
        result_login = ldap_sasl_bind_s(ldap, client_dn, ldap_mech, &cred, NULL, NULL, &servcred);
        ldap_memfree(client_dn);
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
    y_log_message(Y_LOG_LEVEL_ERROR, "client_module_check_password ldap - Error connect_ldap_server");
    result = G_ERROR;
  }
  return result;
}

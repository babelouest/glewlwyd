/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * Provides Json Web Tokens (jwt)
 * 
 * client CRUD services
 *
 * Copyright 2016-2017 Nicolas Mora <mail@babelouest.org>
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
#include <ldap.h>
#include <string.h>

#include "glewlwyd.h"

/**
 * Check client credentials
 * If client_id_header is set, client must be confidential and password must match
 * otherwise client is public
 */
json_t * client_check(struct config_elements * config, const char * client_id, const char * client_id_header, const char * client_password_header, const char * redirect_uri, const int auth_type) {
  json_t * j_res = NULL, * j_client = NULL, * j_auth, * j_element;
  size_t index;
  int redirect_uri_allowed = 1, auth_type_allowed = 0;
  const char * auth_type_str;
  
  // First, check if client_id exist and is valid
  if (client_id != NULL) {
    j_client = get_client(config, client_id, NULL);
    if (check_result_value(j_client, G_OK)) {
      // If client is confidential and auth type can require credentials, check its credentials
      if (json_object_get(json_object_get(j_client, "client"), "confidential") == json_true() && 
          (auth_type == GLEWLWYD_AUHORIZATION_TYPE_CODE ||
          auth_type == GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS ||
          auth_type == GLEWLWYD_AUHORIZATION_TYPE_CLIENT_CREDENTIALS ||
          auth_type == GLEWLWYD_AUHORIZATION_TYPE_REFRESH_TOKEN)) {
        if (o_strcmp(client_id, client_id_header) != 0) {
          j_res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        } else {
          j_auth = auth_check_client_credentials(config, client_id_header, client_password_header);
          if (!check_result_value(j_auth, G_OK)) {
            j_res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          }
          json_decref(j_auth);
        }
      }
      // if no error occured, continue
      if (j_res == NULL) {

        // Check if auth_type is allowed
        switch (auth_type) {
          case GLEWLWYD_AUHORIZATION_TYPE_AUTHORIZATION_CODE:
            auth_type_str = "authorization_code";
            break;
          case GLEWLWYD_AUHORIZATION_TYPE_CODE:
            auth_type_str = "code";
            break;
          case GLEWLWYD_AUHORIZATION_TYPE_IMPLICIT:
            auth_type_str = "token";
            break;
          case GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS:
            auth_type_str = "password";
            break;
          case GLEWLWYD_AUHORIZATION_TYPE_CLIENT_CREDENTIALS:
            auth_type_str = "client_credentials";
            break;
          default:
            auth_type_str = "";
            break;
        }
        json_array_foreach(json_object_get(json_object_get(j_client, "client"), "authorization_type"), index, j_element) {
          if (o_strcmp(json_string_value(j_element), auth_type_str)) {
            auth_type_allowed = 1;
          }
        }
        
        if (auth_type == GLEWLWYD_AUHORIZATION_TYPE_AUTHORIZATION_CODE || auth_type == GLEWLWYD_AUHORIZATION_TYPE_CODE || auth_type == GLEWLWYD_AUHORIZATION_TYPE_IMPLICIT) {
          // Check redirect_uri if auth type requires it
          if (redirect_uri != NULL) {
            redirect_uri_allowed = 0;
            json_array_foreach(json_object_get(json_object_get(j_client, "client"), "redirect_uri"), index, j_element) {
              if (0 == o_strcmp(json_string_value(json_object_get(j_element, "uri")), redirect_uri)) {
                redirect_uri_allowed = 1;
              }
            }
          }
        }
        
        // Final check, is everything ok?
        if (!redirect_uri_allowed || !auth_type_allowed) {
          j_res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        } else {
          j_res = json_pack("{siso}", "result", G_OK, "client", json_copy(json_object_get(j_client, "client")));
        }
      }
    } else {
      j_res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
    json_decref(j_client);
  } else {
    j_res = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  
  return j_res;
}

/**
 * Check client credentials
 */
json_t * auth_check_client_credentials(struct config_elements * config, const char * client_id, const char * password) {
  json_t * j_res = NULL;
  
  if (client_id != NULL && password != NULL) {
    if (config->has_auth_ldap) {
      j_res = auth_check_client_credentials_ldap(config, client_id, password);
    }
    if (config->has_auth_database && !check_result_value(j_res, G_OK)) {
      json_decref(j_res);
      j_res = auth_check_client_credentials_database(config, client_id, password);
    }
    if (config->has_auth_http && !check_result_value(j_res, G_OK)) {
      json_decref(j_res);
      j_res = auth_check_client_credentials_http(config, client_id, password);
    }
  } else {
    j_res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  return j_res;
}

/**
 * Check client credentials in http backend
 */
json_t * auth_check_client_credentials_http(struct config_elements * config, const char * client_id, const char * password) {
  int res, res_status, to_return;
  struct _u_response response;
  struct _u_request request;

  if (client_id != NULL && password != NULL) {
    ulfius_init_request(&request);
    request.http_verb = o_strdup("GET");
    request.http_url = o_strdup(config->auth_http->url);
    request.auth_basic_user = o_strdup(client_id);
    request.auth_basic_password = o_strdup(password);
    ulfius_init_response(&response);
    res = ulfius_send_http_request(&request, &response);
    res_status = response.status;
    ulfius_clean_response(&response);
    ulfius_clean_request(&request);
    if (res == U_OK) {
      to_return = res_status==200?G_OK:G_ERROR_UNAUTHORIZED;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_auth - Error querying authentication server");
      to_return = G_ERROR_UNAUTHORIZED;
    }
  } else {
    to_return = G_ERROR_UNAUTHORIZED;
  }
  return json_pack("{si}", "result", to_return);
}

/**
 * Check client credentials in database backend
 */
json_t * auth_check_client_credentials_database(struct config_elements * config, const char * client_id, const char * password) {
  json_t * j_query, * j_result;
  int res, to_return;
  char * client_id_escaped, * client_password_escaped, * clause_client_password, * clause_client_authorization_type;
  
  if (client_id != NULL && password != NULL) {
    client_id_escaped = h_escape_string(config->conn, client_id);
    clause_client_authorization_type = msprintf("IN (SELECT `gc_client_id` FROM `%s` WHERE `gc_client_id` = '%s' and `got_id` = (SELECT `got_id` FROM `%s` WHERE `got_code` = %d))", GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE, client_id_escaped, GLEWLWYD_TABLE_AUTHORIZATION_TYPE, GLEWLWYD_AUHORIZATION_TYPE_CLIENT_CREDENTIALS);
    if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
      client_password_escaped = h_escape_string(config->conn, password);
      clause_client_password = msprintf("= PASSWORD('%s')", client_password_escaped);
    } else {
      client_password_escaped = generate_hash(config, config->hash_algorithm, password);
      clause_client_password = msprintf("= '%s'", client_password_escaped);
    }
    
    j_query = json_pack("{sss[s]s{sss{ssss}sisis{ssss}}}",
                        "table",
                        GLEWLWYD_TABLE_CLIENT,
                        "columns",
                          "gc_id",
                        "where",
                          "gc_client_id",
                          client_id,
                          "gc_client_password",
                            "operator",
                            "raw",
                            "value",
                            clause_client_password,
                          "gc_enabled",
                          1,
                          "gc_confidential",
                          1,
                          "gc_client_id",
                            "operator",
                            "raw",
                            "value",
                            clause_client_authorization_type);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    o_free(clause_client_password);
    o_free(client_password_escaped);
    o_free(client_id_escaped);
    o_free(clause_client_authorization_type);
    if (res == H_OK) {
      to_return = json_array_size(j_result)>0?G_OK:G_ERROR_UNAUTHORIZED;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "client_auth - Error executing j_query");
      to_return = G_ERROR_DB;
    }
    json_decref(j_result);
  } else {
    to_return = G_ERROR_UNAUTHORIZED;
  }
  return json_pack("{si}", "result", to_return);
}

/**
 * Check client credentials in ldap backend
 */
json_t * auth_check_client_credentials_ldap(struct config_elements * config, const char * client_id, const char * password) {
  LDAP * ldap = NULL;
  LDAPMessage * answer = NULL, * entry;
  
  int  result, result_login;
  int  ldap_version   = LDAP_VERSION3;
  int  scope          = LDAP_SCOPE_ONELEVEL;
  char * filter       = NULL;
  char * attrs[]      = {"memberOf", NULL, NULL};
  int  attrsonly      = 0;
  char * user_dn      = NULL;
  json_t * res        = NULL;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred;
  struct berval *servcred;

  cred.bv_val = config->auth_ldap->bind_passwd;
  cred.bv_len = strlen(config->auth_ldap->bind_passwd);

  if (ldap_initialize(&ldap, config->auth_ldap->uri) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error initializing ldap");
    res = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error setting ldap protocol version");
    res = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if ((result = ldap_sasl_bind_s(ldap, config->auth_ldap->bind_dn, ldap_mech, &cred, NULL, NULL, &servcred)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error binding to ldap server mode %s: %s", ldap_mech, ldap_err2string(result));
    res = json_pack("{si}", "result", G_ERROR_PARAM);
  } else {
    // Connection successful, doing ldap search
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter_client_read, config->auth_ldap->client_id_property_client_read, client_id);
    
    if (config->use_scope) {
      attrs[1] = config->auth_ldap->scope_property_client_read;
    }
    if (filter != NULL && (result = ldap_search_ext_s(ldap, config->auth_ldap->base_search_client, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search: %s", ldap_err2string(result));
      res = json_pack("{si}", "result", G_ERROR_PARAM);
    } else if (ldap_count_entries(ldap, answer) == 0) {
      // No result found for username
      res = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else {
      // ldap found some results, getting the first one
      entry = ldap_first_entry(ldap, answer);
      
      if (entry == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "ldap search: error getting first result");
        res = json_pack("{si}", "result", G_ERROR);
      } else {
        // Testing the first result to username with the given password
        user_dn = ldap_get_dn(ldap, entry);
        cred.bv_val = (char *)password;
        cred.bv_len = strlen(password);
        result_login = ldap_sasl_bind_s(ldap, user_dn, ldap_mech, &cred, NULL, NULL, &servcred);
        ldap_memfree(user_dn);
        if (result_login == LDAP_SUCCESS) {
          res = json_pack("{si}", "result", G_OK);
        } else {
          res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
      }
    }
    o_free(filter);
    ldap_msgfree(answer);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  return res;
}

/**
 *
 * Check if user has allowed scope for client_id
 *
 */
int auth_check_client_user_scope(struct config_elements * config, const char * client_id, const char * username, const char * scope_list) {
  json_t * j_query, * j_result;
  int res, nb_scope = 0;
  char * scope, * escaped_scope, * escaped_scope_list = NULL, * save_scope_list, * saveptr = NULL, * tmp;
  char * scope_clause;
  
  save_scope_list = o_strdup(scope_list);
  scope = strtok_r(save_scope_list, " ", &saveptr);
  while (scope != NULL) {
    nb_scope++;
    escaped_scope = h_escape_string(config->conn, scope);
    if (escaped_scope_list == NULL)  {
      escaped_scope_list = msprintf("'%s'", escaped_scope);
    } else {
      tmp = msprintf("%s,'%s'", escaped_scope_list, escaped_scope);
      o_free(escaped_scope_list);
      escaped_scope_list = tmp;
    }
    o_free(escaped_scope);
    scope = strtok_r(NULL, " ", &saveptr);
  }
  o_free(save_scope_list);
  
  scope_clause = msprintf("IN (SELECT `gs_id` FROM `%s` WHERE `gs_name` IN (%s))", GLEWLWYD_TABLE_SCOPE, escaped_scope_list);
  j_query = json_pack("{sss[s]s{sssss{ssss}}}",
            "table",
            GLEWLWYD_TABLE_CLIENT_USER_SCOPE,
            "columns",
              "gcus_id",
            "where",
              "gco_username",
              username,
              "gc_client_id",
              client_id,
              "gs_id",
                "operator",
                "raw",
                "value",
                scope_clause
            );
  o_free(scope_clause);
  o_free(escaped_scope_list);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    nb_scope -= json_array_size(j_result);
    json_decref(j_result);
    return (nb_scope==0?G_OK:G_ERROR_UNAUTHORIZED);
  } else {
    return G_ERROR_DB;
  }
}

/**
 *
 * Check if client is allowed for the scope_list specified
 * Return a refined list of scope
 *
 */
json_t * auth_check_client_scope(struct config_elements * config, const char * client_id, const char * scope_list) {
  json_t * j_res = NULL;
  
  if (config->has_auth_ldap) {
    j_res = auth_check_client_scope_ldap(config, client_id, scope_list);
  }
  if (config->has_auth_database && (j_res == NULL || !check_result_value(j_res, G_OK))) {
    json_decref(j_res);
    j_res = auth_check_client_scope_database(config, client_id, scope_list);
  }
  if (config->has_auth_http && (j_res == NULL || !check_result_value(j_res, G_OK))) {
    json_decref(j_res);
    j_res = auth_check_client_scope_http(config, client_id, scope_list);
  }
  return j_res;
}

/**
 * Check if client is allowed for the scope_list specified in the http backend
 * As there is no scope available for this backend, just return an empty list
 */
json_t * auth_check_client_scope_http(struct config_elements * config, const char * client_id, const char * scope_list) {
  json_t * scope_list_allowed = NULL;

  return scope_list_allowed;
}

/**
 * Check if client is allowed for the scope_list specified in the database backend
 * Return a refined list of scope
 */
json_t * auth_check_client_scope_database(struct config_elements * config, const char * client_id, const char * scope_list) {
  json_t * j_query, * j_result, * scope_list_allowed, * j_value;
  int res;
  char * scope, * scope_escaped, * saveptr, * scope_list_escaped = NULL, * scope_list_save = o_strdup(scope_list), * client_id_escaped = h_escape_string(config->conn, client_id), * scope_list_join;
  char * where_clause, * tmp;
  size_t index;
  
  if (scope_list == NULL || client_id_escaped == NULL) {
    scope_list_allowed = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (scope_list_save != NULL && client_id_escaped != NULL) {
    scope = strtok_r(scope_list_save, " ", &saveptr);
    while (scope != NULL) {
      scope_escaped = h_escape_string(config->conn, scope);
      if (scope_list_escaped != NULL) {
        tmp = msprintf("%s,'%s'", scope_list_escaped, scope_escaped);
        o_free(scope_list_escaped);
        scope_list_escaped = tmp;
      } else {
        scope_list_escaped = msprintf("'%s'", scope_escaped);
      }
      o_free(scope_escaped);
      scope = strtok_r(NULL, " ", &saveptr);
    }
    o_free(scope_list_save);
    where_clause = msprintf("IN (SELECT gs_id FROM %s WHERE gc_id = (SELECT gc_id FROM %s WHERE gc_client_id='%s') AND gs_id IN (SELECT gs_id FROM %s WHERE gs_name IN (%s)))", GLEWLWYD_TABLE_CLIENT_SCOPE, GLEWLWYD_TABLE_CLIENT, client_id_escaped, GLEWLWYD_TABLE_SCOPE, scope_list_escaped);
    j_query = json_pack("{sss[s]s{s{ssss}}}",
              "table",
              GLEWLWYD_TABLE_SCOPE,
              "columns",
                "gs_name",
              "where",
                "gs_id",
                  "operator",
                  "raw",
                  "value",
                  where_clause);
    o_free(scope_list_escaped);
    o_free(where_clause);
    if (j_query != NULL) {
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result) > 0) {
          scope_list_join = strdup("");
          json_array_foreach(j_result, index, j_value) {
            if (o_strlen(scope_list_join) > 0) {
              tmp = msprintf("%s %s", scope_list_join, json_string_value(json_object_get(j_value, "gs_name")));
              o_free(scope_list_join);
              scope_list_join = tmp;
            } else {
              o_free(scope_list_join);
              scope_list_join = strdup(json_string_value(json_object_get(j_value, "gs_name")));
            }
          }
          scope_list_allowed = json_pack("{siss}", "result", G_OK, "scope", scope_list_join);
          o_free(scope_list_join);
        } else {
          scope_list_allowed = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_client_scope - Error executing sql query");
        scope_list_allowed = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_client_scope - Error allocating resources for j_query");
      scope_list_allowed = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_client_scope - Error allocating resources for scope_list_save %s or client_id_escaped %s or scope_list_escaped %s", scope_list_save, client_id_escaped, scope_list_escaped);
    scope_list_allowed = json_pack("{si}", "result", G_ERROR);
  }
  o_free(client_id_escaped);
  return scope_list_allowed;
}

/**
 *
 * Check if client is allowed for the scope_list specified in the ldap backend
 * Return a refined list of scope
 *
 */
json_t * auth_check_client_scope_ldap(struct config_elements * config, const char * client_id, const char * scope_list) {
  LDAP * ldap = NULL;
  LDAPMessage * answer = NULL, * entry;
  
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  int  scope          = LDAP_SCOPE_ONELEVEL;
  char * filter       = NULL;
  char * attrs[]      = {"memberOf", NULL, NULL};
  int  attrsonly      = 0;
  json_t * res        = NULL;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred;
  struct berval *servcred;

  cred.bv_val = config->auth_ldap->bind_passwd;
  cred.bv_len = strlen(config->auth_ldap->bind_passwd);

  if (ldap_initialize(&ldap, config->auth_ldap->uri) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error initializing ldap");
    res = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error setting ldap protocol version");
    res = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if ((result = ldap_sasl_bind_s(ldap, config->auth_ldap->bind_dn, ldap_mech, &cred, NULL, NULL, &servcred)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error binding to ldap server mode %s: %s", ldap_mech, ldap_err2string(result));
    res = json_pack("{si}", "result", G_ERROR_PARAM);
  } else {
    // Connection successful, doing ldap search
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter_client_read, config->auth_ldap->client_id_property_client_read, client_id);
    
    if (config->use_scope) {
      attrs[1] = config->auth_ldap->scope_property_client_read;
    }
    if (filter != NULL && (result = ldap_search_ext_s(ldap, config->auth_ldap->base_search_client, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search: %s", ldap_err2string(result));
      res = json_pack("{si}", "result", G_ERROR_PARAM);
    } else if (ldap_count_entries(ldap, answer) == 0) {
      // No result found for client_id
      res = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else {
      // ldap found some results, getting the first one
      entry = ldap_first_entry(ldap, answer);
      
      if (entry == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "ldap search: error getting first result");
        res = json_pack("{si}", "result", G_ERROR);
      } else {
        struct berval ** values = ldap_get_values_len(ldap, entry, config->auth_ldap->scope_property_client_read);
        char * new_scope_list = strdup("");
        int i;
        
        for (i=0; i < ldap_count_values_len(values); i++) {
          char * str_value = o_malloc(values[i]->bv_len + 1);
          char * scope_list_dup = strdup(scope_list);
          char * token, * save_ptr = NULL;
          
          snprintf(str_value, values[i]->bv_len + 1, "%s", values[i]->bv_val);
          token = strtok_r(scope_list_dup, " ", &save_ptr);
          while (token != NULL) {
            if (0 == strcmp(token, str_value)) {
              if (strlen(new_scope_list) > 0) {
                char * tmp = msprintf("%s %s", new_scope_list, token);
                o_free(new_scope_list);
                new_scope_list = tmp;
              } else {
                o_free(new_scope_list);
                new_scope_list = strdup(token);
              }
            }
            token = strtok_r(NULL, " ", &save_ptr);
          }
          o_free(scope_list_dup);
          o_free(str_value);
        }
        ldap_value_free_len(values);
        if (o_strlen(new_scope_list) > 0) {
          res = json_pack("{siss}", "result", G_OK, "scope", new_scope_list);
        } else {
          // Client hasn't all of part of the scope requested, sending unauthorized answer
          res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
        o_free(new_scope_list);
      }
    }
    o_free(filter);
    ldap_msgfree(answer);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  return res;
}

/**
 * Get a list of clients
 */
json_t * get_client_list(struct config_elements * config, const char * source, const char * search, long int offset, long int limit) {
  json_t * j_return, * j_source_list = NULL, * j_result_list = json_array();
  
  if (j_result_list != NULL) {
    if ((source == NULL || 0 == strcmp(source, "ldap") || 0 == strcmp(source, "all")) && config->has_auth_ldap) {
      j_source_list = get_client_list_ldap(config, search, offset, limit);
      if (check_result_value(j_source_list, G_OK)) {
        json_array_extend(j_result_list, json_object_get(j_source_list, "client"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error getting ldap list");
      }
      json_decref(j_source_list);
      j_source_list = NULL;
    }
    
    if ((source == NULL || 0 == strcmp(source, "database") || 0 == strcmp(source, "all")) && json_array_size(j_result_list) < limit && config->has_auth_database) {
      j_source_list = get_client_list_database(config, search, offset, (limit - json_array_size(j_result_list)));
      if (check_result_value(j_source_list, G_OK)) {
        json_array_extend(j_result_list, json_object_get(j_source_list, "client"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error getting database list");
      }
      json_decref(j_source_list);
      j_source_list = NULL;
    }
    
    if ((source == NULL || 0 == strcmp(source, "http") || 0 == strcmp(source, "all")) && config->has_auth_http) {
      j_source_list = get_client_list_http(config, search, offset, limit);
      if (check_result_value(j_source_list, G_OK)) {
        json_array_extend(j_result_list, json_object_get(j_source_list, "client"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error getting http list");
      }
      json_decref(j_source_list);
      j_source_list = NULL;
    }

    j_return = json_pack("{siso}", "result", G_OK, "client", j_result_list);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error allocating resources for j_result_list");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

/**
 * Get a list of clients in the ldap backend
 */
json_t * get_client_list_ldap(struct config_elements * config, const char * search, long int offset, long int limit) {
  LDAP * ldap = NULL;
  LDAPMessage * answer = NULL, * entry;
  int i, j, res;
  json_t * j_result, * j_scope_list = get_scope_list(config), * j_query, * j_auth_type, * j_cur_auth_type;
  char * client_clause, * client_id_escaped;
  size_t i_auth_type;
  
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  int  scope          = LDAP_SCOPE_ONELEVEL;
  char * filter       = NULL;
  char * attrs[]      = {config->auth_ldap->name_property_client_read, config->auth_ldap->description_property_client_read, config->auth_ldap->client_id_property_client_read, config->auth_ldap->scope_property_client_read, config->auth_ldap->redirect_uri_property_client_read, config->auth_ldap->confidential_property_client_read, NULL};
  int  attrsonly      = 0;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred;
  struct berval *servcred;

  cred.bv_val = config->auth_ldap->bind_passwd;
  cred.bv_len = strlen(config->auth_ldap->bind_passwd);
  
  if (!check_result_value(j_scope_list, G_OK)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error getting scope list");
    j_result = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (ldap_initialize(&ldap, config->auth_ldap->uri) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error initializing ldap");
    j_result = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error setting ldap protocol version");
    j_result = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if ((result = ldap_sasl_bind_s(ldap, config->auth_ldap->bind_dn, ldap_mech, &cred, NULL, NULL, &servcred)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error binding to ldap server mode %s: %s", ldap_mech, ldap_err2string(result));
    j_result = json_pack("{si}", "result", G_ERROR_PARAM);
  } else {
    // Connection successful, doing ldap search
    if (search != NULL && strcmp("", search) != 0) {
      char * search_escaped = escape_ldap(search);
      filter = msprintf("(&(%s)(|(%s=*%s*)(%s=*%s*)(%s=*%s*)))", 
                        config->auth_ldap->filter_client_read, 
                        config->auth_ldap->client_id_property_client_read, 
                        search_escaped,
                        config->auth_ldap->name_property_client_read, 
                        search_escaped,
                        config->auth_ldap->description_property_client_read, 
                        search_escaped);
      o_free(search_escaped);
    } else {
      filter = msprintf("(%s)", config->auth_ldap->filter_client_read);
    }
    if ((result = ldap_search_ext_s(ldap, config->auth_ldap->base_search_client, scope, filter, attrs, attrsonly, NULL, NULL, NULL, (offset+limit), &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search: %s", ldap_err2string(result));
      j_result = json_pack("{si}", "result", G_ERROR_PARAM);
    } else {
      // Looping in results, staring at offset, until the end of the list
      j_result = json_pack("{sis[]}", "result", G_OK, "client");
      if (ldap_count_entries(ldap, answer) >= offset) {
        entry = ldap_first_entry(ldap, answer);
            
        for (i=0; i<offset && entry != NULL; i++) {
          entry = ldap_next_entry(ldap, entry);
        }
        
        while (entry != NULL && i<(offset+limit)) {
          json_t * j_entry = json_object();
          
          if (j_entry != NULL) {
            struct berval ** name_values = ldap_get_values_len(ldap, entry, config->auth_ldap->name_property_client_read);
            struct berval ** description_values = ldap_get_values_len(ldap, entry, config->auth_ldap->description_property_client_read);
            struct berval ** client_id_values = ldap_get_values_len(ldap, entry, config->auth_ldap->client_id_property_client_read);
            struct berval ** scope_values = ldap_get_values_len(ldap, entry, config->auth_ldap->scope_property_client_read);
            struct berval ** redirect_uri_values = ldap_get_values_len(ldap, entry, config->auth_ldap->redirect_uri_property_client_read);
            struct berval ** confidential_values = ldap_get_values_len(ldap, entry, config->auth_ldap->confidential_property_client_read);
            
            if (ldap_count_values_len(name_values) > 0) {
              json_object_set_new(j_entry, "name", json_stringn(name_values[0]->bv_val, name_values[0]->bv_len));
            }
            
            if (ldap_count_values_len(description_values) > 0) {
              json_object_set_new(j_entry, "description", json_stringn(description_values[0]->bv_val, description_values[0]->bv_len));
            }
            
            if (ldap_count_values_len(client_id_values) > 0) {
              json_object_set_new(j_entry, "client_id", json_stringn(client_id_values[0]->bv_val, client_id_values[0]->bv_len));
            }
            
            // For now a ldap client is always enabled, until I find a standard way to do it
            json_object_set_new(j_entry, "enabled", json_true());
            
            json_object_set_new(j_entry, "scope", json_array());
            for (j=0; j < ldap_count_values_len(scope_values); j++) {
              json_t * j_scope = json_string(scope_values[j]->bv_val);
              if (json_search(json_object_get(j_scope_list, "scope"), j_scope) != NULL) {
                json_array_append_new(json_object_get(j_entry, "scope"), j_scope);
              } else {
                json_decref(j_scope);
              }
            }
            
            json_object_set_new(j_entry, "redirect_uri", json_array());
            for (j=0; j < ldap_count_values_len(redirect_uri_values); j++) {
              char * space_address = strchr(redirect_uri_values[j]->bv_val, ' ');
              if (space_address != NULL) {
                json_t * j_redirect_uri_uri = json_stringn(redirect_uri_values[j]->bv_val, (space_address - redirect_uri_values[j]->bv_val));
                json_t * j_redirect_uri_name = json_string(space_address+sizeof(char));
                json_t * j_redirect_uri = json_pack("{soso}", "name", j_redirect_uri_name, "uri", j_redirect_uri_uri);
                if (j_redirect_uri != NULL) {
                  json_array_append_new(json_object_get(j_entry, "redirect_uri"), j_redirect_uri);
                }
              }
            }
            
            if (ldap_count_values_len(confidential_values) > 0) {
              json_object_set_new(j_entry, "confidential", strcmp(confidential_values[0]->bv_val, "1")==0?json_true():json_false());
            } else {
              json_object_set_new(j_entry, "confidential", json_true());
            }
            
            json_object_set_new(j_entry, "source", json_string("ldap"));
            
            client_id_escaped = h_escape_string(config->conn, json_string_value(json_object_get(j_entry, "client_id")));
            client_clause = msprintf("IN (SELECT `got_id` FROM `%s` WHERE `gc_client_id`='%s')", GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE, client_id_escaped);
            j_query = json_pack("{sss[s]s{s{ssss}}}",
                                "table",
                                GLEWLWYD_TABLE_AUTHORIZATION_TYPE,
                                "columns",
                                  "got_name AS name",
                                "where",
                                  "got_id",
                                    "operator",
                                    "raw",
                                    "value",
                                    client_clause);
            o_free(client_clause);
            o_free(client_id_escaped);
            res = h_select(config->conn, j_query, &j_auth_type, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              json_object_set_new(j_entry, "authorization_type", json_array());
              if (json_object_get(j_entry, "authorization_type") != NULL) {
                json_array_foreach(j_auth_type, i_auth_type, j_cur_auth_type) {
                  json_array_append_new(json_object_get(j_entry, "authorization_type"), json_copy(json_object_get(j_cur_auth_type, "name")));
                }
              }
              json_decref(j_auth_type);
            }
            
            json_array_append_new(json_object_get(j_result, "client"), j_entry);
            
            ldap_value_free_len(name_values);
            ldap_value_free_len(description_values);
            ldap_value_free_len(client_id_values);
            ldap_value_free_len(scope_values);
            ldap_value_free_len(redirect_uri_values);
            ldap_value_free_len(confidential_values);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "Error allocating resources for j_entry");
          }
          entry = ldap_next_entry(ldap, entry);
          i++;
        }
      }
    }
    o_free(filter);
    ldap_msgfree(answer);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  json_decref(j_scope_list);
  return j_result;
}

/**
 * Get a list of clients in the database backend
 */
json_t * get_client_list_database(struct config_elements * config, const char * search, long int offset, long int limit) {
  json_t * j_query, * j_result, * j_scope, * j_redirect_uri, * j_return, * j_entry, * j_scope_entry, * j_auth_type, * j_cur_auth_type;
  int res;
  char * scope_clause, * client_clause, * client_id_escaped;
  size_t index, i_scope, i_auth_type;
  
  j_query = json_pack("{sss[ssssss]sisi}",
                      "table",
                      GLEWLWYD_TABLE_CLIENT,
                      "columns",
                        "gc_id",
                        "gc_name AS name", 
                        "gc_description AS description",
                        "gc_client_id AS client_id",
                        "gc_confidential",
                        "gc_enabled",
                      "offset",
                      offset,
                      "limit",
                      limit);
  if (search != NULL && strcmp("", search) != 0) {
    char * search_escaped = h_escape_string(config->conn, search);
    char * clause_search = msprintf("IN (SELECT `gc_id` FROM `%s` WHERE `gc_name` LIKE '%%%s%%' OR `gc_description` LIKE '%%%s%%' OR `gc_client_id` LIKE '%%%s%%')",
                                    GLEWLWYD_TABLE_CLIENT, search_escaped, search_escaped, search_escaped);
    json_object_set_new(j_query, "where", json_pack("{s{ssss}}", "gc_id", "operator", "raw", "value", clause_search));
    o_free(search_escaped);
    o_free(clause_search);
  }
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_return = json_pack("{sis[]}", "result", G_OK, "client");
    json_array_foreach(j_result, index, j_entry) {
      scope_clause = msprintf("IN (SELECT `gs_id` FROM %s WHERE `gc_id`='%" JSON_INTEGER_FORMAT "')", GLEWLWYD_TABLE_CLIENT_SCOPE, json_integer_value(json_object_get(j_entry, "gc_id")));
      j_query = json_pack("{sss[s]s{s{ssss}}}",
                          "table",
                          GLEWLWYD_TABLE_SCOPE,
                          "columns",
                            "gs_name",
                          "where",
                            "gs_id",
                              "operator",
                              "raw",
                              "value",
                              scope_clause);
      o_free(scope_clause);
      res = h_select(config->conn, j_query, &j_scope, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        json_object_set_new(j_entry, "scope", json_array());
        json_array_foreach(j_scope, i_scope, j_scope_entry) {
          json_array_append_new(json_object_get(j_entry, "scope"), json_copy(json_object_get(j_scope_entry, "gs_name")));
        }
        json_decref(j_scope);
        
        j_query = json_pack("{sss[ss]s{sI}}",
                            "table",
                            GLEWLWYD_TABLE_REDIRECT_URI,
                            "columns",
                              "gru_name AS name",
                              "gru_uri AS uri",
                            "where",
                              "gc_id",
                              json_integer_value(json_object_get(j_entry, "gc_id")));
        res = h_select(config->conn, j_query, &j_redirect_uri, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          json_object_set_new(j_entry, "redirect_uri", j_redirect_uri);

          client_id_escaped = h_escape_string(config->conn, json_string_value(json_object_get(j_entry, "client_id")));
          client_clause = msprintf("IN (SELECT `got_id` FROM `%s` WHERE `gc_client_id`='%s')", GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE, client_id_escaped);
          j_query = json_pack("{sss[s]s{s{ssss}}}",
                              "table",
                              GLEWLWYD_TABLE_AUTHORIZATION_TYPE,
                              "columns",
                                "got_name AS name",
                              "where",
                                "got_id",
                                  "operator",
                                  "raw",
                                  "value",
                                  client_clause);
          o_free(client_clause);
          o_free(client_id_escaped);
          res = h_select(config->conn, j_query, &j_auth_type, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            json_object_set_new(j_entry, "authorization_type", json_array());
            if (json_object_get(j_entry, "authorization_type") != NULL) {
              json_array_foreach(j_auth_type, i_auth_type, j_cur_auth_type) {
                json_array_append_new(json_object_get(j_entry, "authorization_type"), json_copy(json_object_get(j_cur_auth_type, "name")));
              }
            }
            json_decref(j_auth_type);

            json_object_set_new(j_entry, "source", json_string("database"));
            
            if (json_integer_value(json_object_get(j_entry, "gc_enabled")) == 1) {
              json_object_set_new(j_entry, "enabled", json_true());
            } else {
              json_object_set_new(j_entry, "enabled", json_false());
            }
            json_object_del(j_entry, "gc_enabled");
            
            if (json_integer_value(json_object_get(j_entry, "gc_confidential")) == 1) {
              json_object_set_new(j_entry, "confidential", json_true());
            } else {
              json_object_set_new(j_entry, "confidential", json_false());
            }
            json_object_del(j_entry, "gc_confidential");
            
            json_object_del(j_entry, "gc_id");
            
            json_array_append_new(json_object_get(j_return, "client"), json_copy(j_entry));
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_client_database - Error executing j_query for authorization type");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list_database - Error executing j_query for redirect uri");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list_database - Error executing j_query for scope");
      }
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list_database - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

/**
 * Get a list of clients in the http backend
 * as this list is not available yet (we just do basic auth),
 * we return an empty list
 */
json_t * get_client_list_http(struct config_elements * config, const char * search, long int offset, long int limit) {
  json_t * j_return;

  j_return = json_pack("{sis[]}", "result", G_OK, "client");

  return j_return;
}

/**
 * Get a specific client
 */
json_t * get_client(struct config_elements * config, const char * client_id, const char * source) {
  json_t * j_return = NULL, * j_client = NULL;
  int search_ldap = (source == NULL || 0 == strcmp(source, "ldap") || 0 == strcmp(source, "all")), search_database = (source == NULL || 0 == strcmp(source, "database") || 0 == strcmp(source, "all")), search_http = (source == NULL || 0 == strcmp(source, "http") || 0 == strcmp(source, "all"));
  
  if (client_id == NULL || strlen(client_id) == 0) {
    j_client = json_pack("{si}", "result", G_ERROR_PARAM);
  } else {
    if (search_ldap) {
      if (config->has_auth_ldap) {
        j_client = get_client_ldap(config, client_id);
      } else {
        j_client = json_pack("{si}", "result", G_ERROR_PARAM);
      }
    }
    if (!check_result_value(j_client, G_OK) && search_database) {
      json_decref(j_client);
      if (config->has_auth_database) {
        j_client = get_client_database(config, client_id);
      } else {
        j_client = json_pack("{si}", "result", G_ERROR_PARAM);
      }
    }
    if (!check_result_value(j_client, G_OK) && search_http) {
      /*
       * at the moment we are not able to get a client via http
       * so we do not change anything here
       */
    }
    if (check_result_value(j_client, G_OK)) {
      j_return = json_pack("{siso}", "result", G_OK, "client", json_copy(json_object_get(j_client, "client")));
    } else if (check_result_value(j_client, G_ERROR_NOT_FOUND)) {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else if (check_result_value(j_client, G_ERROR_PARAM)) {
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_client - Error getting client");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  }
  json_decref(j_client);
  
  return j_return;
}

/**
 * Get a specific client in database backend
 */
json_t * get_client_database(struct config_elements * config, const char * client_id) {
  json_t * j_query, * j_result = NULL, * j_scope, * j_redirect_uri, * j_return = NULL, * j_entry, * j_scope_entry, * j_auth_type , * j_cur_auth_type;
  int res;
  char * scope_clause, * client_clause, * client_id_escaped;
  size_t i_scope, i_auth_type;
  
  j_query = json_pack("{sss[ssssss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_CLIENT,
                      "columns",
                        "gc_id",
                        "gc_name AS name", 
                        "gc_description AS description",
                        "gc_client_id AS client_id",
                        "gc_confidential",
                        "gc_enabled",
                      "where",
                        "gc_client_id",
                        client_id);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result) > 0) {
      j_entry = json_array_get(j_result, 0);
      scope_clause = msprintf("IN (SELECT `gs_id` FROM %s WHERE `gc_id`='%" JSON_INTEGER_FORMAT "')", GLEWLWYD_TABLE_CLIENT_SCOPE, json_integer_value(json_object_get(j_entry, "gc_id")));
      j_query = json_pack("{sss[s]s{s{ssss}}}",
                          "table",
                          GLEWLWYD_TABLE_SCOPE,
                          "columns",
                            "gs_name",
                          "where",
                            "gs_id",
                              "operator",
                              "raw",
                              "value",
                              scope_clause);
      o_free(scope_clause);
      res = h_select(config->conn, j_query, &j_scope, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        json_object_set_new(j_entry, "scope", json_array());
        json_array_foreach(j_scope, i_scope, j_scope_entry) {
          json_array_append_new(json_object_get(j_entry, "scope"), json_copy(json_object_get(j_scope_entry, "gs_name")));
        }
        json_decref(j_scope);
        
        j_query = json_pack("{sss[ss]s{sI}}",
                            "table",
                            GLEWLWYD_TABLE_REDIRECT_URI,
                            "columns",
                              "gru_name AS name",
                              "gru_uri AS uri",
                            "where",
                              "gc_id",
                              json_integer_value(json_object_get(j_entry, "gc_id")));
        res = h_select(config->conn, j_query, &j_redirect_uri, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          json_object_set_new(j_entry, "redirect_uri", j_redirect_uri);

          client_id_escaped = h_escape_string(config->conn, json_string_value(json_object_get(j_entry, "client_id")));
          client_clause = msprintf("IN (SELECT `got_id` FROM `%s` WHERE `gc_client_id`='%s')", GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE, client_id_escaped);
          j_query = json_pack("{sss[s]s{s{ssss}}}",
                              "table",
                              GLEWLWYD_TABLE_AUTHORIZATION_TYPE,
                              "columns",
                                "got_name AS name",
                              "where",
                                "got_id",
                                  "operator",
                                  "raw",
                                  "value",
                                  client_clause);
          o_free(client_clause);
          o_free(client_id_escaped);
          res = h_select(config->conn, j_query, &j_auth_type, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            json_object_set_new(j_entry, "authorization_type", json_array());
            if (json_object_get(j_entry, "authorization_type") != NULL) {
              json_array_foreach(j_auth_type, i_auth_type, j_cur_auth_type) {
                json_array_append_new(json_object_get(j_entry, "authorization_type"), json_copy(json_object_get(j_cur_auth_type, "name")));
              }
            }
            json_decref(j_auth_type);

            json_object_set_new(j_entry, "source", json_string("database"));
            
            if (json_integer_value(json_object_get(j_entry, "gc_enabled")) == 1) {
              json_object_set_new(j_entry, "enabled", json_true());
            } else {
              json_object_set_new(j_entry, "enabled", json_false());
            }
            json_object_del(j_entry, "gc_enabled");
            
            if (json_integer_value(json_object_get(j_entry, "gc_confidential")) == 1) {
              json_object_set_new(j_entry, "confidential", json_true());
            } else {
              json_object_set_new(j_entry, "confidential", json_false());
            }
            json_object_del(j_entry, "gc_confidential");
            
            json_object_del(j_entry, "gc_id");
            
            j_return = json_pack("{siso}", "result", G_OK, "client", json_copy(j_entry));
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_client_database - Error executing j_query for authorization type");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_client_database - Error executing j_query for redirect uri");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client_database - Error executing j_query for scope");
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_client_database - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

/**
 * Get a specific client in ldap backend
 */
json_t * get_client_ldap(struct config_elements * config, const char * client_id) {
  LDAP * ldap = NULL;
  LDAPMessage * answer = NULL, * entry;
  int j, res;
  json_t * j_result, * j_scope_list = get_scope_list(config), * j_query, * j_auth_type, * j_cur_auth_type;
  char * client_clause, * client_id_escaped;
  size_t i_auth_type;
  
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  int  scope          = LDAP_SCOPE_ONELEVEL;
  char * filter       = NULL;
  char * attrs[]      = {config->auth_ldap->name_property_client_read, config->auth_ldap->description_property_client_read, config->auth_ldap->client_id_property_client_read, config->auth_ldap->scope_property_client_read, config->auth_ldap->redirect_uri_property_client_read, config->auth_ldap->confidential_property_client_read, NULL};
  int  attrsonly      = 0;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred;
  struct berval *servcred;

  cred.bv_val = config->auth_ldap->bind_passwd;
  cred.bv_len = strlen(config->auth_ldap->bind_passwd);
  
  if (!check_result_value(j_scope_list, G_OK)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error getting scope list");
    j_result = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (ldap_initialize(&ldap, config->auth_ldap->uri) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error initializing ldap");
    j_result = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error setting ldap protocol version");
    j_result = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if ((result = ldap_sasl_bind_s(ldap, config->auth_ldap->bind_dn, ldap_mech, &cred, NULL, NULL, &servcred)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error binding to ldap server mode %s: %s", ldap_mech, ldap_err2string(result));
    j_result = json_pack("{si}", "result", G_ERROR_PARAM);
  } else {
    // Connection successful, doing ldap search
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter_client_read, config->auth_ldap->client_id_property_client_read, client_id);
    if ((result = ldap_search_ext_s(ldap, config->auth_ldap->base_search_client, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search: %s", ldap_err2string(result));
      j_result = json_pack("{si}", "result", G_ERROR_PARAM);
    } else {
      // getting first result if exist
      if (ldap_count_entries(ldap, answer) > 0) {
        entry = ldap_first_entry(ldap, answer);
        
        json_t * j_entry = json_object();
        
        if (j_entry != NULL) {
          struct berval ** name_values = ldap_get_values_len(ldap, entry, config->auth_ldap->name_property_client_read);
          struct berval ** description_values = ldap_get_values_len(ldap, entry, config->auth_ldap->description_property_client_read);
          struct berval ** client_id_values = ldap_get_values_len(ldap, entry, config->auth_ldap->client_id_property_client_read);
          struct berval ** scope_values = ldap_get_values_len(ldap, entry, config->auth_ldap->scope_property_client_read);
          struct berval ** redirect_uri_values = ldap_get_values_len(ldap, entry, config->auth_ldap->redirect_uri_property_client_read);
          struct berval ** confidential_values = ldap_get_values_len(ldap, entry, config->auth_ldap->confidential_property_client_read);
          
          if (ldap_count_values_len(name_values) > 0) {
            json_object_set_new(j_entry, "name", json_stringn(name_values[0]->bv_val, name_values[0]->bv_len));
          }
          
          if (ldap_count_values_len(description_values) > 0) {
            json_object_set_new(j_entry, "description", json_stringn(description_values[0]->bv_val, description_values[0]->bv_len));
          }
          
          if (ldap_count_values_len(client_id_values) > 0) {
            json_object_set_new(j_entry, "client_id", json_stringn(client_id_values[0]->bv_val, client_id_values[0]->bv_len));
          }
          
          // For now a ldap client is always enabled, until I find a standard way to do it
          json_object_set_new(j_entry, "enabled", json_true());
          
          json_object_set_new(j_entry, "scope", json_array());
          for (j=0; j < ldap_count_values_len(scope_values); j++) {
            json_t * j_scope = json_string(scope_values[j]->bv_val);
            if (json_search(json_object_get(j_scope_list, "scope"), j_scope) != NULL) {
              json_array_append_new(json_object_get(j_entry, "scope"), j_scope);
            } else {
              json_decref(j_scope);
            }
          }
          
          json_object_set_new(j_entry, "redirect_uri", json_array());
          for (j=0; j < ldap_count_values_len(redirect_uri_values); j++) {
            char * space_address = strchr(redirect_uri_values[j]->bv_val, ' ');
            if (space_address != NULL) {
              json_t * j_redirect_uri_uri = json_stringn(redirect_uri_values[j]->bv_val, (space_address - redirect_uri_values[j]->bv_val));
              json_t * j_redirect_uri_name = json_string(space_address+sizeof(char));
              json_t * j_redirect_uri = json_pack("{soso}", "name", j_redirect_uri_name, "uri", j_redirect_uri_uri);
              if (j_redirect_uri != NULL) {
                json_array_append_new(json_object_get(j_entry, "redirect_uri"), j_redirect_uri);
              }
            }
          }
          
          if (ldap_count_values_len(confidential_values) > 0) {
            json_object_set_new(j_entry, "confidential", strcmp(confidential_values[0]->bv_val, "1")==0?json_true():json_false());
          } else {
            json_object_set_new(j_entry, "confidential", json_true());
          }
          
          client_id_escaped = h_escape_string(config->conn, json_string_value(json_object_get(j_entry, "client_id")));
          client_clause = msprintf("IN (SELECT `got_id` FROM `%s` WHERE `gc_client_id`='%s')", GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE, client_id_escaped);
          j_query = json_pack("{sss[s]s{s{ssss}}}",
                              "table",
                              GLEWLWYD_TABLE_AUTHORIZATION_TYPE,
                              "columns",
                                "got_name AS name",
                              "where",
                                "got_id",
                                  "operator",
                                  "raw",
                                  "value",
                                  client_clause);
          o_free(client_clause);
          o_free(client_id_escaped);
          res = h_select(config->conn, j_query, &j_auth_type, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            json_object_set_new(j_entry, "authorization_type", json_array());
            if (json_object_get(j_entry, "authorization_type") != NULL) {
              json_array_foreach(j_auth_type, i_auth_type, j_cur_auth_type) {
                json_array_append_new(json_object_get(j_entry, "authorization_type"), json_copy(json_object_get(j_cur_auth_type, "name")));
              }
            }
            json_decref(j_auth_type);
          }
            
          json_object_set_new(j_entry, "source", json_string("ldap"));
          j_result = json_pack("{siso}", "result", G_OK, "client", j_entry);
          ldap_value_free_len(name_values);
          ldap_value_free_len(description_values);
          ldap_value_free_len(client_id_values);
          ldap_value_free_len(scope_values);
          ldap_value_free_len(redirect_uri_values);
          ldap_value_free_len(confidential_values);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "Error allocating resources for j_entry");
          j_result = json_pack("{si}", "result", G_ERROR_MEMORY);
        }
      } else {
        j_result = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
    }
    o_free(filter);
    ldap_msgfree(answer);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  json_decref(j_scope_list);
  return j_result;
}

/**
 * Check if client parameters are valid
 */
json_t * is_client_valid(struct config_elements * config, json_t * j_client, int add) {
  json_t * j_return = json_array(), * j_result, * j_scope, * j_redirect_uri, * j_authorization_type_list, * j_authorization_type, * cur_auth_type;
  size_t index, index2;
  int found;
  
  if (j_return != NULL) {
    if (json_is_object(j_client)) {
      if (json_object_get(j_client, "source") != NULL && (!json_is_string(json_object_get(j_client, "source")) || (0 != strcmp(json_string_value(json_object_get(j_client, "source")), "all") && 0 != strcmp(json_string_value(json_object_get(j_client, "source")), "ldap") && 0 != strcmp(json_string_value(json_object_get(j_client, "source")), "database")))) {
        json_array_append_new(j_return, json_pack("{ss}", "source", "source is an optional string, values available are 'all', 'ldap' or 'database', default is 'database'"));
      }
      
      if (json_object_get(j_client, "name") == NULL || !json_is_string(json_object_get(j_client, "name")) || json_string_length(json_object_get(j_client, "name")) > 128 || json_string_length(json_object_get(j_client, "name")) == 0) {
        json_array_append_new(j_return, json_pack("{ss}", "name", "name is a mandatory non null string of maximum 128 characters"));
      }
      
      if (json_object_get(j_client, "description") != NULL && (!json_is_string(json_object_get(j_client, "description")) || json_string_length(json_object_get(j_client, "description")) > 512)) {
        json_array_append_new(j_return, json_pack("{ss}", "description", "description is an optional string between 0 and 512 characters"));
      }
      
      if (json_object_get(j_client, "enabled") != NULL && !json_is_boolean(json_object_get(j_client, "enabled"))) {
        json_array_append_new(j_return, json_pack("{ss}", "enabled", "enabled is an optional boolean"));
      }
      
      if (json_object_get(j_client, "confidential") != NULL && !json_is_boolean(json_object_get(j_client, "confidential"))) {
        json_array_append_new(j_return, json_pack("{ss}", "enabled", "confidential is an optional boolean"));
      }
      
      if (json_object_get(j_client, "authorization_type") != NULL && !json_is_array(json_object_get(j_client, "authorization_type"))) {
        json_array_append_new(j_return, json_pack("{ss}", "authorization_type", "authorization_type is a mandatory array of redirect uri objects, at least one redirect uri is required"));
      } else {
        j_authorization_type_list = get_authorization_type(config, NULL);
        if (check_result_value(j_authorization_type_list, G_OK)) {
          json_array_foreach(json_object_get(j_client, "authorization_type"), index, j_authorization_type) {
            if (!json_is_string(j_authorization_type)) {
              json_array_append_new(j_return, json_pack("{ss}", "authorization_type", "authorization_type must be a string"));
            } else {
              found = 0;
              json_array_foreach(json_object_get(j_authorization_type_list, "authorization"), index2, cur_auth_type) {
                if (json_equal(json_object_get(cur_auth_type, "name"), j_authorization_type) && json_object_get(cur_auth_type, "enabled") == json_true()) {
                  found = 1;
                }
              }
              if (!found) {
                json_array_append_new(j_return, json_pack("{ss}", "authorization_type", "authorization_type does not exist or is not enabled"));
              }
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error getting authorization_type list");
        }
        json_decref(j_authorization_type_list);
      }
      
      if (add) {
        if (json_object_get(j_client, "client_id") == NULL || !json_is_string(json_object_get(j_client, "client_id")) || json_string_length(json_object_get(j_client, "client_id")) > 128 || json_string_length(json_object_get(j_client, "client_id")) == 0) {
          json_array_append_new(j_return, json_pack("{ss}", "client_id", "client_id is a mandatory non null string of maximum 128 characters"));
        } else {
          j_result = get_client(config, json_string_value(json_object_get(j_client, "client_id")), json_string_value(json_object_get(j_client, "source")));
          if (check_result_value(j_result, G_OK)) {
            char * message = msprintf("client_id '%s' already exist", json_string_value(json_object_get(j_client, "client_id")));
            json_array_append_new(j_return, json_pack("{ss}", "client_id", message));
            o_free(message);
          }
          json_decref(j_result);
        }
        
        if (json_object_get(j_client, "confidential") == json_true() && (json_object_get(j_client, "password") == NULL || !json_is_string(json_object_get(j_client, "password")) || (json_string_length(json_object_get(j_client, "password")) > 0 && json_string_length(json_object_get(j_client, "password")) < 8))) {
          json_array_append_new(j_return, json_pack("{ss}", "password", "password is a mandatory string of at least 8 characters if confidential flag is enabled"));
        }
        
        if (config->use_scope) {
          if (json_object_get(j_client, "scope") == NULL || !json_is_array(json_object_get(j_client, "scope"))) {
            json_array_append_new(j_return, json_pack("{ss}", "scope", "scope is a mandatory array of scope names"));
          } else {
            json_array_foreach(json_object_get(j_client, "scope"), index, j_scope) {
              if (!json_is_string(j_scope)) {
                json_array_append_new(j_return, json_pack("{ss}", "scope", "scope name must be a string"));
              } else {
                j_result = get_scope(config, json_string_value(j_scope));
                if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
                  char * message = msprintf("scope name '%s' not found", json_string_value(j_scope));
                  json_array_append_new(j_return, json_pack("{ss}", "scope", message));
                  o_free(message);
                } else if (!check_result_value(j_result, G_OK)) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error while checking scope name '%s'", json_string_value(j_scope));
                }
                json_decref(j_result);
              }
            }
          }
        }
        
        if (json_object_get(j_client, "redirect_uri") == NULL || !json_is_array(json_object_get(j_client, "redirect_uri")) || json_array_size(json_object_get(j_client, "redirect_uri")) < 1) {
          json_array_append_new(j_return, json_pack("{ss}", "redirect_uri", "redirect_uri is a mandatory array of redirect uri objects, at least one redirect uri is required"));
        } else {
          json_array_foreach(json_object_get(j_client, "redirect_uri"), index, j_redirect_uri) {
            if (!json_is_object(j_redirect_uri)) {
              json_array_append_new(j_return, json_pack("{ss}", "redirect_uri", "redirect_uri must be a json object"));
            } else if (json_object_get(j_redirect_uri, "name") == NULL || !json_is_string(json_object_get(j_redirect_uri, "name")) || json_string_length(json_object_get(j_redirect_uri, "name")) > 128 || json_string_length(json_object_get(j_redirect_uri, "name")) == 0) {
              json_array_append_new(j_return, json_pack("{ss}", "redirect_uri", "name must be a non empty string of maximum 128 characters"));
            } else if (json_object_get(j_redirect_uri, "uri") == NULL || !json_is_string(json_object_get(j_redirect_uri, "uri")) || json_string_length(json_object_get(j_redirect_uri, "uri")) > 512 || json_string_length(json_object_get(j_redirect_uri, "uri")) == 0 || (strncmp("http://", json_string_value(json_object_get(j_redirect_uri, "uri")), strlen("http://")) != 0 && strncmp("https://", json_string_value(json_object_get(j_redirect_uri, "uri")), strlen("https://")) != 0)) {
              json_array_append_new(j_return, json_pack("{ss}", "redirect_uri", "uri must be a non empty string of maximum 512 characters and must start with 'http://' or 'https://'"));
            } else if (json_object_get(j_redirect_uri, "enabled") != NULL && !json_is_boolean(json_object_get(j_redirect_uri, "enabled"))) {
              json_array_append_new(j_return, json_pack("{ss}", "redirect_uri", "enabled must be a boolean"));
            }
          }
        }
      } else {
        if (json_object_get(j_client, "confidential") == json_true() && json_object_get(j_client, "password") != NULL && (!json_is_string(json_object_get(j_client, "password")) || (json_string_length(json_object_get(j_client, "password")) > 0 && json_string_length(json_object_get(j_client, "password")) < 8))) {
          json_array_append_new(j_return, json_pack("{ss}", "password", "password is a string of at least 8 characters"));
        }

        if (config->use_scope) {
          if (json_object_get(j_client, "scope") != NULL && !json_is_array(json_object_get(j_client, "scope"))) {
            json_array_append_new(j_return, json_pack("{ss}", "scope", "scope is a mandatory array of scope names"));
          } else if (json_object_get(j_client, "scope") != NULL) {
            json_array_foreach(json_object_get(j_client, "scope"), index, j_scope) {
              if (!json_is_string(j_scope)) {
                json_array_append_new(j_return, json_pack("{ss}", "scope", "scope name must be a string"));
              } else {
                j_result = get_scope(config, json_string_value(j_scope));
                if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
                  char * message = msprintf("scope name '%s' not found", json_string_value(j_scope));
                  json_array_append_new(j_return, json_pack("{ss}", "scope", message));
                  o_free(message);
                } else if (!check_result_value(j_result, G_OK)) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error while checking scope name '%s'", json_string_value(j_scope));
                }
                json_decref(j_result);
              }
            }
          }
        }
      }
    } else {
      json_array_append_new(j_return, json_pack("{ss}", "client", "client must be a json object"));
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error allocating resources for j_result");
  }
  return j_return;
}

/**
 * Add a new client
 */
int add_client(struct config_elements * config, json_t * j_client) {
  if ((json_object_get(j_client, "source") == NULL || 0 == strcmp("database", json_string_value(json_object_get(j_client, "source")))) && config->has_auth_database) {
    return add_client_database(config, j_client);
  } else if (0 == o_strcmp("ldap", json_string_value(json_object_get(j_client, "source"))) && config->has_auth_ldap) {
    return add_client_ldap(config, j_client);
  } else if (0 == o_strcmp("http", json_string_value(json_object_get(j_client, "source"))) && config->has_auth_http) {
    return add_client_http(config, j_client);
  } else {
    return G_ERROR_PARAM;
  }
}

/**
 * Add a new client in the ldap backend
 */
int add_client_ldap(struct config_elements * config, json_t * j_client) {
  LDAP * ldap = NULL;
  int res;
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred, * servcred;
  
  LDAPMod ** mods = NULL;
  char ** scope_values = NULL;
  int nb_scope = 0, nb_redirect_uri = json_array_size(json_object_get(j_client, "redirect_uri")), nb_attr = 2, i, attr_counter; // Default attribute is objectClass
  json_t * j_scope, * j_redirect_uri, * j_query;
  size_t index;
  char * new_dn, * password = NULL, ** redirect_uri_array = NULL, * escaped = NULL, * clause_auth_type;
  
  for (i=0; config->auth_ldap->client_id_property_client_write[i] != NULL; i++) {
    nb_attr++;
  }
  for (i=0; json_object_get(j_client, "name") != NULL && json_string_length(json_object_get(j_client, "name")) > 0 && config->auth_ldap->name_property_client_write[i] != NULL; i++) {
    nb_attr++;
  }
  for (i=0; json_object_get(j_client, "description") != NULL && json_string_length(json_object_get(j_client, "description")) > 0 && config->auth_ldap->description_property_client_write[i] != NULL; i++) {
    nb_attr++;
  }
  for (i=0; json_object_get(j_client, "redirect_uri") != NULL && json_array_size(json_object_get(j_client, "redirect_uri")) > 0 && config->auth_ldap->redirect_uri_property_client_write[i] != NULL; i++) {
    nb_attr++;
  }
  for (i=0; config->use_scope && config->auth_ldap->scope_property_client_write[i] != NULL && json_object_get(j_client, "scope") != NULL && json_array_size(json_object_get(j_client, "scope")) > 0; i++) {
    nb_attr++;
  }
  for (i=0; config->auth_ldap->confidential_property_client_write[i] != NULL; i++) {
    nb_attr++;
  }
  if (json_object_get(j_client, "confidential") == json_true() && json_object_get(j_client, "password") != NULL && json_string_length(json_object_get(j_client, "password")) > 0) {
    nb_attr++;
  }
  if (config->use_scope && json_object_get(j_client, "scope") != NULL && json_array_size(json_object_get(j_client, "scope")) > 0) {
    nb_scope = json_array_size(json_object_get(j_client, "scope"));
  }
  mods = o_malloc(nb_attr*sizeof(LDAPMod *));
  
  cred.bv_val = config->auth_ldap->bind_passwd;
  cred.bv_len = strlen(config->auth_ldap->bind_passwd);

  if (mods == NULL) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error allocating resources for mods");
    res = G_ERROR;
  } else if (ldap_initialize(&ldap, config->auth_ldap->uri) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error initializing ldap");
    res = G_ERROR;
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error setting ldap protocol version");
    res = G_ERROR;
  } else if ((result = ldap_sasl_bind_s(ldap, config->auth_ldap->bind_dn, ldap_mech, &cred, NULL, NULL, &servcred)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error binding to ldap server mode %s: %s", ldap_mech, ldap_err2string(result));
    res = G_ERROR;
  } else {
    new_dn = msprintf("%s=%s,%s", config->auth_ldap->rdn_property_client_write, json_string_value(json_object_get(j_client, "client_id")), config->auth_ldap->base_search_client);
    
    attr_counter = 0;
    mods[attr_counter] = o_malloc(sizeof(LDAPMod));
    mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
    mods[attr_counter]->mod_type   = "objectClass";
    mods[attr_counter]->mod_values = config->auth_ldap->object_class_client_write;
    attr_counter++;
    
    for (i=0; config->auth_ldap->client_id_property_client_write[i] != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
      mods[attr_counter]->mod_type   = config->auth_ldap->client_id_property_client_write[i];
      mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(j_client, "client_id"));
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    for (i=0; json_object_get(j_client, "name") != NULL && json_string_length(json_object_get(j_client, "name")) > 0 && config->auth_ldap->name_property_client_write[i] != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
      mods[attr_counter]->mod_type   = config->auth_ldap->name_property_client_write[i];
      mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(j_client, "name"));
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    for (i=0; json_object_get(j_client, "description") != NULL && json_string_length(json_object_get(j_client, "description")) > 0 && config->auth_ldap->description_property_client_write[i] != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
      mods[attr_counter]->mod_type   = config->auth_ldap->description_property_client_write[i];
      mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(j_client, "description"));
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    if (nb_redirect_uri > 0) {
      redirect_uri_array = o_malloc((nb_redirect_uri+1)*sizeof(char *));
      if (redirect_uri_array != NULL) {
        json_array_foreach(json_object_get(j_client, "redirect_uri"), index, j_redirect_uri) {
          redirect_uri_array[index] = msprintf("%s %s", json_string_value(json_object_get(j_redirect_uri, "uri")), json_string_value(json_object_get(j_redirect_uri, "name")));
          redirect_uri_array[index+1] = NULL;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Error allocating resources for redirect_uri_array");
      }
    }
    
    for (i=0; config->auth_ldap->redirect_uri_property_client_write[i] != NULL && json_object_get(j_client, "redirect_uri") != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
      mods[attr_counter]->mod_type   = config->auth_ldap->redirect_uri_property_client_write[i];
      mods[attr_counter]->mod_values = redirect_uri_array;
      attr_counter++;
    }
    
    for (i=0; config->use_scope && config->auth_ldap->confidential_property_client_write[i] != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
      mods[attr_counter]->mod_type   = config->auth_ldap->confidential_property_client_write[i];
      mods[attr_counter]->mod_values[0] = json_object_get(j_client, "confidential")==json_true()?"1":"0";
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    for (i=0; config->use_scope && config->auth_ldap->scope_property_client_write[i] != NULL && json_object_get(j_client, "scope") != NULL && json_array_size(json_object_get(j_client, "scope")) > 0; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
      mods[attr_counter]->mod_type   = config->auth_ldap->scope_property_client_write[i];
      mods[attr_counter]->mod_values = o_malloc((nb_scope+1)*sizeof(char *));
      json_array_foreach(json_object_get(j_client, "scope"), index, j_scope) {
        mods[attr_counter]->mod_values[index] = (char *)json_string_value(j_scope);
        mods[attr_counter]->mod_values[index+1] = NULL;
      }
      attr_counter++;
    }
    
    if (json_object_get(j_client, "confidential") == json_true() && json_object_get(j_client, "password") != NULL && json_string_length(json_object_get(j_client, "password")) > 0) {
      password = generate_hash(config, config->auth_ldap->password_algorithm_client_write, json_string_value(json_object_get(j_client, "password")));
      if (password != NULL) {
        mods[attr_counter] = o_malloc(sizeof(LDAPMod));
        mods[attr_counter]->mod_values    = o_malloc(2 * sizeof(char *));
        mods[attr_counter]->mod_op        = LDAP_MOD_ADD;
        mods[attr_counter]->mod_type      = config->auth_ldap->password_property_client_write;
        mods[attr_counter]->mod_values[0] = password;
        mods[attr_counter]->mod_values[1] = NULL;
        attr_counter++;
      }
    }
    
    mods[attr_counter] = NULL;
    
    if ((result = ldap_add_ext_s(ldap, new_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error adding new client %s in the ldap backend: %s", new_dn, ldap_err2string(result));
      res = G_ERROR;
    } else {
      res = G_OK;

      if (json_object_get(j_client, "authorization_type") != NULL) {
        j_query = json_pack("{sss[]}",
                            "table",
                            GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE,
                            "values");
        json_array_foreach(json_object_get(j_client, "authorization_type"), index, j_redirect_uri) {
          escaped = h_escape_string(config->conn, json_string_value(j_redirect_uri));
          clause_auth_type = msprintf("(SELECT `got_id` FROM `%s` WHERE `got_name`='%s')", GLEWLWYD_TABLE_AUTHORIZATION_TYPE, escaped);
          o_free(escaped);
          json_array_append_new(json_object_get(j_query, "values"), 
                                json_pack("{sss{ss}}", 
                                          "gc_client_id", 
                                          json_string_value(json_object_get(j_client, "client_id")), 
                                          "got_id",
                                            "raw",
                                            clause_auth_type));
          o_free(clause_auth_type);
        }
        if (json_array_size(json_object_get(j_query, "values")) > 0) {
          if (h_insert(config->conn, j_query, NULL) != H_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "add_client_ldap - Error adding authorization_type");
          }
        }
        json_decref(j_query);
      }      
    }
    
    o_free(scope_values);
    attr_counter = 0;
    o_free(mods[attr_counter]);
    attr_counter++;
    for (i=0; config->auth_ldap->client_id_property_client_write[i] != NULL; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    for (i=0; json_object_get(j_client, "name") != NULL && json_string_length(json_object_get(j_client, "name")) > 0 && config->auth_ldap->name_property_client_write[i] != NULL; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    for (i=0; json_object_get(j_client, "description") != NULL && json_string_length(json_object_get(j_client, "description")) > 0 && config->auth_ldap->description_property_client_write[i] != NULL; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    if (nb_redirect_uri > 0) {
      free_string_array(redirect_uri_array);
      for (i=0; config->auth_ldap->redirect_uri_property_client_write[i] != NULL && json_object_get(j_client, "redirect_uri") != NULL && nb_redirect_uri > 0; i++) {
        o_free(mods[attr_counter]);
        attr_counter++;
      }
    }
    for (i=0; config->use_scope && config->auth_ldap->confidential_property_client_write[i] != NULL; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    for (i=0; config->use_scope && config->auth_ldap->scope_property_client_write[i] != NULL && json_object_get(j_client, "scope") != NULL && json_array_size(json_object_get(j_client, "scope")) > 0; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    if (json_object_get(j_client, "confidential") == json_true() && json_object_get(j_client, "password") != NULL && json_string_length(json_object_get(j_client, "password")) > 0) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    o_free(mods);
    o_free(new_dn);
    o_free(password);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  return res;
}

/**
 * Add a new client in the database backend
 */
int add_client_database(struct config_elements * config, json_t * j_client) {
  json_t * j_query, * j_scope, * j_redirect_uri;
  int res, to_return;
  size_t index;
  char * clause_login, * clause_scope, * escaped = NULL, * password, * clause_auth_type;
  
  if (json_object_get(j_client, "confidential") == json_true()) {
    if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
      escaped = h_escape_string(config->conn, json_string_value(json_object_get(j_client, "password")));
      password = msprintf("PASSWORD('%s')", escaped);
    } else {
      escaped = generate_hash(config, config->hash_algorithm, json_string_value(json_object_get(j_client, "password")));
      password = msprintf("'%s'", escaped);
    }
  } else {
    password = strdup("''");
  }
  j_query = json_pack("{sss{sssssss{ss}sisi}}",
                      "table",
                      GLEWLWYD_TABLE_CLIENT,
                      "values",
                        "gc_name",
                        json_string_value(json_object_get(j_client, "name")),
                        "gc_description",
                        json_object_get(j_client, "description")!=NULL?json_string_value(json_object_get(j_client, "description")):"",
                        "gc_client_id",
                        json_string_value(json_object_get(j_client, "client_id")),
                        "gc_client_password",
                          "raw",
                          password,
                        "gc_enabled",
                        (json_object_get(j_client, "enabled")==json_false()?0:1),
                        "gc_confidential",
                        (json_object_get(j_client, "confidential")==json_true()?1:0));
  res = h_insert(config->conn, j_query, NULL);
  json_decref(j_query);
  o_free(escaped);
  o_free(password);
  if (res == H_OK) {
    if (json_object_get(j_client, "scope") != NULL && config->use_scope) {
      escaped = h_escape_string(config->conn, json_string_value(json_object_get(j_client, "client_id")));
      clause_login = msprintf("(SELECT `gc_id` FROM `%s` WHERE `gc_client_id`='%s')", GLEWLWYD_TABLE_CLIENT, escaped);
      o_free(escaped);
      j_query = json_pack("{sss[]}",
                          "table",
                          GLEWLWYD_TABLE_CLIENT_SCOPE,
                          "values");
      json_array_foreach(json_object_get(j_client, "scope"), index, j_scope) {
        escaped = h_escape_string(config->conn, json_string_value(j_scope));
        clause_scope = msprintf("(SELECT `gs_id` FROM `%s` WHERE `gs_name`='%s')", GLEWLWYD_TABLE_SCOPE, escaped);
        o_free(escaped);
        json_array_append_new(json_object_get(j_query, "values"), json_pack("{s{ss}s{ss}}", "gc_id", "raw", clause_login, "gs_id", "raw", clause_scope));
        o_free(clause_scope);
      }
      if (json_array_size(json_object_get(j_query, "values")) > 0) {
        if (h_insert(config->conn, j_query, NULL) != H_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "add_client_database - Error adding scope");
        }
      }
      o_free(clause_login);
      json_decref(j_query);
    }

    if (json_object_get(j_client, "redirect_uri") != NULL) {
      escaped = h_escape_string(config->conn, json_string_value(json_object_get(j_client, "client_id")));
      clause_login = msprintf("(SELECT `gc_id` FROM `%s` WHERE `gc_client_id`='%s')", GLEWLWYD_TABLE_CLIENT, escaped);
      o_free(escaped);
      j_query = json_pack("{sss[]}",
                          "table",
                          GLEWLWYD_TABLE_REDIRECT_URI,
                          "values");
      json_array_foreach(json_object_get(j_client, "redirect_uri"), index, j_redirect_uri) {
        json_array_append_new(json_object_get(j_query, "values"), 
                              json_pack("{s{ss}ssss}", 
                                        "gc_id", 
                                          "raw", 
                                          clause_login, 
                                        "gru_name", 
                                        json_string_value(json_object_get(j_redirect_uri, "name")),
                                        "gru_uri",
                                        json_string_value(json_object_get(j_redirect_uri, "uri"))));
      }
      o_free(clause_login);
      if (json_array_size(json_object_get(j_query, "values")) > 0) {
        if (h_insert(config->conn, j_query, NULL) != H_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "add_client_database - Error adding redirect_uri");
        }
      }
      json_decref(j_query);
    }

    if (json_object_get(j_client, "authorization_type") != NULL) {
      j_query = json_pack("{sss[]}",
                          "table",
                          GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE,
                          "values");
      json_array_foreach(json_object_get(j_client, "authorization_type"), index, j_redirect_uri) {
        escaped = h_escape_string(config->conn, json_string_value(j_redirect_uri));
        clause_auth_type = msprintf("(SELECT `got_id` FROM `%s` WHERE `got_name`='%s')", GLEWLWYD_TABLE_AUTHORIZATION_TYPE, escaped);
        o_free(escaped);
        json_array_append_new(json_object_get(j_query, "values"), 
                              json_pack("{sss{ss}}", 
                                        "gc_client_id", 
                                        json_string_value(json_object_get(j_client, "client_id")), 
                                        "got_id",
                                          "raw",
                                          clause_auth_type));
        o_free(clause_auth_type);
      }
      if (json_array_size(json_object_get(j_query, "values")) > 0) {
        if (h_insert(config->conn, j_query, NULL) != H_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "add_client_database - Error adding authorization_type");
        }
      }
      json_decref(j_query);
    }
    to_return = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_client_database - Error adding client");
    to_return = G_ERROR_DB;
  }
  return to_return;
}

/**
 * Add a new client in the http backend
 * as this is not possible now, we do nothing
 */
int add_client_http(struct config_elements * config, json_t * j_client) {
  int to_return;

  to_return = G_ERROR_PARAM;

  return to_return;
}

/**
 * Update an existing client
 */
int set_client(struct config_elements * config, const char * client, json_t * j_client, const char * source) {
  if (source == NULL || 0 == strcmp("ldap", source) || 0 == strcmp("all", source)) {
    return set_client_ldap(config, client, j_client);
  } else {
    return set_client_database(config, client, j_client);
  }
}

/**
 * Update an existing client in the ldap backend
 */
int set_client_ldap(struct config_elements * config, const char * client_id, json_t * j_client) {
  LDAP * ldap = NULL;
  int res;
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred, * servcred;
  
  LDAPMod ** mods = NULL;
  char ** scope_values = NULL;
  int nb_scope = 0, nb_redirect_uri = json_array_size(json_object_get(j_client, "redirect_uri")), nb_attr = 2, i, attr_counter;
  json_t * j_scope, * j_redirect_uri;
  size_t index;
  char * cur_dn, * password = NULL, ** redirect_uri_array = NULL;
  json_t * j_query;
  char * escaped, * clause_auth_type;
  
  for (i=0; json_object_get(j_client, "name") != NULL && json_string_length(json_object_get(j_client, "name")) > 0 && config->auth_ldap->name_property_client_write[i] != NULL; i++) {
    nb_attr++;
  }
  for (i=0; json_object_get(j_client, "description") != NULL && json_string_length(json_object_get(j_client, "description")) > 0 && config->auth_ldap->description_property_client_write[i] != NULL; i++) {
    nb_attr++;
  }
  for (i=0; json_object_get(j_client, "redirect_uri") != NULL && json_array_size(json_object_get(j_client, "redirect_uri")) > 0 && config->auth_ldap->redirect_uri_property_client_write[i] != NULL; i++) {
    nb_attr++;
  }
  for (i=0; config->auth_ldap->confidential_property_client_write[i] != NULL; i++) {
    nb_attr++;
  }
  for (i=0; config->use_scope && config->auth_ldap->scope_property_client_write[i] != NULL && json_object_get(j_client, "scope") != NULL && json_array_size(json_object_get(j_client, "scope")) > 0; i++) {
    nb_attr++;
  }
  if (json_object_get(j_client, "confidential") == json_true() && json_object_get(j_client, "password") != NULL && json_string_length(json_object_get(j_client, "password")) > 0) {
    nb_attr++;
  }
  if (config->use_scope && json_object_get(j_client, "scope") != NULL && json_array_size(json_object_get(j_client, "scope")) > 0) {
    nb_scope = json_array_size(json_object_get(j_client, "scope"));
  }
  mods = o_malloc(nb_attr*sizeof(LDAPMod *));
  
  cred.bv_val = config->auth_ldap->bind_passwd;
  cred.bv_len = strlen(config->auth_ldap->bind_passwd);

  if (mods == NULL) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error allocating resources for mods");
    res = G_ERROR;
  } else if (ldap_initialize(&ldap, config->auth_ldap->uri) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error initializing ldap");
    res = G_ERROR;
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error setting ldap protocol version");
    res = G_ERROR;
  } else if ((result = ldap_sasl_bind_s(ldap, config->auth_ldap->bind_dn, ldap_mech, &cred, NULL, NULL, &servcred)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error binding to ldap server mode %s: %s", ldap_mech, ldap_err2string(result));
    res = G_ERROR;
  } else {
    cur_dn = msprintf("%s=%s,%s", config->auth_ldap->rdn_property_client_write, client_id, config->auth_ldap->base_search_client);
    
    attr_counter=0;
    for (i=0; json_object_get(j_client, "name") != NULL && json_string_length(json_object_get(j_client, "name")) > 0 && config->auth_ldap->name_property_client_write[i] != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_REPLACE;
      mods[attr_counter]->mod_type   = config->auth_ldap->name_property_client_write[i];
      mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(j_client, "name"));
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    for (i=0; json_object_get(j_client, "description") != NULL && json_string_length(json_object_get(j_client, "description")) > 0 && config->auth_ldap->description_property_client_write[i] != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_REPLACE;
      mods[attr_counter]->mod_type   = config->auth_ldap->description_property_client_write[i];
      mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(j_client, "description"));
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    if (json_array_size(json_object_get(j_client, "redirect_uri")) > 0) {
      redirect_uri_array = o_malloc((nb_redirect_uri+1)*sizeof(char *));
      if (redirect_uri_array != NULL) {
        json_array_foreach(json_object_get(j_client, "redirect_uri"), index, j_redirect_uri) {
          redirect_uri_array[index] = msprintf("%s %s", json_string_value(json_object_get(j_redirect_uri, "uri")), json_string_value(json_object_get(j_redirect_uri, "name")));
          redirect_uri_array[index+1] = NULL;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Error allocating resources for redirect_uri_array");
      }
      for (i=0; config->auth_ldap->redirect_uri_property_client_write[i] != NULL && json_object_get(j_client, "redirect_uri") != NULL; i++) {
        mods[attr_counter] = o_malloc(sizeof(LDAPMod));
        mods[attr_counter]->mod_op     = LDAP_MOD_REPLACE;
        mods[attr_counter]->mod_type   = config->auth_ldap->redirect_uri_property_client_write[i];
        mods[attr_counter]->mod_values = redirect_uri_array;
        attr_counter++;
      }
    }
    
    for (i=0; config->auth_ldap->confidential_property_client_write[i] != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_REPLACE;
      mods[attr_counter]->mod_type   = config->auth_ldap->confidential_property_client_write[i];
      mods[attr_counter]->mod_values[0] = json_object_get(j_client, "confidential")==json_true()?"1":"0";
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    for (i=0; config->use_scope && config->auth_ldap->scope_property_client_write[i] != NULL && json_object_get(j_client, "scope") != NULL && json_array_size(json_object_get(j_client, "scope")) > 0; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_op     = LDAP_MOD_REPLACE;
      mods[attr_counter]->mod_type   = config->auth_ldap->scope_property_client_write[i];
      mods[attr_counter]->mod_values = o_malloc((nb_scope+1)*sizeof(char *));
      json_array_foreach(json_object_get(j_client, "scope"), index, j_scope) {
        mods[attr_counter]->mod_values[index] = (char *)json_string_value(j_scope);
        mods[attr_counter]->mod_values[index+1] = NULL;
      }
      attr_counter++;
    }
    
    if (json_object_get(j_client, "confidential") == json_true() && json_object_get(j_client, "password") != NULL && json_string_length(json_object_get(j_client, "password")) > 0) {
      password = generate_hash(config, config->auth_ldap->password_algorithm_client_write, json_string_value(json_object_get(j_client, "password")));
      if (password != NULL) {
        mods[attr_counter] = o_malloc(sizeof(LDAPMod));
        mods[attr_counter]->mod_values    = o_malloc(2 * sizeof(char *));
        mods[attr_counter]->mod_op        = LDAP_MOD_REPLACE;
        mods[attr_counter]->mod_type      = config->auth_ldap->password_property_client_write;
        mods[attr_counter]->mod_values[0] = password;
        mods[attr_counter]->mod_values[1] = NULL;
        attr_counter++;
      }
    }
    mods[attr_counter] = NULL;
    
    if ((result = ldap_modify_ext_s(ldap, cur_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error setting client %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
      res = G_ERROR;
    } else {
      if (json_object_get(j_client, "authorization_type") != NULL) {
        j_query = json_pack("{sss{ss}}",
                            "table",
                            GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE,
                            "where",
                              "gc_client_id",
                              client_id);
        res = h_delete(config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          j_query = json_pack("{sss[]}",
                              "table",
                              GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE,
                              "values");
          json_array_foreach(json_object_get(j_client, "authorization_type"), index, j_redirect_uri) {
            escaped = h_escape_string(config->conn, json_string_value(j_redirect_uri));
            clause_auth_type = msprintf("(SELECT `got_id` FROM `%s` WHERE `got_name`='%s')", GLEWLWYD_TABLE_AUTHORIZATION_TYPE, escaped);
            o_free(escaped);
            json_array_append_new(json_object_get(j_query, "values"), 
                                  json_pack("{sss{ss}}", 
                                            "gc_client_id", 
                                            client_id, 
                                            "got_id",
                                              "raw",
                                              clause_auth_type));
            o_free(clause_auth_type);
          }
          if (json_array_size(json_object_get(j_query, "values")) > 0) {
            if (h_insert(config->conn, j_query, NULL) != H_OK) {
              res = G_ERROR_DB;
              y_log_message(Y_LOG_LEVEL_ERROR, "set_client_database - Error adding authorization_type");
            } else {
              res = G_OK;
            }
          }
          json_decref(j_query);
        } else {
          res = G_ERROR_DB;
          y_log_message(Y_LOG_LEVEL_ERROR, "set_client_database - Error deleting old authorization_type");
        }
      } else {
        res = G_OK;
      }
    }
    
    o_free(scope_values);
    attr_counter=0;
    for (i=0; json_object_get(j_client, "name") != NULL && json_string_length(json_object_get(j_client, "name")) > 0 && config->auth_ldap->name_property_client_write[i] != NULL; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    for (i=0; json_object_get(j_client, "description") != NULL && json_string_length(json_object_get(j_client, "description")) > 0 && config->auth_ldap->description_property_client_write[i] != NULL; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    if (json_array_size(json_object_get(j_client, "redirect_uri")) > 0) {
      free_string_array(redirect_uri_array);
      for (i=0; config->auth_ldap->redirect_uri_property_client_write[i] != NULL && json_object_get(j_client, "redirect_uri") != NULL; i++) {
        o_free(mods[attr_counter]);
        attr_counter++;
      }
    }
    for (i=0; config->auth_ldap->confidential_property_client_write[i] != NULL; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    for (i=0; config->use_scope && config->auth_ldap->scope_property_client_write[i] != NULL && json_object_get(j_client, "scope") != NULL && json_array_size(json_object_get(j_client, "scope")) > 0; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    if (json_object_get(j_client, "confidential") == json_true() && json_object_get(j_client, "password") != NULL && json_string_length(json_object_get(j_client, "password")) > 0) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    o_free(mods);
    o_free(cur_dn);
    o_free(password);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  return res;
}

/**
 * Update an existing client in the database backend
 */
int set_client_database(struct config_elements * config, const char * client_id, json_t * j_client) {
  json_t * j_query, * j_scope, * j_redirect_uri;
  int res, to_return;
  size_t index;
  char * clause_login, * clause_scope, * escaped = NULL, * password, * clause_auth_type;
  
  j_query = json_pack("{sss{}s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_CLIENT,
                      "set",
                      "where",
                        "gc_client_id",
                        client_id);
  if (json_object_get(j_client, "name") != NULL) {
    json_object_set_new(json_object_get(j_query, "set"), "gc_name", json_copy(json_object_get(j_client, "name")));
  }
  if (json_object_get(j_client, "description") != NULL) {
    json_object_set_new(json_object_get(j_query, "set"), "gc_description", json_copy(json_object_get(j_client, "description")));
  }
  if (json_object_get(j_client, "confidential") == json_true() && json_object_get(j_client, "password") != NULL) {
    json_object_set_new(json_object_get(j_query, "set"), "gc_confidential", json_integer(1));
    if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
      escaped = h_escape_string(config->conn, json_string_value(json_object_get(j_client, "password")));
      password = msprintf("PASSWORD('%s')", escaped);
    } else {
      escaped = generate_hash(config, config->hash_algorithm, json_string_value(json_object_get(j_client, "password")));
      password = msprintf("'%s'", escaped);
    }
    json_object_set_new(json_object_get(j_query, "set"), "gc_client_password", json_pack("{ss}", "raw", password));
    o_free(password);
    o_free(escaped);
  } else if (json_object_get(j_client, "confidential") == json_false()) {
    json_object_set_new(json_object_get(j_query, "set"), "gc_confidential", json_integer(0));
  }
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_object_get(j_client, "scope") != NULL && config->use_scope) {
      escaped = h_escape_string(config->conn, client_id);
      clause_login = msprintf("= (SELECT `gc_id` FROM `%s` WHERE `gc_client_id`='%s')", GLEWLWYD_TABLE_CLIENT, escaped);
      o_free(escaped);
      j_query = json_pack("{sss{s{ssss}}}",
                          "table",
                          GLEWLWYD_TABLE_CLIENT_SCOPE,
                          "where",
                            "gc_id",
                              "operator",
                              "raw",
                              "value",
                              clause_login);
      o_free(clause_login);
      res = h_delete(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
          escaped = h_escape_string(config->conn, client_id);
          clause_login = msprintf("(SELECT `gc_id` FROM `%s` WHERE `gc_client_id`='%s')", GLEWLWYD_TABLE_CLIENT, escaped);
          o_free(escaped);
          j_query = json_pack("{sss[]}",
                              "table",
                              GLEWLWYD_TABLE_CLIENT_SCOPE,
                              "values");
          json_array_foreach(json_object_get(j_client, "scope"), index, j_scope) {
            escaped = h_escape_string(config->conn, json_string_value(j_scope));
            clause_scope = msprintf("(SELECT `gs_id` FROM `%s` WHERE `gs_name`='%s')", GLEWLWYD_TABLE_SCOPE, escaped);
            o_free(escaped);
            json_array_append_new(json_object_get(j_query, "values"), json_pack("{s{ss}s{ss}}", "gc_id", "raw", clause_login, "gs_id", "raw", clause_scope));
            o_free(clause_scope);
          }
          o_free(clause_login);
          if (json_array_size(json_object_get(j_query, "values")) > 0) {
            if (h_insert(config->conn, j_query, NULL) != H_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "set_client_database - Error adding scope");
            }
          }
          json_decref(j_query);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_client_database - Error deleting old scope");
      }
      
    }
    if (json_object_get(j_client, "redirect_uri") != NULL) {
      escaped = h_escape_string(config->conn, client_id);
      clause_login = msprintf("= (SELECT `gc_id` FROM `%s` WHERE `gc_client_id`='%s')", GLEWLWYD_TABLE_CLIENT, escaped);
      o_free(escaped);
      j_query = json_pack("{sss{s{ssss}}}",
                          "table",
                          GLEWLWYD_TABLE_REDIRECT_URI,
                          "where",
                            "gc_id",
                              "operator",
                              "raw",
                              "value",
                              clause_login);
      o_free(clause_login);
      res = h_delete(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
          escaped = h_escape_string(config->conn, client_id);
          clause_login = msprintf("(SELECT `gc_id` FROM `%s` WHERE `gc_client_id`='%s')", GLEWLWYD_TABLE_CLIENT, escaped);
          o_free(escaped);
          j_query = json_pack("{sss[]}",
                              "table",
                              GLEWLWYD_TABLE_REDIRECT_URI,
                              "values");
          json_array_foreach(json_object_get(j_client, "redirect_uri"), index, j_redirect_uri) {
            json_array_append_new(json_object_get(j_query, "values"), 
                                  json_pack("{s{ss}ssss}", 
                                            "gc_id", 
                                              "raw", 
                                              clause_login, 
                                            "gru_name", 
                                            json_string_value(json_object_get(j_redirect_uri, "name")),
                                            "gru_uri",
                                            json_string_value(json_object_get(j_redirect_uri, "uri"))));
          }
          o_free(clause_login);
          if (json_array_size(json_object_get(j_query, "values")) > 0) {
            if (h_insert(config->conn, j_query, NULL) != H_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "set_client_database - Error adding redirect_uri");
            }
          }
          json_decref(j_query);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_client_database - Error deleting old redirect_uri");
      }
    }

    if (json_object_get(j_client, "authorization_type") != NULL) {
      j_query = json_pack("{sss{ss}}",
                          "table",
                          GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE,
                          "where",
                            "gc_client_id",
                            client_id);
      res = h_delete(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        j_query = json_pack("{sss[]}",
                            "table",
                            GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE,
                            "values");
        json_array_foreach(json_object_get(j_client, "authorization_type"), index, j_redirect_uri) {
          escaped = h_escape_string(config->conn, json_string_value(j_redirect_uri));
          clause_auth_type = msprintf("(SELECT `got_id` FROM `%s` WHERE `got_name`='%s')", GLEWLWYD_TABLE_AUTHORIZATION_TYPE, escaped);
          o_free(escaped);
          json_array_append_new(json_object_get(j_query, "values"), 
                                json_pack("{sss{ss}}", 
                                          "gc_client_id", 
                                          client_id, 
                                          "got_id",
                                            "raw",
                                            clause_auth_type));
          o_free(clause_auth_type);
        }
        if (json_array_size(json_object_get(j_query, "values")) > 0) {
          if (h_insert(config->conn, j_query, NULL) != H_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "set_client_database - Error adding authorization_type");
          }
        }
        json_decref(j_query);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_client_database - Error deleting old authorization_type");
      }
    }      
    to_return = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_client_database - Error updating client");
    to_return = G_ERROR_DB;
  }
  return to_return;
}

/**
 * Delete a specific client
 */
int delete_client(struct config_elements * config, const char * client, const char * source) {
  if (source == NULL || 0 == strcmp("ldap", source) || 0 == strcmp("all", source)) {
    return delete_client_ldap(config, client);
  } else {
    return delete_client_database(config, client);
  }
}

/**
 * Delete a specific client in the ldap backend
 */
int delete_client_ldap(struct config_elements * config, const char * client_id) {
  LDAP * ldap = NULL;
  int res;
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred, * servcred;
  
  char * cur_dn;
  
  cred.bv_val = config->auth_ldap->bind_passwd;
  cred.bv_len = strlen(config->auth_ldap->bind_passwd);

  if (ldap_initialize(&ldap, config->auth_ldap->uri) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error initializing ldap");
    res = G_ERROR;
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error setting ldap protocol version");
    res = G_ERROR;
  } else if ((result = ldap_sasl_bind_s(ldap, config->auth_ldap->bind_dn, ldap_mech, &cred, NULL, NULL, &servcred)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error binding to ldap server mode %s: %s", ldap_mech, ldap_err2string(result));
    res = G_ERROR;
  } else {
    cur_dn = msprintf("%s=%s,%s", config->auth_ldap->rdn_property_client_write, client_id, config->auth_ldap->base_search_client);
    
    if ((result = ldap_delete_ext_s(ldap, cur_dn, NULL, NULL)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error deleting client %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
      res = G_ERROR;
    } else {
      res = G_OK;
    }
    
    o_free(cur_dn);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  return res;
}

/**
 * Delete a specific client in the database backend
 */
int delete_client_database(struct config_elements * config, const char * client_id) {
  json_t * j_query;
  int res;
  
  j_query = json_pack("{sss{ss}}",
                      "table",
                      GLEWLWYD_TABLE_CLIENT,
                      "where",
                        "gc_client_id",
                        client_id);
  res = h_delete(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "delete_client_database - Error deleting client");
    return G_ERROR_DB;
  }
}

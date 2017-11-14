/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * Provides Json Web Tokens (jwt)
 * 
 * user CRUD services
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

#include "glewlwyd.h"

/**
 * Get a specific user in the database backend
 */
json_t * get_user_database(struct config_elements * config, const char * username) {
  json_t * j_query, * j_result, * j_scope, * j_return, * j_scope_entry;
  int res;
  char * scope_clause;
  size_t i_scope;
  
  j_query = json_pack("{sss[ssssss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_USER,
                      "columns",
                        "gu_id",
                        "gu_name AS name", 
                        "gu_email AS email",
                        "gu_login AS login",
                        "gu_additional_property_value AS additional_property_value",
                        "gu_enabled",
                      "where",
                        "gu_login",
                        username);
  res = h_select(config->conn, j_query, &j_result, NULL);
  
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result) > 0) {
      scope_clause = msprintf("IN (SELECT `gs_id` FROM %s WHERE `gu_id`='%" JSON_INTEGER_FORMAT "')", GLEWLWYD_TABLE_USER_SCOPE, json_integer_value(json_object_get(json_array_get(j_result, 0), "gu_id")));
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
        if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gu_enabled")) == 1) {
          json_object_set_new(json_array_get(j_result, 0), "enabled", json_true());
        } else {
          json_object_set_new(json_array_get(j_result, 0), "enabled", json_false());
        }
        json_object_del(json_array_get(j_result, 0), "gu_id");
        json_object_del(json_array_get(j_result, 0), "gu_enabled");
        
        json_object_set_new(json_array_get(j_result, 0), "scope", json_array());
        json_array_foreach(j_scope, i_scope, j_scope_entry) {
          json_array_append_new(json_object_get(json_array_get(j_result, 0), "scope"), json_copy(json_object_get(j_scope_entry, "gs_name")));
        }
        json_decref(j_scope);
        json_object_set_new(json_array_get(j_result, 0), "source", json_string("database"));
        
        if (config->additional_property_name != NULL && o_strlen(config->additional_property_name)) {
          json_object_set_new(json_array_get(j_result, 0), "additional_property_name", json_string(config->additional_property_name));
        } else {
          json_object_del(json_array_get(j_result, 0), "additional_property_value");
        }
        
        j_return = json_pack("{siso}", "result", G_OK, "user", json_copy(json_array_get(j_result, 0)));
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_DB);
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_database - Error executing j_query for scope");
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_database - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

/**
 * Get a specific user in the http backend
 * this is not possible, so return an error
 */
json_t * get_user_http(struct config_elements * config, const char * username) {
  json_t * j_result = NULL;

  j_result = json_pack("{si}", "result", G_ERROR_NOT_FOUND);

  return j_result;
}

/**
 * Get a specific user in the ldap backend
 */
json_t * get_user_ldap(struct config_elements * config, const char * username) {
  LDAP * ldap = NULL;
  LDAPMessage * answer = NULL, * entry;
  int j;
  json_t * j_result = NULL, * j_scope_list = get_scope_list(config);
  char * additional_property_value, * tmp;
  
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  int  scope          = LDAP_SCOPE_ONELEVEL;
  char * filter       = NULL;
  char * attrs[]      = {config->auth_ldap->name_property_user_read, config->auth_ldap->email_property_user_read, config->auth_ldap->login_property_user_read, config->auth_ldap->scope_property_user_read, o_strlen(config->auth_ldap->additional_property_value_read)>0?config->auth_ldap->additional_property_value_read:NULL, NULL};
  int  attrsonly      = 0;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred;
  struct berval *servcred, ** name_values, ** email_values, ** login_values, ** scope_values, ** additional_property_values = NULL;

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
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter_user_read, config->auth_ldap->login_property_user_read, username);
    if ((result = ldap_search_ext_s(ldap, config->auth_ldap->base_search_user, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search: %s", ldap_err2string(result));
      j_result = json_pack("{si}", "result", G_ERROR_PARAM);
    } else {
      // Looping in results, staring at offset, until the end of the list
      if (ldap_count_entries(ldap, answer) > 0) {
        entry = ldap_first_entry(ldap, answer);
          
        json_t * j_entry = json_object();
        
        if (j_entry != NULL) {
          name_values = ldap_get_values_len(ldap, entry, config->auth_ldap->name_property_user_read);
          email_values = ldap_get_values_len(ldap, entry, config->auth_ldap->email_property_user_read);
          login_values = ldap_get_values_len(ldap, entry, config->auth_ldap->login_property_user_read);
          scope_values = ldap_get_values_len(ldap, entry, config->auth_ldap->scope_property_user_read);
          if (o_strlen(config->auth_ldap->additional_property_value_read)>0) {
            additional_property_values = ldap_get_values_len(ldap, entry, config->auth_ldap->additional_property_value_read);
          }
          
          if (ldap_count_values_len(name_values) > 0) {
            json_object_set_new(j_entry, "name", json_stringn(name_values[0]->bv_val, name_values[0]->bv_len));
          }
          
          if (ldap_count_values_len(email_values) > 0) {
            json_object_set_new(j_entry, "email", json_stringn(email_values[0]->bv_val, email_values[0]->bv_len));
          }
          
          if (ldap_count_values_len(login_values) > 0) {
            json_object_set_new(j_entry, "login", json_stringn(login_values[0]->bv_val, login_values[0]->bv_len));
          }
          
          if (additional_property_values != NULL && ldap_count_values_len(additional_property_values) > 0) {
            additional_property_value = NULL;
            for (j=0; j<ldap_count_values_len(additional_property_values); j++) {
              if (additional_property_value == NULL) {
                additional_property_value = o_strndup(additional_property_values[j]->bv_val, additional_property_values[j]->bv_len);
              } else {
                tmp = msprintf("%s,%.*s", additional_property_value, additional_property_values[j]->bv_len, additional_property_values[j]->bv_val);
                o_free(additional_property_value);
                additional_property_value = tmp;
              }
            }
            if (config->additional_property_name != NULL && o_strlen(config->additional_property_name)) {
              json_object_set_new(j_entry, "additional_property_name", json_string(config->additional_property_name));
              json_object_set_new(j_entry, "additional_property_value", json_string(additional_property_value));
            }
            o_free(additional_property_value);
          }
          
          // For now a ldap user is always enabled, until I find a standard way to do it
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
          
          json_object_set_new(j_entry, "source", json_string("ldap"));
          j_result = json_pack("{siso}", "result", G_OK, "user", j_entry);
          ldap_value_free_len(name_values);
          ldap_value_free_len(email_values);
          ldap_value_free_len(login_values);
          ldap_value_free_len(scope_values);
          ldap_value_free_len(additional_property_values);
          //y_log_message(Y_LOG_LEVEL_DEBUG, "j_entry is %s", json_dumps(j_entry, JSON_ENCODE_ANY));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "Error allocating resources for j_entry");
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
 * Get the list of available scopes for a specific user
 */
json_t * get_user_scope_grant(struct config_elements * config, const char * username) {
  json_t * j_res = NULL;
  
  if (username != NULL) {
    if (config->has_auth_ldap) {
      j_res = get_user_scope_grant_ldap(config, username);
    }
    if (config->has_auth_database && !check_result_value(j_res, G_OK)) {
      json_decref(j_res);
      j_res = get_user_scope_grant_database(config, username);
    }
    if (config->has_auth_http && !check_result_value(j_res, G_OK)) {
      json_decref(j_res);
      j_res = get_user_scope_grant_http(config, username);
    }
  } else {
    j_res = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_res;
}

/**
 * Get the list of available scopes for a specific user in the http backend
 * as we have no scope in http, we return an empty list
 */
json_t * get_user_scope_grant_http(struct config_elements * config, const char * username) {
  json_t * j_result = NULL;

  j_result = json_pack("{si}", "result", G_ERROR_NOT_FOUND);

  return j_result;
}

/**
 * Get the list of available scopes for a specific user in the database backend
 */
json_t * get_user_scope_grant_database(struct config_elements * config, const char * username) {
  json_t * j_query, * j_result, * j_return;
  int res;
  char * username_escaped = h_escape_string(config->conn, username), 
       * clause_where_scope = msprintf("IN (SELECT `gs_id` FROM `%s` WHERE `gu_id` = (SELECT `gu_id` FROM `%s` WHERE `gu_login`='%s'))", GLEWLWYD_TABLE_USER_SCOPE, GLEWLWYD_TABLE_USER, username_escaped);
  
  j_query = json_pack("{sss[ss]s{s{ssss}}}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "columns",
                        "gs_name AS name",
                        "gs_description AS description",
                      "where",
                        "gs_id",
                          "operator",
                          "raw",
                          "value",
                          clause_where_scope);
  o_free(username_escaped);
  o_free(clause_where_scope);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_return = json_pack("{siso}", "result", G_OK, "scope", j_result);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

/**
 * Get the list of available scopes for a specific user in the ldap backend
 */
json_t * get_user_scope_grant_ldap(struct config_elements * config, const char * username) {
  LDAP * ldap = NULL;
  LDAPMessage * answer = NULL, * entry;
  
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  int  scope          = LDAP_SCOPE_ONELEVEL;
  char * filter       = NULL;
  char * attrs[]      = {"memberOf", config->auth_ldap->scope_property_user_read, NULL};
  int  attrsonly      = 0;
  json_t * j_return   = NULL;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred;
  struct berval *servcred;
  
  char * scope_list_escaped = NULL, * scope_escaped, * tmp;
  int i, res;
  json_t * j_query, * j_result;

  cred.bv_val = config->auth_ldap->bind_passwd;
  cred.bv_len = strlen(config->auth_ldap->bind_passwd);

  if (ldap_initialize(&ldap, config->auth_ldap->uri) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error initializing ldap");
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error setting ldap protocol version");
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if ((result = ldap_sasl_bind_s(ldap, config->auth_ldap->bind_dn, ldap_mech, &cred, NULL, NULL, &servcred)) != LDAP_SUCCESS) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error binding to ldap server mode %s: %s", ldap_mech, ldap_err2string(result));
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  } else {
    // Connection successful, doing ldap search
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter_user_read, config->auth_ldap->login_property_user_read, username);
    
    if (filter != NULL && (result = ldap_search_ext_s(ldap, config->auth_ldap->base_search_user, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search: %s", ldap_err2string(result));
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    } else if (ldap_count_entries(ldap, answer) == 0) {
      // No result found for username
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    } else {
      // ldap found some results, getting the first one
      entry = ldap_first_entry(ldap, answer);
      
      if (entry == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "ldap search: error getting first result");
        j_return = json_pack("{si}", "result", G_ERROR);
      } else {
        struct berval ** scope_values = ldap_get_values_len(ldap, entry, config->auth_ldap->scope_property_user_read);
        
        for (i=0; i < ldap_count_values_len(scope_values); i++) {
          scope_escaped = h_escape_string(config->conn, scope_values[i]->bv_val);
          if (scope_list_escaped == NULL) {
            scope_list_escaped = msprintf("'%s'", scope_escaped);
          } else {
            tmp = msprintf("%s,'%s'", scope_list_escaped, scope_escaped);
            o_free(scope_list_escaped);
            scope_list_escaped = tmp;
          }
          o_free(scope_escaped);
        }
        ldap_value_free_len(scope_values);
        
        j_query = json_pack("{sss[ss]s{s{ssss}}}",
                            "table",
                            GLEWLWYD_TABLE_SCOPE,
                            "columns",
                              "gs_name AS name",
                              "gs_description AS description",
                            "where",
                              "gs_name",
                                "operator",
                                "in",
                                "value",
                                scope_list_escaped);
        o_free(scope_list_escaped);
        res = h_select(config->conn, j_query, &j_result, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          j_return = json_pack("{siso}", "result", G_OK, "scope", j_result);
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
      }
    }
    o_free(filter);
    ldap_msgfree(answer);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  return j_return;
}

/**
 * All inclusive authentication check for a user
 */
json_t * auth_check_user_credentials_scope(struct config_elements * config, const char * username, const char * password, const char * scope_list) {
  json_t * j_res_auth = NULL, * j_res_scope = NULL, * j_res;
  
  if (scope_list == NULL && config->use_scope) {
    j_res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  } else if (username != NULL && password != NULL) {
    if (config->has_auth_ldap) {
      j_res_auth = auth_check_user_credentials_ldap(config, username, password);
      if (check_result_value(j_res_auth, G_OK)) {
        j_res_scope = auth_check_user_scope_ldap(config, username, scope_list);
      }
    }
    
    if (config->has_auth_database && !check_result_value(j_res_auth, G_OK)) {
      json_decref(j_res_auth);
      j_res_auth = auth_check_user_credentials_database(config, username, password);
      if (check_result_value(j_res_auth, G_OK)) {
        j_res_scope = auth_check_user_scope_database(config, username, scope_list);
      }
    }

    if (config->has_auth_http && !check_result_value(j_res_auth, G_OK)) {
      json_decref(j_res_auth);
      j_res_auth = auth_check_user_credentials_http(config, username, password);
      if (check_result_value(j_res_auth, G_OK)) {
        j_res_scope = auth_check_user_scope_http(config, username, scope_list);
      }
    }
    
    if (check_result_value(j_res_auth, G_OK)) {
      if (check_result_value(j_res_scope, G_OK)) {
        j_res = json_copy(j_res_scope);
      } else if (check_result_value(j_res_scope, G_ERROR_UNAUTHORIZED)) {
        j_res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      } else {
        j_res = json_pack("{si}", "result", G_ERROR);
      }
    } else {
      j_res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
    json_decref(j_res_scope);
    json_decref(j_res_auth);
  } else if (check_result_value(j_res_auth, G_ERROR_UNAUTHORIZED)) {
    j_res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  } else {
    j_res = json_pack("{si}", "result", G_ERROR);
  }
  return j_res;
}

/**
 * Check if a user has valid credentials
 */
json_t * auth_check_user_credentials(struct config_elements * config, const char * username, const char * password) {
  json_t * j_res = NULL;
  
  if (username != NULL && password != NULL && strlen(password) > 0) {
    if (config->has_auth_ldap) {
      j_res = auth_check_user_credentials_ldap(config, username, password);
    }
    if (config->has_auth_database && !check_result_value(j_res, G_OK)) {
      json_decref(j_res);
      j_res = auth_check_user_credentials_database(config, username, password);
    }
    if (config->has_auth_http && !check_result_value(j_res, G_OK)) {
      json_decref(j_res);
      j_res = auth_check_user_credentials_http(config, username, password);
    }
  } else {
    j_res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  return j_res;
}

/**
 * Check if the username and password specified are valid as a http user
 * On success, return a json array with all scope values available
 */
json_t * auth_check_user_credentials_http(struct config_elements * config, const char * username, const char * password) {
  int res, res_status;
  struct _u_response response;
  struct _u_request request;

  if (o_strlen(username) <= 0 || o_strlen(password) <= 0) {
    return json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  } else {
    ulfius_init_request(&request);
    request.http_verb = o_strdup("GET");
    request.http_url = o_strdup(config->auth_http->url);
    request.auth_basic_user = o_strdup(username);
    request.auth_basic_password = o_strdup(password);
    ulfius_init_response(&response);
    res = ulfius_send_http_request(&request, &response);
    res_status = response.status;
    ulfius_clean_response(&response);
    ulfius_clean_request(&request);
    if (res == U_OK) {
      if (res_status == 200) {
        return json_pack("{si}", "result", G_OK);
      } else {
        return json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error querying authentication server");
      return json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
  }
}

/**
 * Check if the username and password specified are valid as a database user
 * On success, return a json array with all scope values available
 */
json_t * auth_check_user_credentials_database(struct config_elements * config, const char * username, const char * password) {
  json_t * j_query, * j_result;
  char * escaped, * str_password;
  int res, res_size;
  
  if (o_strlen(username) <= 0 || o_strlen(password) <= 0) {
    return json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  } else {
    if (config->conn->type == HOEL_DB_TYPE_SQLITE) {
      escaped = generate_hash(config, config->hash_algorithm, password);
      str_password = msprintf("= '%s'", escaped);
      o_free(escaped);
    } else {
      escaped = h_escape_string(config->conn, password);
      str_password = msprintf("= PASSWORD('%s')", escaped);
      o_free(escaped);
    }
    j_query = json_pack("{sss{sss{ssss}si}}",
                        "table",
                        GLEWLWYD_TABLE_USER,
                        "where",
                          "gu_login",
                          username,
                          "gu_password",
                            "operator",
                            "raw",
                            "value",
                            str_password,
                          "gu_enabled",
                          1);
    
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    o_free(str_password);
    if (res == H_OK) {
      res_size = json_array_size(j_result);
      json_decref(j_result);
      if (res_size == 0) {
        return json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      } else if (res_size == 1) {
        return json_pack("{si}", "result", G_OK);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Error in database while getting credentials (obviously)");
        return json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error in database while executing query");
      return json_pack("{si}", "result", G_ERROR_DB);
    }
  }
}

/**
 * Check if the username and password specified are valid as a LDAP user
 */
json_t * auth_check_user_credentials_ldap(struct config_elements * config, const char * username, const char * password) {
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
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter_user_read, config->auth_ldap->login_property_user_read, username);
    
    if (config->use_scope) {
      attrs[1] = config->auth_ldap->scope_property_user_read;
    }
    if (filter != NULL && (result = ldap_search_ext_s(ldap, config->auth_ldap->base_search_user, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
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
 * Check the scope list specified for the database user and return the filtered scope_list
 */
json_t * auth_check_user_scope_database(struct config_elements * config, const char * username, const char * scope_list) {
  json_t * j_query, * j_result, * scope_list_allowed, * j_value;
  int res;
  char * scope, * scope_escaped, * saveptr, * scope_list_escaped = NULL, * scope_list_save = o_strdup(scope_list), * login_escaped = h_escape_string(config->conn, username), * scope_list_join;
  char * where_clause, * tmp;
  size_t index;
  
  if (scope_list == NULL || username == NULL) {
    scope_list_allowed = json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (scope_list_save != NULL && login_escaped != NULL) {
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
    where_clause = msprintf("IN (SELECT gs_id FROM %s WHERE gu_id = (SELECT gu_id FROM %s WHERE gu_login='%s') AND gs_id IN (SELECT gs_id FROM %s WHERE gs_name IN (%s)))", GLEWLWYD_TABLE_USER_SCOPE, GLEWLWYD_TABLE_USER, login_escaped, GLEWLWYD_TABLE_SCOPE, scope_list_escaped);
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
          scope_list_join = NULL;
          json_array_foreach(j_result, index, j_value) {
            if (scope_list_join != NULL) {
              tmp = msprintf("%s %s", scope_list_join, json_string_value(json_object_get(j_value, "gs_name")));
              o_free(scope_list_join);
              scope_list_join = tmp;
            } else {
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
        y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_scope_database - Error executing sql query");
        scope_list_allowed = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_scope_database - Error allocating resources for j_query");
      scope_list_allowed = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_scope_database - Error allocating resources for scope_list_save %s or login_escaped %s or scope_list_escaped %s", scope_list_save, login_escaped, scope_list_escaped);
    scope_list_allowed = json_pack("{si}", "result", G_ERROR);
  }
  o_free(scope_list_save);
  o_free(login_escaped);
  return scope_list_allowed;
}

/**
 * Check if user is allowed for the scope_list specified
 * Return a refined list of scope
 */
json_t * auth_check_user_scope(struct config_elements * config, const char * username, const char * scope_list) {
  json_t * j_res = NULL;
  
  if (scope_list != NULL) {
    if (config->has_auth_ldap) {
      j_res = auth_check_user_scope_ldap(config, username, scope_list);
    }
    if (config->has_auth_database && (j_res == NULL || !check_result_value(j_res, G_OK))) {
      json_decref(j_res);
      j_res = auth_check_user_scope_database(config, username, scope_list);
    }
    if (config->has_auth_http && (j_res == NULL || !check_result_value(j_res, G_OK))) {
      json_decref(j_res);
      j_res = auth_check_user_scope_http(config, username, scope_list);
    }
  } else {
    j_res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  return j_res;
}

/**
 * Check if http user is allowed for the scope_list specified
 * Return a refined list of scope
 * as we have no scope in http, we return an empty list
 */
json_t * auth_check_user_scope_http(struct config_elements * config, const char * username, const char * scope_list) {
  json_t * res        = NULL;

  return res;
}

/**
 * Check if ldap user is allowed for the scope_list specified
 * Return a refined list of scope
 */
json_t * auth_check_user_scope_ldap(struct config_elements * config, const char * username, const char * scope_list) {
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
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter_user_read, config->auth_ldap->login_property_user_read, username);
    
    if (config->use_scope) {
      attrs[1] = config->auth_ldap->scope_property_user_read;
    }
    if (filter != NULL && (result = ldap_search_ext_s(ldap, config->auth_ldap->base_search_user, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
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
        struct berval ** values = ldap_get_values_len(ldap, entry, config->auth_ldap->scope_property_user_read);
        char * new_scope_list = strdup("");
        int i;
        
        for (i=0; i < ldap_count_values_len(values); i++) {
          char * str_value = o_malloc(values[i]->bv_len + 1);
          char * scope_list_dup = o_strdup(scope_list);
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
          // User hasn't all of part of the scope requested, sending unauthorized answer
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
 * Return the list of users
 */
json_t * get_user_list(struct config_elements * config, const char * source, const char * search, long int offset, long int limit) {
  json_t * j_return, * j_source_list = NULL, * j_result_list = json_array();
  
  if (j_result_list != NULL) {
    if ((source == NULL || 0 == strcmp(source, "ldap") || 0 == strcmp(source, "all")) && config->has_auth_ldap) {
      j_source_list = get_user_list_ldap(config, search, offset, limit);
      if (check_result_value(j_source_list, G_OK)) {
        json_array_extend(j_result_list, json_object_get(j_source_list, "user"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error getting ldap list");
      }
      json_decref(j_source_list);
      j_source_list = NULL;
    }

    if ((source == NULL || 0 == strcmp(source, "http") || 0 == strcmp(source, "all")) && config->has_auth_http) {
      j_source_list = get_user_list_http(config, search, offset, limit);
      if (check_result_value(j_source_list, G_OK)) {
        json_array_extend(j_result_list, json_object_get(j_source_list, "user"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error getting ldap list");
      }
      json_decref(j_source_list);
      j_source_list = NULL;
    }
    
    if ((source == NULL || 0 == strcmp(source, "database") || 0 == strcmp(source, "all")) && json_array_size(j_result_list) < limit && config->has_auth_database) {
      j_source_list = get_user_list_database(config, search, offset, (limit - json_array_size(j_result_list)));
      if (check_result_value(j_source_list, G_OK)) {
        json_array_extend(j_result_list, json_object_get(j_source_list, "user"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error getting database list");
      }
      json_decref(j_source_list);
      j_source_list = NULL;
    }
    
    j_return = json_pack("{siso}", "result", G_OK, "user", j_result_list);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error allocating resources for j_result_list");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

/**
 * Return the list of users in the ldap backend
 */
json_t * get_user_list_ldap(struct config_elements * config, const char * search, long int offset, long int limit) {
  LDAP * ldap = NULL;
  LDAPMessage * answer = NULL, * entry;
  int i, j;
  json_t * j_result, * j_scope_list = get_scope_list(config);
  char * additional_property_value, * tmp;
  
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  int  scope          = LDAP_SCOPE_ONELEVEL;
  char * filter       = NULL;
  char * attrs[]      = {config->auth_ldap->name_property_user_read, config->auth_ldap->email_property_user_read, config->auth_ldap->login_property_user_read, config->auth_ldap->scope_property_user_read, o_strlen(config->auth_ldap->additional_property_value_read)>0?config->auth_ldap->additional_property_value_read:NULL, NULL};
  int  attrsonly      = 0;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred;
  struct berval *servcred, ** name_values, ** email_values, ** login_values, ** scope_values, ** additional_property_values = NULL;

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
                        config->auth_ldap->filter_user_read, 
                        config->auth_ldap->login_property_user_read, 
                        search_escaped,
                        config->auth_ldap->name_property_user_read, 
                        search_escaped,
                        config->auth_ldap->email_property_user_read, 
                        search_escaped);
      o_free(search_escaped);
    } else {
      filter = msprintf("(%s)", config->auth_ldap->filter_user_read);
    }
    if ((result = ldap_search_ext_s(ldap, config->auth_ldap->base_search_user, scope, filter, attrs, attrsonly, NULL, NULL, NULL, (offset+limit), &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search: %s", ldap_err2string(result));
      j_result = json_pack("{si}", "result", G_ERROR_PARAM);
    } else {
      // Looping in results, staring at offset, until the end of the list
      j_result = json_pack("{sis[]}", "result", G_OK, "user");
      if (ldap_count_entries(ldap, answer) >= offset) {
        entry = ldap_first_entry(ldap, answer);
            
        for (i=0; i<offset && entry != NULL; i++) {
          entry = ldap_next_entry(ldap, entry);
        }
        
        while (entry != NULL && i<(offset+limit)) {
          json_t * j_entry = json_object();
          
          if (j_entry != NULL) {
            name_values = ldap_get_values_len(ldap, entry, config->auth_ldap->name_property_user_read);
            email_values = ldap_get_values_len(ldap, entry, config->auth_ldap->email_property_user_read);
            login_values = ldap_get_values_len(ldap, entry, config->auth_ldap->login_property_user_read);
            scope_values = ldap_get_values_len(ldap, entry, config->auth_ldap->scope_property_user_read);
            if (o_strlen(config->auth_ldap->additional_property_value_read)>0 && config->additional_property_name != NULL && o_strlen(config->additional_property_name)) {
              additional_property_values = ldap_get_values_len(ldap, entry, config->auth_ldap->additional_property_value_read);
            }
            
            if (ldap_count_values_len(name_values) > 0) {
              json_object_set_new(j_entry, "name", json_stringn(name_values[0]->bv_val, name_values[0]->bv_len));
            }
            
            if (ldap_count_values_len(email_values) > 0) {
              json_object_set_new(j_entry, "email", json_stringn(email_values[0]->bv_val, email_values[0]->bv_len));
            }
            
            if (ldap_count_values_len(login_values) > 0) {
              json_object_set_new(j_entry, "login", json_stringn(login_values[0]->bv_val, login_values[0]->bv_len));
            }
            
            if (additional_property_values != NULL && ldap_count_values_len(additional_property_values) > 0) {
              additional_property_value = NULL;
              for (j=0; j<ldap_count_values_len(additional_property_values); j++) {
                if (additional_property_value == NULL) {
                  additional_property_value = o_strndup(login_values[j]->bv_val, login_values[j]->bv_len);
                } else {
                  tmp = msprintf("%s,%.*s", additional_property_value, login_values[j]->bv_len, login_values[j]->bv_val);
                  o_free(additional_property_value);
                  additional_property_value = tmp;
                }
              }
              if (config->additional_property_name != NULL && o_strlen(config->additional_property_name)) {
                json_object_set_new(j_entry, "additional_property_name", json_string(config->additional_property_name));
                json_object_set_new(j_entry, "additional_property_value", json_string(additional_property_value));
              }
              o_free(additional_property_value);
            }
            
            // For now a ldap user is always enabled, until I find a standard way to do it
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
            
            json_object_set_new(j_entry, "source", json_string("ldap"));
            json_array_append_new(json_object_get(j_result, "user"), j_entry);
            ldap_value_free_len(name_values);
            ldap_value_free_len(email_values);
            ldap_value_free_len(login_values);
            ldap_value_free_len(scope_values);
            ldap_value_free_len(additional_property_values);
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
 * Return the list of users in the database backend
 */
json_t * get_user_list_database(struct config_elements * config, const char * search, long int offset, long int limit) {
  json_t * j_query, * j_result, * j_scope, * j_return, * j_entry, * j_scope_entry;
  int res;
  char * scope_clause;
  size_t index, i_scope;
  
  j_query = json_pack("{sss[ssssss]sisi}",
                      "table",
                      GLEWLWYD_TABLE_USER,
                      "columns",
                        "gu_id",
                        "gu_name AS name", 
                        "gu_email AS email",
                        "gu_login AS login",
                        "gu_additional_property_value AS additional_property_value",
                        "gu_enabled",
                      "offset",
                      offset,
                      "limit",
                      limit);
  if (search != NULL && strcmp("", search) != 0) {
    char * search_escaped = h_escape_string(config->conn, search);
    char * clause_search = msprintf("IN (SELECT `gu_id` FROM `%s` WHERE `gu_name` LIKE '%%%s%%' OR `gu_email` LIKE '%%%s%%' OR `gu_login` LIKE '%%%s%%')",
                                    GLEWLWYD_TABLE_USER, search_escaped, search_escaped, search_escaped);
    json_object_set_new(j_query, "where", json_pack("{s{ssss}}", "gu_id", "operator", "raw", "value", clause_search));
    o_free(search_escaped);
    o_free(clause_search);
  }
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_return = json_pack("{sis[]}", "result", G_OK, "user");
    json_array_foreach(j_result, index, j_entry) {
      scope_clause = msprintf("IN (SELECT `gs_id` FROM %s WHERE `gu_id`='%" JSON_INTEGER_FORMAT "')", GLEWLWYD_TABLE_USER_SCOPE, json_integer_value(json_object_get(j_entry, "gu_id")));
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
        if (json_integer_value(json_object_get(j_entry, "gu_enabled")) == 1) {
          json_object_set_new(j_entry, "enabled", json_true());
        } else {
          json_object_set_new(j_entry, "enabled", json_false());
        }
        json_object_del(j_entry, "gu_id");
        json_object_del(j_entry, "gu_enabled");
        
        json_object_set_new(j_entry, "scope", json_array());
        json_array_foreach(j_scope, i_scope, j_scope_entry) {
          json_array_append_new(json_object_get(j_entry, "scope"), json_copy(json_object_get(j_scope_entry, "gs_name")));
        }
        json_decref(j_scope);
        json_object_set_new(j_entry, "source", json_string("database"));
        
        if (config->additional_property_name != NULL && o_strlen(config->additional_property_name)) {
          json_object_set_new(j_entry, "additional_property_name", json_string(config->additional_property_name));
        } else {
          json_object_del(j_entry, "additional_property_value");
        }
        
        json_array_append_new(json_object_get(j_return, "user"), json_copy(j_entry));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list_database - Error executing j_query for scope");
      }
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list_database - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

/**
 * Return the list of users in the http backend
 * as we have no user list in http, we return an empty list
 */
json_t * get_user_list_http(struct config_elements * config, const char * search, long int offset, long int limit) {
  json_t * j_return;

  j_return = json_pack("{sis[]}", "result", G_OK, "user");

  return j_return;
}

/**
 * Return a specific user
 */
json_t * get_user(struct config_elements * config, const char * login, const char * source) {
  json_t * j_return = NULL, * j_user = NULL;
  int search_ldap = (source == NULL || 0 == strcmp(source, "ldap") || 0 == strcmp(source, "all")), search_database = (source == NULL || 0 == strcmp(source, "database") || 0 == strcmp(source, "all")), search_http = (source == NULL || 0 == strcmp(source, "http") || 0 == strcmp(source, "all"));
  
  if (search_ldap) {
    if (config->has_auth_ldap) {
      j_user = get_user_ldap(config, login);
    } else {
      j_user = json_pack("{si}", "result", G_ERROR_PARAM);
    }
  }
  if (!check_result_value(j_user, G_OK) && search_database) {
    json_decref(j_user);
    if (config->has_auth_database) {
      j_user = get_user_database(config, login);
    } else {
      j_user = json_pack("{si}", "result", G_ERROR_PARAM);
    }
  }
  if (!check_result_value(j_user, G_OK) && search_http) {
    json_decref(j_user);
    if (config->has_auth_http) {
      j_user = get_user_http(config, login);
    } else {
      j_user = json_pack("{si}", "result", G_ERROR_PARAM);
    }
  }
  if (check_result_value(j_user, G_OK)) {
    j_return = json_pack("{siso}", "result", G_OK, "user", json_copy(json_object_get(j_user, "user")));
  } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  } else if (check_result_value(j_user, G_ERROR_PARAM)) {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user - Error getting user");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_user);
  
  return j_return;
}

/**
 * Checks if the user parameters are valid
 */
json_t * is_user_valid(struct config_elements * config, json_t * j_user, int add) {
  json_t * j_return = json_array(), * j_result, * j_scope;
  size_t index;
  
  if (j_return != NULL) {
    if (json_is_object(j_user)) {
      if (json_object_get(j_user, "source") != NULL && (!json_is_string(json_object_get(j_user, "source")) || (0 != strcmp(json_string_value(json_object_get(j_user, "source")), "all") && 0 != strcmp(json_string_value(json_object_get(j_user, "source")), "ldap") && 0 != strcmp(json_string_value(json_object_get(j_user, "source")), "database")))) {
        json_array_append_new(j_return, json_pack("{ss}", "source", "source is an optional string, values available are 'all', 'ldap' or 'database', default is 'database'"));
      }
      
      if (json_object_get(j_user, "name") != NULL && (!json_is_string(json_object_get(j_user, "name")) || json_string_length(json_object_get(j_user, "name")) > 128)) {
        json_array_append_new(j_return, json_pack("{ss}", "name", "name is an optional string between 0 and 128 characters"));
      }
      
      if (json_object_get(j_user, "email") != NULL && (!json_is_string(json_object_get(j_user, "email")) || json_string_length(json_object_get(j_user, "email")) > 128)) {
        json_array_append_new(j_return, json_pack("{ss}", "email", "email is an optional string between 0 and 128 characters"));
      }
      
      if (json_object_get(j_user, "additional_property_value") != NULL && (!json_is_string(json_object_get(j_user, "additional_property_value")) || json_string_length(json_object_get(j_user, "additional_property_value")) > 512)) {
        json_array_append_new(j_return, json_pack("{ss}", "additional_property_value", "additional_property_value is an optional string between 0 and 512 characters"));
      }
      
      if (json_object_get(j_user, "enabled") != NULL && !json_is_boolean(json_object_get(j_user, "enabled"))) {
        json_array_append_new(j_return, json_pack("{ss}", "enabled", "enabled is an optional boolean"));
      }
      
      if (add) {
        if (json_object_get(j_user, "login") == NULL || !json_is_string(json_object_get(j_user, "login")) || json_string_length(json_object_get(j_user, "login")) > 128) {
          json_array_append_new(j_return, json_pack("{ss}", "login", "login is a mandatory string between 0 and 128 characters"));
        } else {
          j_result = get_user(config, json_string_value(json_object_get(j_user, "login")), json_string_value(json_object_get(j_user, "source")));
          if (check_result_value(j_result, G_OK)) {
            char * message = msprintf("login '%s' already exist", json_string_value(json_object_get(j_user, "login")));
            json_array_append_new(j_return, json_pack("{ss}", "login", message));
            o_free(message);
          }
          json_decref(j_result);
        }
        
        if (json_object_get(j_user, "password") != NULL && (!json_is_string(json_object_get(j_user, "password")) || (json_string_length(json_object_get(j_user, "password")) > 0 && json_string_length(json_object_get(j_user, "password")) < 8))) {
          json_array_append_new(j_return, json_pack("{ss}", "password", "password is a string of at least 8 characters"));
        }
        
        if (config->use_scope) {
          if (json_object_get(j_user, "scope") == NULL || !json_is_array(json_object_get(j_user, "scope"))) {
            json_array_append_new(j_return, json_pack("{ss}", "scope", "scope is a mandatory array of scope names"));
          } else {
            json_array_foreach(json_object_get(j_user, "scope"), index, j_scope) {
              if (!json_is_string(j_scope)) {
                json_array_append_new(j_return, json_pack("{ss}", "scope", "scope name must be a string"));
              } else {
                j_result = get_scope(config, json_string_value(j_scope));
                if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
                  char * message = msprintf("scope name '%s' not found", json_string_value(j_scope));
                  json_array_append_new(j_return, json_pack("{ss}", "scope", message));
                  o_free(message);
                } else if (!check_result_value(j_result, G_OK)) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "is_user_valid - Error while checking scope name '%s'", json_string_value(j_scope));
                }
                json_decref(j_result);
              }
            }
          }
        }
      } else {
        if (json_object_get(j_user, "password") != NULL && (!json_is_string(json_object_get(j_user, "password")) || (json_string_length(json_object_get(j_user, "password")) > 0 && json_string_length(json_object_get(j_user, "password")) < 8))) {
          json_array_append_new(j_return, json_pack("{ss}", "password", "password is a string of at least 8 characters"));
        }

        if (config->use_scope) {
          if (json_object_get(j_user, "scope") != NULL && !json_is_array(json_object_get(j_user, "scope"))) {
            json_array_append_new(j_return, json_pack("{ss}", "scope", "scope is a mandatory array of scope names"));
          } else if (json_object_get(j_user, "scope") != NULL) {
            json_array_foreach(json_object_get(j_user, "scope"), index, j_scope) {
              if (!json_is_string(j_scope)) {
                json_array_append_new(j_return, json_pack("{ss}", "scope", "scope name must be a string"));
              } else {
                j_result = get_scope(config, json_string_value(j_scope));
                if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
                  char * message = msprintf("scope name '%s' not found", json_string_value(j_scope));
                  json_array_append_new(j_return, json_pack("{ss}", "scope", message));
                  o_free(message);
                } else if (!check_result_value(j_result, G_OK)) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "is_user_valid - Error while checking scope name '%s'", json_string_value(j_scope));
                }
                json_decref(j_result);
              }
            }
          }
        }
      }
    } else {
      json_array_append_new(j_return, json_pack("{ss}", "user", "user must be a json object"));
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_user_valid - Error allocating resources for j_result");
  }
  return j_return;
}

/**
 * Add a new user
 */
int add_user(struct config_elements * config, json_t * j_user) {
  if ((json_object_get(j_user, "source") == NULL || 0 == strcmp("database", json_string_value(json_object_get(j_user, "source")))) && config->has_auth_database) {
    return add_user_database(config, j_user);
  } else if (0 == o_strcmp("ldap", json_string_value(json_object_get(j_user, "source"))) && config->has_auth_ldap) {
    return add_user_ldap(config, j_user);
  } else if (0 == o_strcmp("http", json_string_value(json_object_get(j_user, "source"))) && config->has_auth_http) {
    return add_user_http(config, j_user);
  } else {
    return G_ERROR_PARAM;
  }
}

/**
 * Add a new user in the http backend
 * as this is not possible right now, we just retrun ok
 */
int add_user_http(struct config_elements * config, json_t * j_user) {
  int res;

  res = G_ERROR_PARAM;

  return res;
}

/**
 * Add a new user in the ldap backend
 */
int add_user_ldap(struct config_elements * config, json_t * j_user) {
  LDAP * ldap = NULL;
  int res;
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred, * servcred;
  
  LDAPMod ** mods = NULL;
  char ** scope_values = NULL;
  int nb_scope = 0, nb_attr = 3, i, attr_counter; // Default attributes are objectClass and password
  json_t * j_scope;
  size_t index;
  char * new_dn, * password = NULL;
  
  for (i=0; config->auth_ldap->login_property_user_write[i] != NULL; i++) {
    nb_attr++;
  }
  for (i=0; config->auth_ldap->name_property_user_write[i] != NULL; i++) {
    nb_attr++;
  }
  for (i=0; json_object_get(j_user, "email") != NULL && json_string_length(json_object_get(j_user, "email")) > 0 && config->auth_ldap->email_property_user_write[i] != NULL; i++) {
    nb_attr++;
  }
  for (i=0; json_object_get(j_user, "additional_property_value") != NULL && json_string_length(json_object_get(j_user, "additional_property_value")) > 0 && config->auth_ldap->additional_property_value_write[i] != NULL && config->additional_property_name != NULL && o_strlen(config->additional_property_name); i++) {
    nb_attr++;
  }
  for (i=0; config->use_scope && config->auth_ldap->scope_property_user_write[i] != NULL && json_object_get(j_user, "scope") != NULL && json_array_size(json_object_get(j_user, "scope")) > 0; i++) {
    nb_attr++;
  }
  if (config->use_scope && json_object_get(j_user, "scope") != NULL && json_array_size(json_object_get(j_user, "scope")) > 0) {
    nb_scope = json_array_size(json_object_get(j_user, "scope"));
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
int i;
    new_dn = msprintf("%s=%s,%s", config->auth_ldap->rdn_property_user_write, json_string_value(json_object_get(j_user, "login")), config->auth_ldap->base_search_user);
    
    attr_counter = 0;
    mods[attr_counter] = o_malloc(sizeof(LDAPMod));
    mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
    mods[attr_counter]->mod_type   = "objectClass";
    mods[attr_counter]->mod_values = config->auth_ldap->object_class_user_write;
    attr_counter++;
    
    for (i=0; config->auth_ldap->login_property_user_write[i] != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
      mods[attr_counter]->mod_type   = config->auth_ldap->login_property_user_write[i];
      mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(j_user, "login"));
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    for (i=0; config->auth_ldap->name_property_user_write[i] != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
      mods[attr_counter]->mod_type   = config->auth_ldap->name_property_user_write[i];
      if (json_object_get(j_user, "name") != NULL && json_string_length(json_object_get(j_user, "name")) > 0) {
        mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(j_user, "name"));
      } else {
        mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(j_user, "login"));
      }
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    for (i=0; json_object_get(j_user, "email") != NULL && json_string_length(json_object_get(j_user, "email")) > 0 && config->auth_ldap->email_property_user_write[i] != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
      mods[attr_counter]->mod_type   = config->auth_ldap->email_property_user_write[i];
      mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(j_user, "email"));
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    for (i=0; json_object_get(j_user, "additional_property_value") != NULL && json_string_length(json_object_get(j_user, "additional_property_value")) > 0 && config->auth_ldap->additional_property_value_write[i] != NULL && config->additional_property_name != NULL && o_strlen(config->additional_property_name); i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
      mods[attr_counter]->mod_type   = config->auth_ldap->additional_property_value_write[i];
      mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(j_user, "additional_property_value"));
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    for (i=0; config->use_scope && config->auth_ldap->scope_property_user_write[i] != NULL && json_object_get(j_user, "scope") != NULL && json_array_size(json_object_get(j_user, "scope")) > 0; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
      mods[attr_counter]->mod_type   = config->auth_ldap->scope_property_user_write[i];
      mods[attr_counter]->mod_values = o_realloc(scope_values, (nb_scope+1)*sizeof(char *));
      json_array_foreach(json_object_get(j_user, "scope"), index, j_scope) {
        mods[attr_counter]->mod_values[index] = (char *)json_string_value(j_scope);
        mods[attr_counter]->mod_values[index+1] = NULL;
      }
      attr_counter++;
    }
    
    if (json_object_get(j_user, "password") != NULL) {
      password = generate_hash(config, config->auth_ldap->password_algorithm_user_write, json_string_value(json_object_get(j_user, "password")));
      if (password != NULL) {
        mods[attr_counter] = o_malloc(sizeof(LDAPMod));
        mods[attr_counter]->mod_values    = o_malloc(2 * sizeof(char *));
        mods[attr_counter]->mod_op        = LDAP_MOD_REPLACE;
        mods[attr_counter]->mod_type      = config->auth_ldap->password_property_user_write;
        mods[attr_counter]->mod_values[0] = password;
        mods[attr_counter]->mod_values[1] = NULL;
        attr_counter++;
      }
    }
    
    mods[attr_counter] = NULL;
    
    if ((result = ldap_add_ext_s(ldap, new_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error adding new user %s in the ldap backend: %s", new_dn, ldap_err2string(result));
      res = G_ERROR;
    } else {
      res = G_OK;
    }
    
    o_free(scope_values);
    attr_counter=0;
    o_free(mods[attr_counter]);
    attr_counter++;
    for (i=0; config->auth_ldap->login_property_user_write[i] != NULL; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    for (i=0; config->auth_ldap->name_property_user_write[i] != NULL; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    for (i=0; json_object_get(j_user, "email") != NULL && json_string_length(json_object_get(j_user, "email")) > 0 && config->auth_ldap->email_property_user_write[i] != NULL; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    for (i=0; json_object_get(j_user, "additional_property_value") != NULL && json_string_length(json_object_get(j_user, "additional_property_value")) > 0 && config->auth_ldap->additional_property_value_write[i] != NULL && config->additional_property_name != NULL && o_strlen(config->additional_property_name); i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    for (i=0; config->use_scope && config->auth_ldap->scope_property_user_write[i] != NULL && json_object_get(j_user, "scope") != NULL && json_array_size(json_object_get(j_user, "scope")) > 0; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    if (json_object_get(j_user, "password") != NULL && json_string_length(json_object_get(j_user, "password")) > 0) {
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
 * Add a new user in the database backend
 */
int add_user_database(struct config_elements * config, json_t * j_user) {
  json_t * j_query, * j_scope;
  int res, to_return;
  size_t index;
  char * clause_login, * clause_scope, * escaped, * password;
  
  if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
    escaped = h_escape_string(config->conn, json_string_value(json_object_get(j_user, "password")));
    password = msprintf("PASSWORD('%s')", escaped);
  } else {
    escaped = generate_hash(config, config->hash_algorithm,json_string_value(json_object_get(j_user, "password")));
    password = msprintf("'%s'", escaped);
  }
  j_query = json_pack("{sss{sssssss{ss}si}}",
                      "table",
                      GLEWLWYD_TABLE_USER,
                      "values",
                        "gu_name",
                        json_object_get(j_user, "name")!=NULL?json_string_value(json_object_get(j_user, "name")):"",
                        "gu_email",
                        json_object_get(j_user, "email")!=NULL?json_string_value(json_object_get(j_user, "email")):"",
                        "gu_login",
                        json_string_value(json_object_get(j_user, "login")),
                        "gu_password",
                          "raw",
                          password,
                        "gu_enabled",
                        json_object_get(j_user, "enabled")==json_false()?0:1);
  if (config->additional_property_name != NULL && o_strlen(config->additional_property_name)) {
		json_object_set(json_object_get(j_query, "values"), "gu_additional_property_value", json_object_get(j_user, "additional_property_value")!=NULL?json_object_get(j_user, "additional_property_value"):json_null());
	}
	res = h_insert(config->conn, j_query, NULL);
  json_decref(j_query);
  o_free(escaped);
  o_free(password);
  if (res == H_OK) {
    if (json_object_get(j_user, "scope") != NULL && config->use_scope) {
      escaped = h_escape_string(config->conn, json_string_value(json_object_get(j_user, "login")));
      clause_login = msprintf("(SELECT `gu_id` FROM `%s` WHERE `gu_login`='%s')", GLEWLWYD_TABLE_USER, escaped);
      o_free(escaped);
      j_query = json_pack("{sss[]}",
                          "table",
                          GLEWLWYD_TABLE_USER_SCOPE,
                          "values");
      json_array_foreach(json_object_get(j_user, "scope"), index, j_scope) {
        escaped = h_escape_string(config->conn, json_string_value(j_scope));
        clause_scope = msprintf("(SELECT `gs_id` FROM `%s` WHERE `gs_name`='%s')", GLEWLWYD_TABLE_SCOPE, escaped);
        o_free(escaped);
        json_array_append_new(json_object_get(j_query, "values"), json_pack("{s{ss}s{ss}}", "gu_id", "raw", clause_login, "gs_id", "raw", clause_scope));
        o_free(clause_scope);
      }
      if (json_array_size(json_object_get(j_query, "values")) > 0) {
        if (h_insert(config->conn, j_query, NULL) != H_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "add_user_database - Error adding scope");
        }
      }
      o_free(clause_login);
      json_decref(j_query);
    }
    to_return = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_user_database - Error adding user");
    to_return = G_ERROR_DB;
  }
  return to_return;
}

/**
 * Update an existing user
 */
int set_user(struct config_elements * config, const char * user, json_t * j_user, const char * source) {
  if (source == NULL || 0 == strcmp("ldap", source) || 0 == strcmp("all", source)) {
    return set_user_ldap(config, user, j_user);
  } else {
    return set_user_database(config, user, j_user);
  }
}

/**
 * Update an existing user in the ldap backend
 */
int set_user_ldap(struct config_elements * config, const char * user, json_t * j_user) {
  LDAP * ldap = NULL;
  int res;
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred, * servcred;
  
  LDAPMod ** mods = NULL;
  char ** scope_values = NULL;
  int nb_scope = 0, nb_attr = 2, i, attr_counter;
  json_t * j_scope;
  size_t index;
  char * cur_dn, * password = NULL;
  
  for (i=0; json_object_get(j_user, "name") != NULL && json_string_length(json_object_get(j_user, "name")) > 0 && config->auth_ldap->name_property_user_write[i] != NULL; i++) {
    nb_attr++;
  }
  for (i=0; json_object_get(j_user, "email") != NULL && json_string_length(json_object_get(j_user, "email")) > 0 && config->auth_ldap->email_property_user_write[i] != NULL; i++) {
    nb_attr++;
  }
  for (i=0; json_object_get(j_user, "additional_property_value") != NULL && json_string_length(json_object_get(j_user, "additional_property_value")) > 0 && config->auth_ldap->additional_property_value_write[i] != NULL && config->additional_property_name != NULL && o_strlen(config->additional_property_name); i++) {
    nb_attr++;
  }
  for (i=0; config->use_scope && config->auth_ldap->scope_property_user_write[i] != NULL && json_object_get(j_user, "scope") != NULL && json_array_size(json_object_get(j_user, "scope")) > 0; i++) {
    nb_attr++;
  }
  if (config->use_scope && json_object_get(j_user, "scope") != NULL) {
    nb_scope = json_array_size(json_object_get(j_user, "scope"));
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
    cur_dn = msprintf("%s=%s,%s", config->auth_ldap->rdn_property_user_write, user, config->auth_ldap->base_search_user);
    
    attr_counter = 0;
    for (i=0; json_object_get(j_user, "name") != NULL && json_string_length(json_object_get(j_user, "name")) > 0 && config->auth_ldap->name_property_user_write[i] != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_REPLACE;
      mods[attr_counter]->mod_type   = config->auth_ldap->name_property_user_write[i];
      mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(j_user, "name"));
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    for (i=0; json_object_get(j_user, "email") != NULL && json_string_length(json_object_get(j_user, "email")) > 0 && config->auth_ldap->email_property_user_write[i] != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_REPLACE;
      mods[attr_counter]->mod_type   = config->auth_ldap->email_property_user_write[i];
      mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(j_user, "email"));
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    for (i=0; json_object_get(j_user, "additional_property_value") != NULL && json_string_length(json_object_get(j_user, "additional_property_value")) > 0 && config->auth_ldap->additional_property_value_write[i] != NULL && config->additional_property_name != NULL && o_strlen(config->additional_property_name); i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_ADD;
      mods[attr_counter]->mod_type   = config->auth_ldap->additional_property_value_write[i];
      mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(j_user, "additional_property_value"));
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    for (i=0; config->use_scope && config->auth_ldap->scope_property_user_write[i] != NULL && json_object_get(j_user, "scope") != NULL && json_array_size(json_object_get(j_user, "scope")) > 0; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_op     = LDAP_MOD_REPLACE;
      mods[attr_counter]->mod_type   = config->auth_ldap->scope_property_user_write[i];
      mods[attr_counter]->mod_values = o_realloc(scope_values, (nb_scope+1)*sizeof(char *));
      json_array_foreach(json_object_get(j_user, "scope"), index, j_scope) {
        mods[attr_counter]->mod_values[index] = (char *)json_string_value(j_scope);
        mods[attr_counter]->mod_values[index+1] = NULL;
      }
      attr_counter++;
    }
    
    if (json_object_get(j_user, "password") != NULL) {
      password = generate_hash(config, config->auth_ldap->password_algorithm_user_write, json_string_value(json_object_get(j_user, "password")));
      if (password != NULL) {
        mods[attr_counter] = o_malloc(sizeof(LDAPMod));
        mods[attr_counter]->mod_values    = o_malloc(2 * sizeof(char *));
        mods[attr_counter]->mod_op        = LDAP_MOD_REPLACE;
        mods[attr_counter]->mod_type      = config->auth_ldap->password_property_user_write;
        mods[attr_counter]->mod_values[0] = password;
        mods[attr_counter]->mod_values[1] = NULL;
        attr_counter++;
      }
    }
    
    mods[attr_counter] = NULL;
    
    if ((result = ldap_modify_ext_s(ldap, cur_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error setting new user %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
      res = G_ERROR;
    } else {
      res = G_OK;
    }
    
    o_free(scope_values);
    attr_counter = 0;
    for (i=0; json_object_get(j_user, "name") != NULL && json_string_length(json_object_get(j_user, "name")) > 0 && config->auth_ldap->name_property_user_write[i] != NULL; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    for (i=0; json_object_get(j_user, "email") != NULL && json_string_length(json_object_get(j_user, "email")) > 0 && config->auth_ldap->email_property_user_write[i] != NULL; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    for (i=0; json_object_get(j_user, "additional_property_value") != NULL && json_string_length(json_object_get(j_user, "additional_property_value")) > 0 && config->auth_ldap->additional_property_value_write[i] != NULL && config->additional_property_name != NULL && o_strlen(config->additional_property_name); i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    for (i=0; config->use_scope && config->auth_ldap->scope_property_user_write[i] != NULL && json_object_get(j_user, "scope") != NULL && json_array_size(json_object_get(j_user, "scope")) > 0; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    if (json_object_get(j_user, "password") != NULL) {
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
 * Update an existing user in the database backend
 */
int set_user_database(struct config_elements * config, const char * user, json_t * j_user) {
  json_t * j_query, * j_scope;
  int res, to_return;
  size_t index;
  char * clause_login, * clause_scope, * escaped, * password;
  
  j_query = json_pack("{sss{}s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_USER,
                      "set",
                      "where",
                        "gu_login",
                        user);
  if (json_object_get(j_user, "name") != NULL) {
    json_object_set_new(json_object_get(j_query, "set"), "gu_name", json_copy(json_object_get(j_user, "name")));
  }
  if (json_object_get(j_user, "email") != NULL) {
    json_object_set_new(json_object_get(j_query, "set"), "gu_email", json_copy(json_object_get(j_user, "email")));
  }
  if (json_object_get(j_user, "password") != NULL) {
    if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
      escaped = h_escape_string(config->conn, json_string_value(json_object_get(j_user, "password")));
      password = msprintf("PASSWORD('%s')", escaped);
    } else {
      escaped = generate_hash(config, config->hash_algorithm, json_string_value(json_object_get(j_user, "password")));
      password = msprintf("'%s'", escaped);
    }
    json_object_set_new(json_object_get(j_query, "set"), "gu_password", json_pack("{ss}", "raw", password));
    o_free(password);
    o_free(escaped);
  }
  if (json_object_get(j_user, "additional_property_value") != NULL && config->additional_property_name != NULL && o_strlen(config->additional_property_name)) {
    json_object_set_new(json_object_get(j_query, "set"), "gu_additional_property_value", json_copy(json_object_get(j_user, "additional_property_value")));
  }
  if (json_object_get(j_user, "enabled") != NULL) {
    json_object_set_new(json_object_get(j_query, "set"), "gu_enabled", json_object_get(j_user, "enabled")==json_false()?json_integer(0):json_integer(1));
  }
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_object_get(j_user, "scope") != NULL && config->use_scope) {
      escaped = h_escape_string(config->conn, user);
      clause_login = msprintf("= (SELECT `gu_id` FROM `%s` WHERE `gu_login`='%s')", GLEWLWYD_TABLE_USER, escaped);
      o_free(escaped);
      j_query = json_pack("{sss{s{ssss}}}",
                          "table",
                          GLEWLWYD_TABLE_USER_SCOPE,
                          "where",
                            "gu_id",
                              "operator",
                              "raw",
                              "value",
                              clause_login);
      o_free(clause_login);
      res = h_delete(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
          escaped = h_escape_string(config->conn, user);
          clause_login = msprintf("(SELECT `gu_id` FROM `%s` WHERE `gu_login`='%s')", GLEWLWYD_TABLE_USER, escaped);
          o_free(escaped);
          j_query = json_pack("{sss[]}",
                              "table",
                              GLEWLWYD_TABLE_USER_SCOPE,
                              "values");
          json_array_foreach(json_object_get(j_user, "scope"), index, j_scope) {
            escaped = h_escape_string(config->conn, json_string_value(j_scope));
            clause_scope = msprintf("(SELECT `gs_id` FROM `%s` WHERE `gs_name`='%s')", GLEWLWYD_TABLE_SCOPE, escaped);
            o_free(escaped);
            json_array_append_new(json_object_get(j_query, "values"), json_pack("{s{ss}s{ss}}", "gu_id", "raw", clause_login, "gs_id", "raw", clause_scope));
            o_free(clause_scope);
          }
          if (json_array_size(json_object_get(j_query, "values")) > 0) {
            if (h_insert(config->conn, j_query, NULL) != H_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "add_user_database - Error adding scope");
            }
          }
          json_decref(j_query);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_user_database - Error deleting old scope");
      }
    }
    to_return = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_user_database - Error updating user");
    to_return = G_ERROR_DB;
  }
  return to_return;
}

/**
 * Delete an existing user
 */
int delete_user(struct config_elements * config, const char * user, const char * source) {
  if (source == NULL || 0 == strcmp("ldap", source) || 0 == strcmp("all", source)) {
    return delete_user_ldap(config, user);
  } else {
    return delete_user_database(config, user);
  }
}

/**
 * Delete an existing user in the ldap backend
 */
int delete_user_ldap(struct config_elements * config, const char * user) {
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
    cur_dn = msprintf("%s=%s,%s", config->auth_ldap->rdn_property_user_write, user, config->auth_ldap->base_search_user);
    
    if ((result = ldap_delete_ext_s(ldap, cur_dn, NULL, NULL)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error deleting user %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
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
 * Delete an existing user in the database backend
 */
int delete_user_database(struct config_elements * config, const char * user) {
  json_t * j_query;
  int res;
  
  j_query = json_pack("{sss{ss}}",
                      "table",
                      GLEWLWYD_TABLE_USER,
                      "where",
                        "gu_login",
                        user);
  res = h_delete(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "delete_user_database - Error deleting user");
    return G_ERROR_DB;
  }
}

/**
 * Check if the user profile parameters are valid
 */
json_t * is_user_profile_valid(struct config_elements * config, const char * username, json_t * profile) {
  json_t * j_return = json_array(), * j_user;
  
  if (j_return != NULL) {
    if (profile == NULL || !json_is_object(profile)) {
      json_array_append_new(j_return, json_pack("{ss}", "profile", "profile must be a json object"));
    } else {
      if (json_object_get(profile, "name") != NULL && (!json_is_string(json_object_get(profile, "name")) || json_string_length(json_object_get(profile, "name")) > 512 || json_string_length(json_object_get(profile, "name")) < 1)) {
        json_array_append_new(j_return, json_pack("{ss}", "name", "name is an optional string between 1 and 512 characters"));
      }

      if (json_object_get(profile, "new_password") != NULL && !json_is_string(json_object_get(profile, "new_password")) && json_string_length(json_object_get(profile, "new_password")) > 0) {
        json_array_append_new(j_return, json_pack("{ss}", "new_password", "new_password must be a non empty string"));
      }
      if (json_object_get(profile, "old_password") != NULL && !json_is_string(json_object_get(profile, "old_password")) && json_string_length(json_object_get(profile, "old_password")) > 0) {
        json_array_append_new(j_return, json_pack("{ss}", "old_password", "old_password must be a non empty string"));
      }
      
      if (json_object_get(profile, "new_password") != NULL && json_object_get(profile, "old_password") == NULL) {
        json_array_append_new(j_return, json_pack("{ss}", "new_password", "old_password is mandatory to set a new password"));
      } else if (json_object_get(profile, "new_password") != NULL && json_object_get(profile, "old_password") != NULL) {
        j_user = auth_check_user_credentials(config, username, json_string_value(json_object_get(profile, "old_password")));
        if (check_result_value(j_user, G_ERROR_UNAUTHORIZED)) {
          json_array_append_new(j_return, json_pack("{ss}", "old_password", "old_password does not match"));
        }
        json_decref(j_user);
        
        if (json_string_length(json_object_get(profile, "new_password")) < 8) {
          json_array_append_new(j_return, json_pack("{ss}", "new_password", "new_password must be at least 8 characters"));
        }
      }
      
      if (json_object_get(profile, "name") == NULL && json_object_get(profile, "new_password") == NULL) {
        json_array_append_new(j_return, json_pack("{ss}", "profile", "you must update at least one value"));
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_user_profile_valid - Error allocating resources for j_return");
  }
  
  return j_return;
}

/**
 * Updates a user profile
 */
int set_user_profile(struct config_elements * config, const char * username, json_t * profile) {
  json_t * j_user = get_user(config, username, NULL);
  int res;
  
  if (check_result_value(j_user, G_OK)) {
    if (o_strcmp(json_string_value(json_object_get(json_object_get(j_user, "user"), "source")), "ldap") == 0) {
      res = set_user_profile_ldap(config, username, profile);
    } else {
      res = set_user_profile_database(config, username, profile);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_user_profile - Error getting j_user");
    res = G_ERROR;
  }
  json_decref(j_user);
  return res;
}

/**
 * Updates a user profile in the ldap backend
 */
int set_user_profile_ldap(struct config_elements * config, const char * username, json_t * profile) {
  LDAP * ldap = NULL;
  int res;
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  char * ldap_mech    = LDAP_SASL_SIMPLE;
  struct berval cred, * servcred;
  
  LDAPMod ** mods = NULL;
  char ** scope_values = NULL;
  int nb_attr = 2, i, attr_counter;
  char * cur_dn, * password = NULL;
  
  for (i=0; json_object_get(profile, "name") != NULL && config->auth_ldap->name_property_user_write[i] != NULL; i++) {
    nb_attr++;
  }
  if (json_object_get(profile, "new_password") != NULL) {
    nb_attr++;
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
    cur_dn = msprintf("%s=%s,%s", config->auth_ldap->rdn_property_user_write, username, config->auth_ldap->base_search_user);
    
    attr_counter = 0;
    for (i=0; json_object_get(profile, "name") != NULL && config->auth_ldap->name_property_user_write[i] != NULL; i++) {
      mods[attr_counter] = o_malloc(sizeof(LDAPMod));
      mods[attr_counter]->mod_values = o_malloc(2 * sizeof(char *));
      mods[attr_counter]->mod_op     = LDAP_MOD_REPLACE;
      mods[attr_counter]->mod_type   = config->auth_ldap->name_property_user_write[i];
      mods[attr_counter]->mod_values[0] = (char *)json_string_value(json_object_get(profile, "name"));
      mods[attr_counter]->mod_values[1] = NULL;
      attr_counter++;
    }
    
    if (json_object_get(profile, "new_password") != NULL) {
      password = generate_hash(config, config->auth_ldap->password_algorithm_user_write, json_string_value(json_object_get(profile, "new_password")));
      if (password != NULL) {
        mods[attr_counter] = o_malloc(sizeof(LDAPMod));
        mods[attr_counter]->mod_values    = o_malloc(2 * sizeof(char *));
        mods[attr_counter]->mod_op        = LDAP_MOD_REPLACE;
        mods[attr_counter]->mod_type      = config->auth_ldap->password_property_user_write;
        mods[attr_counter]->mod_values[0] = password;
        mods[attr_counter]->mod_values[1] = NULL;
        attr_counter++;
      }
    }
    
    mods[attr_counter] = NULL;
    
    if ((result = ldap_modify_ext_s(ldap, cur_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error setting user %s in the ldap backend: %s", cur_dn, ldap_err2string(result));
      res = G_ERROR;
    } else {
      res = G_OK;
    }
    
    o_free(scope_values);
    attr_counter = 0;
    for (i=0; json_object_get(profile, "name") != NULL && config->auth_ldap->name_property_user_write[i] != NULL; i++) {
      o_free(mods[attr_counter]->mod_values);
      o_free(mods[attr_counter]);
      attr_counter++;
    }
    if (json_object_get(profile, "new_password") != NULL) {
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
 * Updates a user profile in the database backend
 */
int set_user_profile_database(struct config_elements * config, const char * username, json_t * profile) {
  json_t * j_query;
  int res, to_return;
  char * escaped, * password;
  
  j_query = json_pack("{sss{}s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_USER,
                      "set",
                      "where",
                        "gu_login",
                        username);
  if (json_object_get(profile, "name") != NULL) {
    json_object_set_new(json_object_get(j_query, "set"), "gu_name", json_copy(json_object_get(profile, "name")));
  }
  if (json_object_get(profile, "new_password") != NULL) {
    if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
      escaped = h_escape_string(config->conn, json_string_value(json_object_get(profile, "new_password")));
      password = msprintf("PASSWORD('%s')", escaped);
    } else {
      escaped = generate_hash(config, config->hash_algorithm, json_string_value(json_object_get(profile, "new_password")));
      password = msprintf("'%s'", escaped);
    }
    if (password != NULL) {
      json_object_set_new(json_object_get(j_query, "set"), "gu_password", json_pack("{ss}", "raw", password));
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "set_user_profile_database - Error generating password hash");
    }
    o_free(password);
    o_free(escaped);
  }
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    to_return = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_user_profile_database - Error updating user");
    to_return = G_ERROR_DB;
  }
  return to_return;
}

/**
 * Sends a reset password email to the specified user
 */
int send_reset_user_profile_email(struct config_elements * config, const char * username, const char * ip_source) {
  json_t * j_user = get_user(config, username, NULL);
  char * mail_subject, * mail_body, * tmp, * token = NULL;
  int res;
  
  if (check_result_value(j_user, G_OK) && json_object_get(json_object_get(j_user, "user"), "email") != NULL && json_string_length(json_object_get(json_object_get(j_user, "user"), "email")) > 0) {
    mail_subject = str_replace(config->reset_password_config->email_subject, "$USERNAME", username);
    
    token = generate_user_reset_password_token(config, username, ip_source);
    if (token != NULL) {
      mail_body = str_replace(config->reset_password_config->email_template, "$URL", config->reset_password_config->page_url_prefix);
      
      tmp = str_replace(mail_body, "$USERNAME", username);
      o_free(mail_body);
      mail_body = tmp;
      
      tmp = str_replace(mail_body, "$TOKEN", token);
      o_free(mail_body);
      mail_body = tmp;
      
      if (ulfius_send_smtp_email(config->reset_password_config->smtp_host,
                                 config->reset_password_config->smtp_port,
                                 config->reset_password_config->smtp_use_tls,
                                 config->reset_password_config->smtp_verify_certificate,
                                 config->reset_password_config->smtp_user,
                                 config->reset_password_config->smtp_password,
                                 config->reset_password_config->email_from,
                                 json_string_value(json_object_get(json_object_get(j_user, "user"), "email")),
                                 NULL,
                                 NULL,
                                 mail_subject,
                                 mail_body) != U_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "send_reset_user_profile_email - Error sending reset email");
        res = G_ERROR_PARAM;
      } else {
        res = G_OK;
      }
      o_free(mail_body);
      o_free(mail_subject);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "send_reset_user_profile_email - Error generating token");
      res = G_ERROR;
    }
    o_free(token);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "send_reset_user_profile_email - Error getting user");
    res = G_ERROR;
  }
  json_decref(j_user);
  return res;
}

/**
 * Check if the reset token is valid for the specified user
 */
int is_reset_user_profile_valid(struct config_elements * config, const char * username, const char * token, const char * password) {
  json_t * j_query, * j_result;
  int res, to_return;
  char * token_hash, * col_grp_issued_at, * clause_grp_issued_at;
  
  if (token != NULL && password != NULL && strlen(password) >= 8) {
    token_hash = generate_hash(config, config->hash_algorithm, token);
    if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
      col_grp_issued_at = o_strdup("UNIX_TIMESTAMP(`grp_issued_at`)");
      clause_grp_issued_at = msprintf("> (UNIX_TIMESTAMP(NOW()) - %d)", config->reset_password_config->token_expiration);
    } else {
      col_grp_issued_at = o_strdup("grp_issued_at");
      clause_grp_issued_at = msprintf("> (strftime('%%s','now') - %d)", config->reset_password_config->token_expiration);
    }
    j_query = json_pack("{sss{sssssis{ssss}}}",
                        "table",
                        GLEWLWYD_TABLE_RESET_PASSWORD,
                        "where",
                          "grp_username",
                          username,
                          "grp_token",
                          token_hash,
                          "grp_enabled",
                          1,
                          col_grp_issued_at,
                            "operator",
                            "raw",
                            "value",
                            clause_grp_issued_at);
    o_free(col_grp_issued_at);
    o_free(clause_grp_issued_at);
    o_free(token_hash);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result) > 0) {
        to_return = G_OK;
      } else {
        to_return = G_ERROR_NOT_FOUND;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_reset_user_profile_valid - Error executing j_query");
      to_return = G_ERROR_DB;
    }
    json_decref(j_result);
  } else {
    to_return = G_ERROR_PARAM;
  }
  return to_return;
}

/**
 * Updates the user password
 */
int reset_user_profile(struct config_elements * config, const char * username, const char * token, const char * password) {
  json_t * j_query, * j_user, * j_profile;
  int res, to_return;
  char * token_hash = generate_hash(config, config->hash_algorithm, token);
  
  j_user = get_user(config, username, NULL);
  if (token_hash != NULL && check_result_value(j_user, G_OK)) {
    j_query = json_pack("{sss{sis{ss}}s{ssss}}",
                        "table",
                        GLEWLWYD_TABLE_RESET_PASSWORD,
                        "set",
                          "grp_enabled",
                          0,
                          "grp_reset_at",
                            "raw",
                            (config->conn->type==HOEL_DB_TYPE_MARIADB?"NOW()":"strftime('%s','now')"),
                        "where",
                          "grp_username",
                          username,
                          "grp_token",
                          token_hash);
    res = h_update(config->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      j_profile = json_pack("{ss}", "password", password);
      to_return = set_user(config, username, j_profile, json_string_value(json_object_get(json_object_get(j_user, "user"), "source")));
      json_decref(j_profile);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "reset_user_profile - Error executing j_query");
      to_return = G_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "reset_user_profile - Error generating token_hash");
    to_return = G_ERROR;
  }
  o_free(token_hash);
  json_decref(j_user);
  return to_return;
}

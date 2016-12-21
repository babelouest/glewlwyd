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
 * Copyright 2016 Nicolas Mora <mail@babelouest.org>
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

json_t * get_user_profile(struct config_elements * config, const char * username) {
  json_t * j_res = NULL;
  
  if (username != NULL) {
    if (config->has_auth_ldap) {
      j_res = get_user_profile_ldap(config, username);
    }
    if (config->has_auth_database && !check_result_value(j_res, G_OK)) {
      json_decref(j_res);
      j_res = get_user_profile_database(config, username);
    }
  } else {
    j_res = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_res;
}

json_t * get_user_profile_database(struct config_elements * config, const char * username) {
  json_t * j_query, * j_result, * j_return;
  int res;
  
  j_query = json_pack("{sss[ss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_USER,
                      "columns",
                        "gu_name AS name",
                        "gu_email AS email",
                      "where",
                        "gu_login",
                        username);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result) > 0) {
      j_return = json_pack("{siso}", "result", G_OK, "user", json_copy(json_array_get(j_result, 0)));
    } else {
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_profile_database - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  json_decref(j_result);
  return j_return;
}

json_t * get_user_profile_ldap(struct config_elements * config, const char * username) {
  LDAP * ldap;
  LDAPMessage * answer, * entry;
  
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  int  scope          = LDAP_SCOPE_SUBTREE;
  char * filter       = NULL;
  char * attrs[]      = {"memberOf", config->auth_ldap->name_property_user, config->auth_ldap->email_property_user, NULL};
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
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter_user, config->auth_ldap->login_property_user, username);
    
    if (filter != NULL && (result = ldap_search_ext_s(ldap, config->auth_ldap->base_search_user, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search: %s", ldap_err2string(result));
      res = json_pack("{si}", "result", G_ERROR_PARAM);
    } else if (ldap_count_entries(ldap, answer) == 0) {
      // No result found for username
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap, no entry for this username");
      res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    } else {
      // ldap found some results, getting the first one
      entry = ldap_first_entry(ldap, answer);
      
      if (entry == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "ldap search: error getting first result");
        res = json_pack("{si}", "result", G_ERROR);
      } else {
        struct berval ** name_value = ldap_get_values_len(ldap, entry, config->auth_ldap->name_property_user);
        struct berval ** email_value = ldap_get_values_len(ldap, entry, config->auth_ldap->email_property_user);
        res = json_pack("{sis{}}",  "result", G_OK,  "user");
        
        if (ldap_count_values_len(name_value) > 0) {
          json_object_set_new(json_object_get(res, "user"), "name", json_string(name_value[0]->bv_val));
        } else {
          json_object_set_new(json_object_get(res, "user"), "name", json_string(username));
        }
        
        if (ldap_count_values_len(email_value) > 0) {
          json_object_set_new(json_object_get(res, "user"), "email", json_string(email_value[0]->bv_val));
        } else {
          json_object_set_new(json_object_get(res, "user"), "email", json_string(""));
        }
        
        ldap_value_free_len(name_value);
        ldap_value_free_len(email_value);
      }
    }
    free(filter);
    ldap_msgfree(answer);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  return res;
}

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
  } else {
    j_res = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_res;
}

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
  free(username_escaped);
  free(clause_where_scope);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_return = json_pack("{siso}", "result", G_OK, "scope", j_result);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

json_t * get_user_scope_grant_ldap(struct config_elements * config, const char * username) {
  LDAP * ldap;
  LDAPMessage * answer, * entry;
  
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  int  scope          = LDAP_SCOPE_SUBTREE;
  char * filter       = NULL;
  char * attrs[]      = {"memberOf", config->auth_ldap->scope_property_user, NULL};
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
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter_user, config->auth_ldap->login_property_user, username);
    
    if (filter != NULL && (result = ldap_search_ext_s(ldap, config->auth_ldap->base_search_user, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search: %s", ldap_err2string(result));
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    } else if (ldap_count_entries(ldap, answer) == 0) {
      // No result found for username
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap, no entry for this username");
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    } else {
      // ldap found some results, getting the first one
      entry = ldap_first_entry(ldap, answer);
      
      if (entry == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "ldap search: error getting first result");
        j_return = json_pack("{si}", "result", G_ERROR);
      } else {
        struct berval ** scope_values = ldap_get_values_len(ldap, entry, config->auth_ldap->scope_property_user);
        
        for (i=0; i < ldap_count_values_len(scope_values); i++) {
          scope_escaped = h_escape_string(config->conn, scope_values[i]->bv_val);
          if (scope_list_escaped == NULL) {
            scope_list_escaped = msprintf("'%s'", scope_escaped);
          } else {
            tmp = msprintf("%s,'%s'", scope_list_escaped, scope_escaped);
            free(scope_list_escaped);
            scope_list_escaped = tmp;
          }
          free(scope_escaped);
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
        free(scope_list_escaped);
        res = h_select(config->conn, j_query, &j_result, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          j_return = json_pack("{siso}", "result", G_OK, "scope", j_result);
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
      }
    }
    free(filter);
    ldap_msgfree(answer);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  return j_return;
}

/**
 *
 * All inclusive authentication check for a user
 * 
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

json_t * auth_check_user_credentials(struct config_elements * config, const char * username, const char * password) {
  json_t * j_res = NULL;
  
  if (username != NULL && password != NULL) {
    if (config->has_auth_ldap) {
      j_res = auth_check_user_credentials_ldap(config, username, password);
    }
    if (config->has_auth_database && !check_result_value(j_res, G_OK)) {
      json_decref(j_res);
      j_res = auth_check_user_credentials_database(config, username, password);
    }
  } else {
    j_res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  return j_res;
}

/**
 * Check if the username and password specified are valid as a database user
 * On success, return a json array with all scope values available
 */
json_t * auth_check_user_credentials_database(struct config_elements * config, const char * username, const char * password) {
  json_t * j_query, * j_result;
  char * escaped, * str_password;
  int res, res_size;
  
  if (nstrlen(username) <= 0 || nstrlen(password) <= 0) {
    return json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  } else {
    if (config->conn->type == HOEL_DB_TYPE_SQLITE) {
      escaped = str2md5(password, strlen(password));
      str_password = msprintf("= '%s'", escaped);
      free(escaped);
    } else {
      escaped = h_escape_string(config->conn, password);
      str_password = msprintf("= PASSWORD('%s')", escaped);
      free(escaped);
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
    free(str_password);
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
  LDAP * ldap;
  LDAPMessage * answer, * entry;
  
  int  result, result_login;
  int  ldap_version   = LDAP_VERSION3;
  int  scope          = LDAP_SCOPE_SUBTREE;
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
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter_user, config->auth_ldap->login_property_user, username);
    
    if (config->use_scope) {
      attrs[1] = config->auth_ldap->scope_property_user;
    }
    if (filter != NULL && (result = ldap_search_ext_s(ldap, config->auth_ldap->base_search_user, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search: %s", ldap_err2string(result));
      res = json_pack("{si}", "result", G_ERROR_PARAM);
    } else if (ldap_count_entries(ldap, answer) == 0) {
      // No result found for username
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap, no entry for this username");
      res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
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
          y_log_message(Y_LOG_LEVEL_ERROR, "User '%s' error log in", username);
          res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
      }
    }
    free(filter);
    ldap_msgfree(answer);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  return res;
}

/**
 *
 * Check the scope list specified for the database user and return the filtered scope_list
 *
 */
json_t * auth_check_user_scope_database(struct config_elements * config, const char * username, const char * scope_list) {
  json_t * j_query, * j_result, * scope_list_allowed, * j_value;
  int res;
  char * scope, * scope_escaped, * saveptr, * scope_list_escaped = NULL, * scope_list_save = nstrdup(scope_list), * login_escaped = h_escape_string(config->conn, username), * scope_list_join;
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
        free(scope_list_escaped);
        scope_list_escaped = tmp;
      } else {
        scope_list_escaped = msprintf("'%s'", scope_escaped);
      }
      free(scope_escaped);
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
    free(scope_list_escaped);
    free(where_clause);
    if (j_query != NULL) {
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result) > 0) {
          scope_list_join = NULL;
          json_array_foreach(j_result, index, j_value) {
            if (scope_list_join != NULL) {
              tmp = msprintf("%s %s", scope_list_join, json_string_value(json_object_get(j_value, "gs_name")));
              free(scope_list_join);
              scope_list_join = tmp;
            } else {
              scope_list_join = strdup(json_string_value(json_object_get(j_value, "gs_name")));
            }
          }
          scope_list_allowed = json_pack("{siss}", "result", G_OK, "scope", scope_list_join);
          free(scope_list_join);
        } else {
          y_log_message(Y_LOG_LEVEL_WARNING, "Error user '%s' with scope %s", username, scope_list);
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
  free(scope_list_save);
  free(login_escaped);
  return scope_list_allowed;
}

/**
 *
 * Check if user is allowed for the scope_list specified
 * Return a refined list of scope
 *
 */
json_t * auth_check_user_scope(struct config_elements * config, const char * username, const char * scope_list) {
  json_t * j_res = NULL;
  
  if (config->has_auth_ldap) {
    j_res = auth_check_user_scope_ldap(config, username, scope_list);
  }
  if (config->has_auth_database && (j_res == NULL || check_result_value(j_res, G_OK))) {
    json_decref(j_res);
    j_res = auth_check_user_scope_database(config, username, scope_list);
  }
  return j_res;
}

/**
 *
 * Check if ldap user is allowed for the scope_list specified
 * Return a refined list of scope
 *
 */
json_t * auth_check_user_scope_ldap(struct config_elements * config, const char * username, const char * scope_list) {
  LDAP * ldap;
  LDAPMessage * answer, * entry;
  
  int  result;
  int  ldap_version   = LDAP_VERSION3;
  int  scope          = LDAP_SCOPE_SUBTREE;
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
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter_user, config->auth_ldap->login_property_user, username);
    
    if (config->use_scope) {
      attrs[1] = config->auth_ldap->scope_property_user;
    }
    if (filter != NULL && (result = ldap_search_ext_s(ldap, config->auth_ldap->base_search_user, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap search: %s", ldap_err2string(result));
      res = json_pack("{si}", "result", G_ERROR_PARAM);
    } else if (ldap_count_entries(ldap, answer) == 0) {
      // No result found for username
      y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap, no entry for this username");
      res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    } else {
      // ldap found some results, getting the first one
      entry = ldap_first_entry(ldap, answer);
      
      if (entry == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "ldap search: error getting first result");
        res = json_pack("{si}", "result", G_ERROR);
      } else {
        struct berval ** values = ldap_get_values_len(ldap, entry, config->auth_ldap->scope_property_user);
        char * new_scope_list = strdup("");
        int i;
        
        for (i=0; i < ldap_count_values_len(values); i++) {
          char * str_value = malloc(values[i]->bv_len + 1);
          char * scope_list_dup = strdup(scope_list);
          char * token, * save_ptr = NULL;
          
          snprintf(str_value, values[i]->bv_len + 1, "%s", values[i]->bv_val);
          token = strtok_r(scope_list_dup, " ", &save_ptr);
          while (token != NULL) {
            if (0 == strcmp(token, str_value)) {
              if (strlen(new_scope_list) > 0) {
                char * tmp = msprintf("%s %s", new_scope_list, token);
                free(new_scope_list);
                new_scope_list = tmp;
              } else {
                free(new_scope_list);
                new_scope_list = strdup(token);
              }
            }
            token = strtok_r(NULL, " ", &save_ptr);
          }
          free(scope_list_dup);
          free(str_value);
        }
        ldap_value_free_len(values);
        if (nstrlen(new_scope_list) > 0) {
          res = json_pack("{siss}", "result", G_OK, "scope", new_scope_list);
        } else {
          // User hasn't all of part of the scope requested, sending unauthorized answer
          y_log_message(Y_LOG_LEVEL_ERROR, "Error ldap, scope incorrect");
          res = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
      }
    }
    free(filter);
    ldap_msgfree(answer);
  }
  ldap_unbind_ext(ldap, NULL, NULL);
  return res;
}

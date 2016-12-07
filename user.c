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
  char * attrs[]      = {"memberOf", config->auth_ldap->name_property, config->auth_ldap->email_property, NULL};
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
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter, config->auth_ldap->login_property, username);
    
    if (filter != NULL && (result = ldap_search_ext_s(ldap, config->auth_ldap->base_search, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
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
        struct berval ** name_value = ldap_get_values_len(ldap, entry, config->auth_ldap->name_property);
        struct berval ** email_value = ldap_get_values_len(ldap, entry, config->auth_ldap->email_property);
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
  char * attrs[]      = {"memberOf", config->auth_ldap->scope_property, NULL};
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
    filter = msprintf("(&(%s)(%s=%s))", config->auth_ldap->filter, config->auth_ldap->login_property, username);
    
    if (filter != NULL && (result = ldap_search_ext_s(ldap, config->auth_ldap->base_search, scope, filter, attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &answer)) != LDAP_SUCCESS) {
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
        struct berval ** scope_values = ldap_get_values_len(ldap, entry, config->auth_ldap->scope_property);
        
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

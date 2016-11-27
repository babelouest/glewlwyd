/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * 
 * main functions definitions
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

#include <string.h>

#include "glewlwyd.h"

int check_auth_type_auth_code_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  // The most used authorization type: client redirects user to login page, 
  // Then if authorized, glewlwyd redirects to redirect_uri with a code in the uri
  // If necessary, two intermediate steps can be used: login page and grant access page
  struct config_elements * config = (struct config_elements *)user_data;
  char * authorization_code = NULL, * redirect_url, * cb_encoded, * query;
  const char * ip_source = get_ip_source(request);
  int check;
  json_t * session_payload, * j_scope;
  time_t now;
  
  // Check if client_id and redirect_uri are valid
  check = client_check(config, GLEWLWYD_AUHORIZATION_TYPE_IMPLICIT, u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "redirect_uri"));
  if (check == G_OK) {
    // Client is allowed to use implicit grant with this redirection_uri
    session_payload = session_check(config, request);
    if (check_result_value(session_payload, G_OK)) {
      // User Session is valid
      time(&now);
      if (config->use_scope) {
        j_scope = auth_check_scope(config, json_string_value(json_object_get(session_payload, "username")), u_map_get(request->map_url, "scope"));
        if (check_result_value(j_scope, G_OK)) {
          // User is allowed for this scope
          if (auth_check_client_user_scope(config, u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(session_payload, "username")), json_string_value(json_object_get(j_scope, "scope"))) == G_OK) {
            // User has granted access to the cleaned scope list for this client
            // Generate code, generate the url and redirect to it
            authorization_code = generate_authorization_code(config, json_string_value(json_object_get(session_payload, "username")), u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(j_scope, "scope")), u_map_get(request->map_url, "redirect_uri"), ip_source);
            redirect_url = msprintf("%s#code=%s%s%s", u_map_get(request->map_url, "redirect_uri"), authorization_code, (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
            ulfius_add_header_to_response(response, "Location", redirect_url);
            free(redirect_url);
            free(authorization_code);
            response->status = 302;
          } else {
            // User has not granted access to the cleaned scope list for this client, redirect to grant access page
            cb_encoded = url_encode(request->http_url);
            query = generate_query_parameters(request);
            redirect_url = msprintf("../../%s/grant.html?%s", config->static_files_prefix, query);
            ulfius_add_header_to_response(response, "Location", redirect_url);
            free(redirect_url);
            free(cb_encoded);
            free(query);
            response->status = 302;
          }
        } else {
          // Scope is not allowed for this user
          response->status = 302;
          redirect_url = msprintf("%s#error=invalid_scope%s%s", u_map_get(request->map_url, "redirect_uri"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
          ulfius_add_header_to_response(response, "Location", redirect_url);
          free(redirect_url);
        }
        json_decref(j_scope);
      } else {
        // Generate code, generate the url and redirect to it
        authorization_code = generate_authorization_code(config, json_string_value(json_object_get(session_payload, "username")), u_map_get(request->map_url, "client_id"), NULL, u_map_get(request->map_url, "redirect_uri"), ip_source);
        redirect_url = msprintf("%s#code=%s%s%s", u_map_get(request->map_url, "redirect_uri"), authorization_code, (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        free(redirect_url);
        free(authorization_code);
        response->status = 302;
      }
    } else {
      // Redirect to login page
      cb_encoded = url_encode(request->http_url);
      query = generate_query_parameters(request);
      redirect_url = msprintf("../../%s/login.html?%s", config->static_files_prefix, query);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      free(redirect_url);
      free(cb_encoded);
      free(query);
      response->status = 302;
    }
    json_decref(session_payload);
  } else {
    // client is not authorized with this redirect_uri
    response->status = 302;
    redirect_url = msprintf("%s#error=unauthorized_client%s%s", u_map_get(request->map_url, "redirect_uri"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
    ulfius_add_header_to_response(response, "Location", redirect_url);
    free(redirect_url);
  }
  return U_OK;
}

int check_auth_type_access_token_request (const struct _u_request * request, struct _u_response * response, void * user_data) {
  /*
   select gco_id from g_code 
     where gco_code_hash='1cd5524ab8ded892ee116547f0dbb983' 
       and gco_enabled=1 
       and gco_ip_source='127.0.0.1' 
       and UNIX_TIMESTAMP(gco_date) > (UNIX_TIMESTAMP(NOW()) - 600)
       and gru_id=(select gru_id from g_redirect_uri where gru_uri='http:localhost/example-client1.com/cb1' and gc_id=(SELECT gc_id from g_client WHERE gc_client_id='client1_id')) 
       and gc_id=(SELECT gc_id from g_client WHERE gc_client_id='client1_id');
  */
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_query, * j_result, * j_scope, * j_element;
  size_t index;
  int res;
  json_int_t gco_id;
  const char * code = u_map_get(request->map_post_body, "code"), 
             * client_id = u_map_get(request->map_post_body, "client_id"), 
             * redirect_uri = u_map_get(request->map_post_body, "redirect_uri"),
             * ip_source = get_ip_source(request);
  char * username, * code_hash, * escape, * escape_ip_source, * clause_redirect_uri, * clause_client_id, * col_gco_date, * clause_gco_date, * clause_scope, * scope_list = NULL, * tmp;
  time_t now;
  char * refresh_token, * access_token;

  if (code != NULL && client_id != NULL) {
    code_hash = str2md5(code, strlen(code));
    escape_ip_source = h_escape_string(config->conn, ip_source);
    escape = h_escape_string(config->conn, redirect_uri);
    clause_redirect_uri = msprintf("(SELECT `gru_id` FROM `%s` WHERE `gru_uri`='%s')", GLEWLWYD_TABLE_REDIRECT_URI, escape);
    free(escape);
    escape = h_escape_string(config->conn, client_id);
    clause_client_id = msprintf("(SELECT `gc_id` FROM `%s` WHERE `gc_client_id`='%s')", GLEWLWYD_TABLE_CLIENT, escape);
    free(escape);
    
    if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
      col_gco_date = nstrdup("UNIX_TIMESTAMP(`gco_date`)");
      clause_gco_date = nstrdup("(UNIX_TIMESTAMP(NOW()) - 600)");
    } else {
      col_gco_date = nstrdup("gco_date");
      clause_gco_date = nstrdup("(strftime('%s','now') - 600)");
    }
    
    j_query = json_pack("{sss[ss]s{si ss ss s{ssss} s{ssss} s{ssss}}}",
                        "table",
                        GLEWLWYD_TABLE_CODE,
                        "columns",
                          "gco_id",
                          "gco_username",
                        "where",
                          "gco_enabled",
                          1,
                          "gco_code_hash",
                          code_hash,
                          "gco_ip_source",
                          escape_ip_source,
                          "gru_id",
                            "operator",
                            "raw",
                            "value",
                            clause_redirect_uri,
                          "gc_id",
                            "operator",
                            "raw",
                            "value",
                            clause_client_id,
                          col_gco_date,
                            "operator",
                            "raw",
                            "value",
                            clause_gco_date);
    free(clause_gco_date);
    free(col_gco_date);
    free(clause_client_id);
    free(clause_redirect_uri);
    free(escape_ip_source);
    free(code_hash);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result) > 0) {
        // Code and redirect_uri look good, generate refresh and access tokens
        
        // Get username
        username = nstrdup(json_string_value(json_object_get(json_array_get(j_result, 0), "gco_username")));
        
        // Get scope_list (if any)
        if (config->use_scope) {
          gco_id = json_integer_value(json_object_get(json_array_get(j_result, 0), "gco_id"));
          clause_scope = msprintf("(SELECT `gs_id` FROM `%s` WHERE `gc_id`=%" JSON_INTEGER_FORMAT ")", GLEWLWYD_TABLE_CODE_SCOPE, gco_id);
          j_query = json_pack("{sss[s]s{ssss}}",
                              "table",
                              GLEWLWYD_TABLE_SCOPE,
                              "columns",
                              "gs_name",
                              "where",
                                "gs_id",
                                  "operator",
                                  "raw",
                                  "value",
                                  clause_scope);
          free(clause_scope);
          res = h_select(config->conn, j_query, &j_scope, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            json_array_foreach(j_scope, index, j_element) {
              if (scope_list == NULL) {
                scope_list = nstrdup(json_string_value(json_object_get(j_element, "gs_name")));
              } else {
                tmp = msprintf("%s %s", scope_list, json_string_value(json_object_get(j_element, "gs_name")));
                free(scope_list);
                scope_list = tmp;
              }
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - error executing j_query scope");
            response->status = 500;
          }
          json_decref(j_scope);
        }
        time(&now);
        refresh_token = generate_refresh_token(config, username, GLEWLWYD_AUHORIZATION_TYPE_CODE, ip_source, scope_list, now);
        if (refresh_token != NULL) {
          access_token = generate_access_token(config, refresh_token, username, GLEWLWYD_AUHORIZATION_TYPE_CODE, ip_source, scope_list, now);
          if (access_token != NULL) {
            // Disable gco_id entry
            j_query = json_pack("{sss{si}s{sI}}",
                                "table",
                                GLEWLWYD_TABLE_CODE,
                                "set",
                                  "gco_enabled",
                                  0,
                                "where",
                                  "gco_id",
                                  gco_id);
            res = h_update(config->conn, j_query, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              // Finally, the tokens are all here, no error, no problem
              response->json_body = json_pack("{sssssssi}",
                                    "token_type",
                                    "bearer",
                                    "access_token",
                                    access_token,
                                    "refresh_token",
                                    refresh_token,
                                    "iat",
                                    now);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - error executing j_query update");
              response->status = 500;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - error generating access_token");
            response->status = 500;
          }
          free(access_token);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - error generating refresh_token");
          response->status = 500;
        }
        free(refresh_token);
      } else {
        response->status = 400;
        response->json_body = json_pack("{ss}", "error", "invalid_request");
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - error executing j_query");
      response->status = 500;
    }
  } else {
    response->status = 400;
    response->json_body = json_pack("{ss}", "error", "invalid_request");
  }
  return U_OK;
}

int check_auth_type_implicit_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  // The second more simple authorization type: client redirects user to login page, 
  // Then if authorized, glewlwyd redirects to redirect_uri with the access_token in the uri
  // If necessary, two intermediate steps can be used: login page and grant access page
  struct config_elements * config = (struct config_elements *)user_data;
  char * access_token = NULL, * redirect_url, * cb_encoded, * query;
  const char * ip_source = get_ip_source(request);
  int check;
  json_t * session_payload, * j_scope;
  time_t now;
  
  // Check if client_id and redirect_uri are valid
  check = client_check(config, GLEWLWYD_AUHORIZATION_TYPE_IMPLICIT, u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "redirect_uri"));
  if (check == G_OK) {
    // Client is allowed to use implicit grant with this redirection_uri
    session_payload = session_check(config, request);
    if (check_result_value(session_payload, G_OK)) {
      // User Session is valid
      time(&now);
      if (config->use_scope) {
        j_scope = auth_check_scope(config, json_string_value(json_object_get(session_payload, "username")), u_map_get(request->map_url, "scope"));
        if (check_result_value(j_scope, G_OK)) {
          // User is allowed for this scope
          if (auth_check_client_user_scope(config, u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(session_payload, "username")), json_string_value(json_object_get(j_scope, "scope"))) == G_OK) {
            // User has granted access to the cleaned scope list for this client
            access_token = generate_access_token(config, NULL, json_string_value(json_object_get(session_payload, "username")), GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, ip_source, NULL, now);
            if (u_map_get(request->map_url, "state") != NULL) {
              redirect_url = msprintf("%s#access_token=%s&token_type=bearer&expires_in=%d&state=%s", u_map_get(request->map_url, "redirect_uri"), access_token, config->access_token_expiration, u_map_get(request->map_url, "state"));
            } else {
              redirect_url = msprintf("%s#access_token=%s&token_type=bearer&expires_in=%d", u_map_get(request->map_url, "redirect_uri"), access_token, config->access_token_expiration);
            }
            ulfius_add_header_to_response(response, "Location", redirect_url);
            free(redirect_url);
            free(access_token);
            response->status = 302;
          } else {
            // User has not granted access to the cleaned scope list for this client, redirect to grant access page
            cb_encoded = url_encode(request->http_url);
            query = generate_query_parameters(request);
            redirect_url = msprintf("../../%s/grant.html?%s", config->static_files_prefix, query);
            ulfius_add_header_to_response(response, "Location", redirect_url);
            free(redirect_url);
            free(cb_encoded);
            free(query);
            response->status = 302;
          }
        } else {
          // Scope is not allowed for this user
          response->status = 302;
          redirect_url = msprintf("%s#error=invalid_scope%s%s", u_map_get(request->map_url, "redirect_uri"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
          ulfius_add_header_to_response(response, "Location", redirect_url);
          free(redirect_url);
        }
        json_decref(j_scope);
      } else {
        // Generate access_token, generate the url and redirect to it
        access_token = generate_access_token(config, NULL, json_string_value(json_object_get(session_payload, "username")), GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, ip_source, NULL, now);
        if (u_map_get(request->map_url, "state") != NULL) {
          redirect_url = msprintf("%s#access_token=%s&token_type=bearer&expires_in=%d&state=%s", access_token, u_map_get(request->map_url, "redirect_uri"), config->access_token_expiration, u_map_get(request->map_url, "state"));
        } else {
          redirect_url = msprintf("%s#access_token=%s&token_type=bearer&expires_in=%d", access_token, u_map_get(request->map_url, "redirect_uri"), config->access_token_expiration);
        }
        ulfius_add_header_to_response(response, "Location", redirect_url);
        free(redirect_url);
        response->status = 302;
      }
    } else {
      // Redirect to login page
      cb_encoded = url_encode(request->http_url);
      query = generate_query_parameters(request);
      redirect_url = msprintf("../../%s/login.html?%s", config->static_files_prefix, query);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      free(redirect_url);
      free(cb_encoded);
      free(query);
      response->status = 302;
    }
    json_decref(session_payload);
  } else {
    // client is not authorized with this redirect_uri
    response->status = 302;
    redirect_url = msprintf("%s#error=unauthorized_client%s%s", u_map_get(request->map_url, "redirect_uri"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
    ulfius_add_header_to_response(response, "Location", redirect_url);
    free(redirect_url);
  }
  return U_OK;
}

int check_auth_type_resource_owner_pwd_cred (const struct _u_request * request, struct _u_response * response, void * user_data) {
  // The more simple authorization type: username and password are given in the POST parameters, the access_token and refresh_token in a json object are returned
  struct config_elements * config = (struct config_elements *)user_data;
  time_t now;
  char * refresh_token, * access_token;
  const char * ip_source = get_ip_source(request);
  json_t * j_result = auth_check(config, u_map_get(request->map_post_body, "username"), u_map_get(request->map_post_body, "password"), u_map_get(request->map_post_body, "scope"));
  
  if (check_result_value(j_result, G_OK)) {
    time(&now);
    refresh_token = generate_refresh_token(config, u_map_get(request->map_post_body, "username"), GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, ip_source, u_map_get(request->map_post_body, "scope"), now);
    if (refresh_token != NULL) {
      access_token = generate_access_token(config, refresh_token, u_map_get(request->map_post_body, "username"), GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, ip_source, u_map_get(request->map_post_body, "scope"), now);
      if (access_token != NULL) {
          response->json_body = json_pack("{sssssssi}",
                                "token_type",
                                "bearer",
                                "access_token",
                                access_token,
                                "refresh_token",
                                refresh_token,
                                "iat",
                                now);
        if (response->json_body != NULL) {
          if (config->use_scope) {
            json_object_set_new(response->json_body, "scope", json_string(u_map_get(request->map_post_body, "scope")));
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - error allocating resources for response->json_body");
          response->status = 500;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - error allocating resources for access_token");
        response->status = 500;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - error allocating resources for refresh_token");
      response->status = 500;
    }
  } else if (check_result_value(j_result, G_ERROR_UNAUTHORIZED)) {
    response->status = 403;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - error checking credentials");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int check_auth_type_client_credentials_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

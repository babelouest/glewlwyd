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
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "glewlwyd.h"

int check_auth_type_auth_code_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int check_auth_type_access_token_request (const struct _u_request * request, struct _u_response * response, void * user_data) {
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

// Test case: response_type=token&client_id=client1_id&redirect_uri=http%3A%2F%2Flocalhost%2Fexample-client1.com%2Fcb1&scope=scope1&state=abcd
// https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/auth/?response_type=token&client_id=client1_id&redirect_uri=http%3A%2F%2Flocalhost%2Fexample-client1.com%2Fcb1&scope=scope1&state=abcd
int check_auth_type_implicit_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  // The second more simple authorization type: client redirects user to login page, 
  // Then if authorized, glewlwyd redirects to redirect_uri with the access_token in the uri
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
      y_log_message(Y_LOG_LEVEL_DEBUG, "grut 1");
      // User Session is valid
      time(&now);
      if (config->use_scope) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "grut 2");
        j_scope = auth_check_scope(config, json_string_value(json_object_get(json_object_get(session_payload, "session"), "username")), u_map_get(request->map_url, "scope"));
        if (check_result_value(j_scope, G_OK)) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "grut 3");
          // User is allowed for this scope
          if (auth_check_client_user_scope(config, u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(json_object_get(session_payload, "session"), "username")), json_string_value(json_object_get(j_scope, "scope"))) == G_OK) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "grut 4");
            // User has granted access to the cleaned scope list for this client
            access_token = generate_access_token(config, NULL, json_string_value(json_object_get(json_object_get(session_payload, "session"), "username")), GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, ip_source, NULL, now);
            if (u_map_get(request->map_url, "state") != NULL) {
              redirect_url = msprintf("%s#access_token=%s&token_type=bearer&expires_in=%d&state=%s", access_token, u_map_get(request->map_url, "redirect_uri"), config->access_token_expiration, u_map_get(request->map_url, "state"));
            } else {
              redirect_url = msprintf("%s#access_token=%s&token_type=bearer&expires_in=%d", access_token, u_map_get(request->map_url, "redirect_uri"), config->access_token_expiration);
            }
            ulfius_add_header_to_response(response, "Location", redirect_url);
            free(redirect_url);
            free(access_token);
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "grut 5");
            // User has not granted access to the cleaned scope list for this client, redirect to grant access page
            cb_encoded = url_encode(request->http_url);
            query = generate_query_parameters(request);
            redirect_url = msprintf("../../%s/grant.html?%s", config->static_files_prefix, query);
            ulfius_add_header_to_response(response, "Location", redirect_url);
            free(redirect_url);
            free(cb_encoded);
            free(query);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "grut 6");
          // Scope is not allowed for this user
          response->status = 403;
        }
        json_decref(j_scope);
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "grut 7");
        // Generate access_token, generate the url and redirect to it
        access_token = generate_access_token(config, NULL, json_string_value(json_object_get(json_object_get(session_payload, "session"), "username")), GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, ip_source, NULL, now);
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
      y_log_message(Y_LOG_LEVEL_DEBUG, "grut 8");
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
    // Scope is not allowed for this user
    response->status = 403;
    y_log_message(Y_LOG_LEVEL_DEBUG, "grut 9");
  }
  return U_OK;
}

int check_auth_type_client_credentials_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

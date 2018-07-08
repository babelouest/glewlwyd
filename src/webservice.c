/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * Callback functions definition
 *
 * Copyright 2018 Nicolas Mora <mail@babelouest.org>
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

int callback_glewlwyd_options (const struct _u_request * request, struct _u_response * response, void * user_data) {
  u_map_put(response->map_header, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  u_map_put(response->map_header, "Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Bearer, Authorization");
  u_map_put(response->map_header, "Access-Control-Max-Age", "1800");
  return U_CALLBACK_COMPLETE;
}

int callback_glewlwyd_server_configuration (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * json_body = json_pack("{ssssss}", 
                        "api_prefix", 
                        ((struct config_elements *)user_data)->api_prefix,
                        "admin_scope",
                        ((struct config_elements *)user_data)->glewlwyd_resource_config_admin->oauth_scope,
                        "profile_scope",
                        ((struct config_elements *)user_data)->glewlwyd_resource_config_profile->oauth_scope);
  ulfius_set_json_body_response(response, 200, json_body);
  json_decref(json_body);
  return U_CALLBACK_CONTINUE;
}

int callback_default (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * json_body = json_pack("{ssss}", "error", "resource not found", "message", "no resource available at this address");
  ulfius_set_json_body_response(response, 404, json_body);
  json_decref(json_body);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_validate_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_param = ulfius_get_json_body_request(request, NULL), * j_result = NULL;
  const char * ip_source = get_ip_source(request);
  char * session_uid, session_str_array[129];
  time_t now;
  
  time(&now);
  if (j_param != NULL) {
    if (json_object_get(j_param, "username") != NULL && json_is_string(json_object_get(j_param, "username"))) {
      if (json_object_get(j_param, "scheme") != NULL && json_is_string(json_object_get(j_param, "scheme"))) {
        if (0 == o_strcmp(json_string_value(json_object_get(j_param, "scheme")), "password")) {
          if (json_object_get(j_param, "password") != NULL && json_is_string(json_object_get(j_param, "password"))) {
            j_result = auth_check_user_credentials(config, json_string_value(json_object_get(j_param, "username")), json_string_value(json_object_get(j_param, "password")));
            if (check_result_value(j_result, G_OK)) {
              if ((session_uid = (char *)u_map_get(request->map_cookie, GLEWLWYD_DEFAULT_SESSION_KEY)) == NULL) {
                session_uid = rand_string(session_str_array, 128);
              }
              if (update_session(config, session_uid, json_string_value(json_object_get(j_param, "username")), "password", GLEWLWYD_DEFAULT_SESSION_EXPIRATION_PASSWORD) != G_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_validate_user - Error update_session");
                response->status = 500;
              } else {
                ulfius_add_cookie_to_response(response, GLEWLWYD_DEFAULT_SESSION_KEY, session_uid, NULL, GLEWLWYD_DEFAULT_SESSION_EXPIRATION_COOKIE, NULL, NULL, 0, 0);
              }
            } else {
              if (check_result_value(j_result, G_ERROR_UNAUTHORIZED)) {
                y_log_message(Y_LOG_LEVEL_WARNING, "Security - Error login/password for username %s at IP Address %s", json_string_value(json_object_get(j_param, "username")), ip_source);
              }
              if ((session_uid = (char *)u_map_get(request->map_cookie, GLEWLWYD_DEFAULT_SESSION_KEY)) != NULL && update_session(config, session_uid, json_string_value(json_object_get(j_param, "username")), "password", 0) != G_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_validate_user - Error update_session");
              } else {
                ulfius_add_cookie_to_response(response, GLEWLWYD_DEFAULT_SESSION_KEY, session_uid, NULL, GLEWLWYD_DEFAULT_SESSION_EXPIRATION_COOKIE, NULL, NULL, 0, 0);
              }
              response->status = 401;
            }
            json_decref(j_result);
          } else {
            ulfius_set_string_body_response(response, 400, "password is mandatory");
          }
        } else {
          // Look for another scheme
          response->status = 401; // TODO
        }
      } else {
        ulfius_set_string_body_response(response, 400, "scheme is mandatory");
      }
    } else {
      ulfius_set_string_body_response(response, 400, "username is mandatory");
    }
  } else {
    ulfius_set_string_body_response(response, 400, "Input parameters must be in JSON format");
  }
  json_decref(j_param);

  return U_CALLBACK_CONTINUE;
}

#ifdef DEBUG
// TODO: Remove on release
int callback_glewlwyd_check_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session;
  const char * username = u_map_get(request->map_url, "username"), * session_uid = u_map_get(request->map_cookie, GLEWLWYD_DEFAULT_SESSION_KEY);
  
  if (session_uid != NULL) {
    if (username == NULL) {
      j_session = get_session(config, session_uid);
    } else {
      j_session = get_session_for_username(config, session_uid, username);
    }
    ulfius_set_json_body_response(response, 200, json_object_get(j_session, "session"));
    json_decref(j_session);
  } else {
    response->status = 404;
  }
  
  return U_CALLBACK_COMPLETE;
}
#endif

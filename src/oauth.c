/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * Provides Json Web Tokens (jwt)
 * 
 * OAuth2 authorization management
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

#include <string.h>

#include "glewlwyd.h"

/**
 * The most used authorization type: if client is authorized and has granted access to scope, 
 * glewlwyd redirects to redirect_uri with a code in the uri
 * If necessary, two intermediate steps can be used: login page and grant access page
 */
int check_auth_type_auth_code_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  char * authorization_code = NULL, * redirect_url, * cb_encoded, * query;
  const char * ip_source = get_ip_source(request);
  json_t * session_payload, * j_scope, * j_client_check;
  time_t now;
  
  // Check if client is allowed to perform this request
  j_client_check = client_check(config, u_map_get(request->map_url, "client_id"), request->auth_basic_user, request->auth_basic_password, u_map_get(request->map_url, "redirect_uri"), GLEWLWYD_AUHORIZATION_TYPE_AUTHORIZATION_CODE);
  if (check_result_value(j_client_check, G_OK)) {
    // Client is allowed to use auth_code grant with this redirection_uri
    session_payload = session_check(config, u_map_get(request->map_cookie, config->session_key));
    if (check_result_value(session_payload, G_OK)) {
      if (u_map_get(request->map_url, "login_validated") != NULL) {
        // User Session is valid and confirmed by the owner
        time(&now);
        if (config->use_scope) {
          j_scope = auth_check_user_scope(config, json_string_value(json_object_get(json_object_get(session_payload, "grants"), "username")), u_map_get(request->map_url, "scope"));
          if (check_result_value(j_scope, G_OK)) {
            // User is allowed for this scope
            if (auth_check_client_user_scope(config, u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(json_object_get(session_payload, "grants"), "username")), json_string_value(json_object_get(j_scope, "scope"))) == G_OK) {
              // User has granted access to the cleaned scope list for this client
              // Generate code, generate the url and redirect to it
              authorization_code = generate_authorization_code(config, json_string_value(json_object_get(json_object_get(session_payload, "grants"), "username")), u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(j_scope, "scope")), u_map_get(request->map_url, "redirect_uri"), ip_source);
              redirect_url = msprintf("%s%scode=%s%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), authorization_code, (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
              o_free(authorization_code);
              response->status = 302;
            } else {
              // User has not granted access to the cleaned scope list for this client, redirect to grant access page
              cb_encoded = url_encode(request->http_url);
              query = generate_query_parameters(request);
              redirect_url = msprintf("%s%s", config->grant_url, query);
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
              o_free(cb_encoded);
              o_free(query);
              response->status = 302;
            }
          } else {
            // Scope is not allowed for this user
            response->status = 302;
            redirect_url = msprintf("%s%serror=invalid_scope%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
          }
          json_decref(j_scope);
        } else {
          // Generate code, generate the url and redirect to it
          authorization_code = generate_authorization_code(config, json_string_value(json_object_get(json_object_get(session_payload, "grants"), "username")), u_map_get(request->map_url, "client_id"), NULL, u_map_get(request->map_url, "redirect_uri"), ip_source);
          redirect_url = msprintf("%s%scode=%s%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), authorization_code, (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
          o_free(authorization_code);
          response->status = 302;
        }
      } else {
        // Redirect to login page
        cb_encoded = url_encode(request->http_url);
        query = generate_query_parameters(request);
        redirect_url = msprintf("%s%s", config->login_url, query);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
        o_free(cb_encoded);
        o_free(query);
        response->status = 302;
      }
    } else {
      // Redirect to login page
      cb_encoded = url_encode(request->http_url);
      query = generate_query_parameters(request);
      redirect_url = msprintf("%s%s", config->login_url, query);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      o_free(cb_encoded);
      o_free(query);
      response->status = 302;
    }
    json_decref(session_payload);
  } else {
    // client is not authorized with this redirect_uri
    response->status = 302;
    redirect_url = msprintf("%s%serror=unauthorized_client%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
    ulfius_add_header_to_response(response, "Location", redirect_url);
    o_free(redirect_url);
  }
  json_decref(j_client_check);
  
  return U_OK;
}

/**
 * The second step of authentiation code
 * Validates if code, client_id and redirect_uri sent are valid, then returns a token set
 */
int check_auth_type_access_token_request (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_query, * j_validate, * j_auth, * json_body = NULL, * j_user;
  int res;
  const char * code = u_map_get(request->map_post_body, "code"), 
             * redirect_uri = u_map_get(request->map_post_body, "redirect_uri"),
             * ip_source = get_ip_source(request),
             * client_id = u_map_get(request->map_post_body, "client_id"), 
             * scope_list = NULL;
  time_t now;
  char * refresh_token, * access_token;
  
  // Check if client is allowed to perform this request
  j_auth = client_check(config, client_id, request->auth_basic_user, request->auth_basic_password, redirect_uri, GLEWLWYD_AUHORIZATION_TYPE_CODE);
  if (check_result_value(j_auth, G_OK)) {
    j_validate = validate_authorization_code(config, code, u_map_get(request->map_post_body, "client_id"), redirect_uri, ip_source);
    if (check_result_value(j_validate, G_OK)) {
			j_user = get_user(config, json_string_value(json_object_get(j_validate, "username")), NULL);
			if (check_result_value(j_user, G_OK)) {
				if (config->use_scope) {
					scope_list = json_string_value(json_object_get(j_validate, "scope"));
				}
				time(&now);
				refresh_token = generate_refresh_token(config, request->auth_basic_user, json_string_value(json_object_get(json_object_get(j_user, "user"), "login")), GLEWLWYD_AUHORIZATION_TYPE_CODE, ip_source, scope_list, now);
				if (refresh_token != NULL) {
					access_token = generate_access_token(config, refresh_token, json_string_value(json_object_get(json_object_get(j_user, "user"), "login")), GLEWLWYD_AUHORIZATION_TYPE_CODE, ip_source, scope_list, json_object_get(json_object_get(j_user, "user"), "additional_property_name")!=json_null()?json_string_value(json_object_get(json_object_get(j_user, "user"), "additional_property_name")):NULL, json_object_get(json_object_get(j_user, "user"), "additional_property_value")!=json_null()?json_string_value(json_object_get(json_object_get(j_user, "user"), "additional_property_value")):NULL, now);
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
																	json_integer_value((json_object_get(j_validate, "gco_id"))));
						res = h_update(config->conn, j_query, NULL);
						json_decref(j_query);
						if (res == H_OK) {
							// Finally, the tokens are all here, no error, no problem
							json_body = json_pack("{sssssssisi}",
																		"token_type",
																		"bearer",
																		"access_token",
																		access_token,
																		"refresh_token",
																		refresh_token,
																		"iat",
																		now,
																		"expires_in",
																		config->access_token_expiration);
							ulfius_set_json_body_response(response, 200, json_body);
						} else {
							y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - error executing j_query update");
							response->status = 500;
						}
					} else {
						y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - error generating access_token");
						response->status = 500;
					}
					o_free(access_token);
					json_decref(j_user);
				} else {
					y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - error generating refresh_token");
					response->status = 500;
				}
				o_free(refresh_token);
			} else {
				y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - error getting user");
				response->status = 500;
			}
    } else {
      y_log_message(Y_LOG_LEVEL_WARNING, "Security - Code invalid from IP Address %s", ip_source);
      json_body = json_pack("{ss}", "error", json_string_value(json_object_get(j_validate, "error")));
      ulfius_set_json_body_response(response, 403, json_body);
    }
    json_decref(j_validate);
  } else {
    json_body = json_pack("{ss}", "error", "unauthorized_client");
    ulfius_set_json_body_response(response, 403, json_body);
  }
  json_decref(j_auth);
  json_decref(json_body);
  return U_OK;
}

/**
 * The second more simple authorization type: client redirects user to login page, 
 * Then if authorized, glewlwyd redirects to redirect_uri with the access_token in the uri
 * If necessary, two intermediate steps can be used: login page and grant access page
 */
int check_auth_type_implicit_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  char * access_token = NULL, * redirect_url, * cb_encoded, * query;
  const char * ip_source = get_ip_source(request);
  json_t * session_payload, * j_scope, * j_client_check, * j_user;
  time_t now;
  
  // Check if client_id and redirect_uri are valid
  j_client_check = client_check(config, u_map_get(request->map_url, "client_id"), request->auth_basic_user, request->auth_basic_password, u_map_get(request->map_url, "redirect_uri"), GLEWLWYD_AUHORIZATION_TYPE_IMPLICIT);
  if (check_result_value(j_client_check, G_OK)) {
    // Client is allowed to use implicit grant with this redirection_uri
    session_payload = session_check(config, u_map_get(request->map_cookie, config->session_key));
    if (check_result_value(session_payload, G_OK)) {
      if (u_map_get(request->map_url, "login_validated") != NULL) {
        // User Session is valid
        j_user = get_user(config, json_string_value(json_object_get(json_object_get(session_payload, "grants"), "username")), NULL);
        if (check_result_value(j_user, G_OK)) {
          time(&now);
          if (config->use_scope) {
            j_scope = auth_check_user_scope(config, json_string_value(json_object_get(json_object_get(session_payload, "grants"), "username")), u_map_get(request->map_url, "scope"));
            if (check_result_value(j_scope, G_OK)) {
              // User is allowed for this scope
              if (auth_check_client_user_scope(config, u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(json_object_get(session_payload, "grants"), "username")), json_string_value(json_object_get(j_scope, "scope"))) == G_OK) {
                // User has granted access to the cleaned scope list for this client
                access_token = generate_access_token(config, NULL, json_string_value(json_object_get(json_object_get(session_payload, "grants"), "username")), GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, ip_source, json_string_value(json_object_get(j_scope, "scope")), json_object_get(json_object_get(j_user, "user"), "additional_property_name")!=json_null()?json_string_value(json_object_get(json_object_get(j_user, "user"), "additional_property_name")):NULL, json_object_get(json_object_get(j_user, "user"), "additional_property_value")!=json_null()?json_string_value(json_object_get(json_object_get(j_user, "user"), "additional_property_value")):NULL, now);
                if (u_map_get(request->map_url, "state") != NULL) {
                  redirect_url = msprintf("%s%saccess_token=%s&token_type=bearer&expires_in=%d&state=%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '#')!=NULL?"&":"#"), access_token, config->access_token_expiration, u_map_get(request->map_url, "state"));
                } else {
                  redirect_url = msprintf("%s%saccess_token=%s&token_type=bearer&expires_in=%d", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '#')!=NULL?"&":"#"), access_token, config->access_token_expiration);
                }
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
                o_free(access_token);
                response->status = 302;
              } else {
                // User has not granted access to the cleaned scope list for this client, redirect to grant access page
                cb_encoded = url_encode(request->http_url);
                query = generate_query_parameters(request);
                redirect_url = msprintf("%s%s", config->grant_url, query);
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
                o_free(cb_encoded);
                o_free(query);
                response->status = 302;
              }
            } else {
              // Scope is not allowed for this user
              response->status = 302;
              redirect_url = msprintf("%s%serror=invalid_scope%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '#')!=NULL?"&":"#"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
            }
            json_decref(j_scope);
          } else {
            // Generate access_token, generate the url and redirect to it
            access_token = generate_access_token(config, NULL, json_string_value(json_object_get(json_object_get(session_payload, "grants"), "username")), GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, ip_source, NULL, json_object_get(json_object_get(j_user, "user"), "additional_property_name")!=json_null()?json_string_value(json_object_get(json_object_get(j_user, "user"), "additional_property_name")):NULL, json_object_get(json_object_get(j_user, "user"), "additional_property_value")!=json_null()?json_string_value(json_object_get(json_object_get(j_user, "user"), "additional_property_value")):NULL, now);
            redirect_url = msprintf("%s%saccess_token=%s&token_type=bearer&expires_in=%d%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '#')!=NULL?"&":"#"), access_token, config->access_token_expiration, (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
            response->status = 302;
            o_free(access_token);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_implicit_grant - Error get_user");
          response->status = 500;
        }
        json_decref(j_user);
      } else {
        // Redirect to login page
        cb_encoded = url_encode(request->http_url);
        query = generate_query_parameters(request);
        redirect_url = msprintf("%s%s", config->login_url, query);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
        o_free(cb_encoded);
        o_free(query);
        response->status = 302;
      }
    } else {
      // Redirect to login page
      cb_encoded = url_encode(request->http_url);
      query = generate_query_parameters(request);
      redirect_url = msprintf("%s%s", config->login_url, query);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      o_free(cb_encoded);
      o_free(query);
      response->status = 302;
    }
    json_decref(session_payload);
  } else {
    // client is not authorized with this redirect_uri
    response->status = 302;
    redirect_url = msprintf("%s%serror=unauthorized_client%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '#')!=NULL?"&":"#"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
    ulfius_add_header_to_response(response, "Location", redirect_url);
    o_free(redirect_url);
  }
  json_decref(j_client_check);
  return U_OK;
}

/**
 * The more simple authorization type
 * username and password are given in the POST parameters,
 * the access_token and refresh_token in a json object are returned
 */
int check_auth_type_resource_owner_pwd_cred (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  time_t now;
  char * refresh_token, * access_token;
  const char * ip_source = get_ip_source(request);
  json_t * j_result, * j_auth = NULL, * json_body = NULL, * j_user;
  
  if (request->auth_basic_user != NULL && request->auth_basic_password != NULL) {
    j_auth = client_check(config, request->auth_basic_user, request->auth_basic_user, request->auth_basic_password, NULL, GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS);
  }
  if (check_result_value(j_auth, G_OK) || (request->auth_basic_user == NULL && request->auth_basic_password == NULL)) {
    if (config->use_scope) {
      j_result = auth_check_user_credentials_scope(config, u_map_get(request->map_post_body, "username"), u_map_get(request->map_post_body, "password"), u_map_get(request->map_post_body, "scope"));
    } else {
      j_result = auth_check_user_credentials(config, u_map_get(request->map_post_body, "username"), u_map_get(request->map_post_body, "password"));
    }
    if (check_result_value(j_result, G_OK)) {
			j_user = get_user(config, u_map_get(request->map_post_body, "username"), NULL);
			if (check_result_value(j_user, G_OK)) {
				time(&now);
				refresh_token = generate_refresh_token(config, request->auth_basic_user, json_string_value(json_object_get(json_object_get(j_user, "user"), "login")), GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, ip_source, json_string_value(json_object_get(j_result, "scope")), now);
				if (refresh_token != NULL) {
					access_token = generate_access_token(config, refresh_token, json_string_value(json_object_get(json_object_get(j_user, "user"), "login")), GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, ip_source, json_string_value(json_object_get(j_result, "scope")), json_object_get(json_object_get(j_user, "user"), "additional_property_name")!=json_null()?json_string_value(json_object_get(json_object_get(j_user, "user"), "additional_property_name")):NULL, json_object_get(json_object_get(j_user, "user"), "additional_property_value")!=json_null()?json_string_value(json_object_get(json_object_get(j_user, "user"), "additional_property_value")):NULL, now);
					if (access_token != NULL) {
							json_body = json_pack("{sssssssisi}",
																		"token_type",
																		"bearer",
																		"access_token",
																		access_token,
																		"refresh_token",
																		refresh_token,
																		"iat",
																		now,
																		"expires_in",
																		config->access_token_expiration);
						if (json_body != NULL) {
							if (config->use_scope) {
								json_object_set_new(json_body, "scope", json_copy(json_object_get(j_result, "scope")));
							}
							ulfius_set_json_body_response(response, 200, json_body);
						} else {
							y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - error allocating resources for json_body");
							response->status = 500;
						}
					} else {
						y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - error allocating resources for access_token");
						response->status = 500;
					}
					o_free(access_token);
				} else {
					y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - error allocating resources for refresh_token");
					response->status = 500;
				}
				o_free(refresh_token);
			} else {
				y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - error get_user");
				response->status = 500;
			}
			json_decref(j_user);
    } else if (check_result_value(j_result, G_ERROR_UNAUTHORIZED)) {
      y_log_message(Y_LOG_LEVEL_WARNING, "Security - Error login/password for username %s at IP Address %s", u_map_get(request->map_post_body, "username"), ip_source);
      response->status = 403;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - error checking credentials");
      response->status = 500;
    }
    json_decref(j_result);
  } else {
    json_body = json_pack("{ss}", "error", "unauthorized_client");
    ulfius_set_json_body_response(response, 400, json_body);
  }
  json_decref(json_body);
  json_decref(j_auth);
  return U_OK;
}

/**
 * Send an access_token to a confidential client
 */
int check_auth_type_client_credentials_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  char * access_token;
  const char * ip_source = get_ip_source(request);
  time_t now;
  json_t * j_scope_list = NULL, * j_auth, * json_body = NULL;
  
  j_auth = auth_check_client_credentials(config, request->auth_basic_user, request->auth_basic_password);
  if (check_result_value(j_auth, G_OK)) {
    if (config->use_scope) {
      j_scope_list = auth_check_client_scope(config, request->auth_basic_user, u_map_get(request->map_post_body, "scope"));
      if (check_result_value(j_scope_list, G_OK)) {
        time(&now);
        access_token = generate_client_access_token(config, request->auth_basic_user, json_string_value(json_object_get(j_scope_list, "scope")), ip_source, now);
        if (access_token != NULL) {
          json_body = json_pack("{sssssiso}",
                                          "access_token", access_token,
                                          "token_type", "bearer",
                                          "expires_in", config->access_token_expiration,
                                          "scope",
                                          json_copy(json_object_get(j_scope_list, "scope")));
          o_free(access_token);
          ulfius_set_json_body_response(response, 200, json_body);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_client_credentials_grant - Error generating access_token");
          json_body = json_pack("{ss}", "error", "server_error");
          ulfius_set_json_body_response(response, 500, json_body);
        }
      } else {
        json_body = json_pack("{ss}", "error", "scope_invalid");
        ulfius_set_json_body_response(response, 400, json_body);
      }
    } else {
      time(&now);
      access_token = generate_client_access_token(config, request->auth_basic_user, ip_source, NULL, now);
      if (access_token != NULL) {
        json_body = json_pack("{sssssi}",
                                        "access_token", access_token,
                                        "token_type", "bearer",
                                        "expires_in", config->access_token_expiration);
        ulfius_set_json_body_response(response, 200, json_body);
        o_free(access_token);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_client_credentials_grant - Error generating access_token");
        json_body = json_pack("{ss}", "error", "server_error");
        ulfius_set_json_body_response(response, 500, json_body);
      }
    }
    json_decref(j_scope_list);
  } else {
    y_log_message(Y_LOG_LEVEL_WARNING, "Security - Error client_id/client_password for client_id %s at IP Address %s", request->auth_basic_user, ip_source);
    json_body = json_pack("{ss}", "error", "invalid_client");
    ulfius_set_json_body_response(response, 403, json_body);
  }
  json_decref(j_auth);
  json_decref(json_body);
  return U_OK;
}

/**
 * Get a new access_token from a refresh_token
 */
int get_access_token_from_refresh (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  char * access_token, * token_hash, * clause_expired_at, * last_seen_value, * scope, * scope_list_save, * scope_escaped, * scope_list_escaped = NULL, * saveptr = NULL, * clause_scope_list, * new_scope_list = NULL, * tmp;
  json_t * j_query, * j_result = NULL, * j_result2 = NULL, * j_element, * j_auth = NULL, * j_user;
  size_t index;
  int res;
  const char * refresh_token = u_map_get(request->map_post_body, "refresh_token");
  const char * ip_source = get_ip_source(request);
  jwt_t * jwt;
  time_t now;
  json_t * json_body = NULL;
  
  if (request->auth_basic_user != NULL && request->auth_basic_password != NULL) {
    j_auth = client_check(config, request->auth_basic_user, request->auth_basic_user, request->auth_basic_password, NULL, GLEWLWYD_AUHORIZATION_TYPE_REFRESH_TOKEN);
  }
  if (check_result_value(j_auth, G_OK) || (request->auth_basic_user == NULL && request->auth_basic_password == NULL)) {
    if (refresh_token != NULL) {
      time(&now);
      token_hash = generate_hash(config, config->hash_algorithm, refresh_token);
      
      if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
        clause_expired_at = o_strdup("> NOW()");
      } else {
        clause_expired_at = o_strdup("> (strftime('%s','now'))");
      }

      j_query = json_pack("{sss[s]s{sssisos{ssss}}}",
                          "table",
                          GLEWLWYD_TABLE_REFRESH_TOKEN,
                          "columns",
                            "grt_id",
                          "where",
                            "grt_hash",
                            token_hash,
                            "grt_enabled",
                            1,
                            "gc_client_id",
                            (request->auth_basic_user==NULL?json_null():json_string(request->auth_basic_user)),
                            "grt_expired_at",
                              "operator",
                              "raw",
                              "value",
                              clause_expired_at);
      o_free(clause_expired_at);
      if (request->auth_basic_user != NULL) {
        json_object_set_new(json_object_get(j_query, "where"), "gc_client_id", json_string(request->auth_basic_user));
      } else {
        json_object_set_new(json_object_get(j_query, "where"), "gc_client_id", json_null());
      }
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK && json_array_size(j_result) > 0) {
        if (!jwt_decode(&jwt, refresh_token, (const unsigned char *)config->jwt_decode_key, strlen(config->jwt_decode_key)) && jwt_get_alg(jwt) == jwt_get_alg(config->jwt)) {
          j_user = get_user(config, jwt_get_grant(jwt, "username"), NULL);
          if (check_result_value(j_user, G_OK)) {
            if (json_object_get(json_object_get(j_user, "user"), "enabled") == json_true()) {
              last_seen_value = msprintf(config->conn->type==HOEL_DB_TYPE_MARIADB?"FROM_UNIXTIME(%d)":"%d", now);
              j_query = json_pack("{sss{s{ss}}s{ss}}",
                                  "table",
                                  GLEWLWYD_TABLE_REFRESH_TOKEN,
                                  "set",
                                    "grt_last_seen",
                                      "raw",
                                      last_seen_value,
                                  "where",
                                    "grt_hash",
                                    token_hash);
              o_free(last_seen_value);
              res = h_update(config->conn, j_query, NULL);
              json_decref(j_query);
              if (res == H_OK) {
                if (config->use_scope) {
                  // Get scope
                  if (u_map_get(request->map_post_body, "scope") != NULL) {
                    scope_list_save = o_strdup(u_map_get(request->map_post_body, "scope"));
                    scope = strtok_r(scope_list_save, " ", &saveptr);
                    while (scope != NULL) {
                      scope_escaped = h_escape_string(config->conn, scope);
                      if (scope_list_escaped == NULL) {
                        scope_list_escaped = msprintf("'%s'", scope_escaped);
                      } else {
                        tmp = msprintf("%s,'%s'", scope_list_escaped, scope_escaped);
                        o_free(scope_list_escaped);
                        scope_list_escaped = tmp;
                      }
                      o_free(scope_escaped);
                      scope = strtok_r(NULL, " ", &saveptr);
                    }
                    clause_scope_list = msprintf("IN (SELECT `gs_id` FROM `%s` WHERE `grt_id` = (SELECT `grt_id` FROM `%s` WHERE `grt_hash` = '%s' AND `grt_enabled` = 1) AND `gs_id` IN (SELECT `gs_id` FROM `%s` WHERE `gs_name` IN (%s)))", GLEWLWYD_TABLE_REFRESH_TOKEN_SCOPE, GLEWLWYD_TABLE_REFRESH_TOKEN, token_hash, GLEWLWYD_TABLE_SCOPE, scope_list_escaped);
                    o_free(scope_list_save);
                    o_free(scope_list_escaped);
                  } else {
                    clause_scope_list = msprintf("IN (SELECT `gs_id` FROM `%s` WHERE `grt_id` = (SELECT `grt_id` FROM `%s` WHERE `grt_hash` = '%s' AND `grt_enabled` = 1))", GLEWLWYD_TABLE_REFRESH_TOKEN_SCOPE, GLEWLWYD_TABLE_REFRESH_TOKEN, token_hash);
                  }
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
                                          clause_scope_list);
                  o_free(clause_scope_list);
                  res = h_select(config->conn, j_query, &j_result2, NULL);
                  json_decref(j_query);
                  if (res == H_OK && json_array_size(j_result2) > 0) {
                    json_array_foreach(j_result2, index, j_element) {
                      if (new_scope_list == NULL) {
                        new_scope_list = o_strdup(json_string_value(json_object_get(j_element, "gs_name")));
                      } else {
                        tmp = msprintf("%s %s", new_scope_list, json_string_value(json_object_get(j_element, "gs_name")));
                        o_free(new_scope_list);
                        new_scope_list = tmp;
                      }
                    }
                    access_token = generate_access_token(config, refresh_token, jwt_get_grant(jwt, "username"), GLEWLWYD_AUHORIZATION_TYPE_REFRESH_TOKEN, ip_source, new_scope_list, json_object_get(json_object_get(j_user, "user"), "additional_property_name")!=json_null()?json_string_value(json_object_get(json_object_get(j_user, "user"), "additional_property_name")):NULL, json_object_get(json_object_get(j_user, "user"), "additional_property_value")!=json_null()?json_string_value(json_object_get(json_object_get(j_user, "user"), "additional_property_value")):NULL, now);
                    o_free(new_scope_list);
                    if (access_token != NULL) {
                      json_body = json_pack("{sssssisi}",
                                                      "access_token",
                                                      access_token,
                                                      "token_type",
                                                      "bearer",
                                                      "expires_in",
                                                      config->access_token_expiration,
                                                      "iat",
                                                      now);
                      ulfius_set_json_body_response(response, 200, json_body);
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "get_access_token_from_refresh - Error generating access_token");
                      json_body = json_pack("{ss}", "error", "server_error");
                      ulfius_set_json_body_response(response, 500, json_body);
                    }
                    o_free(access_token);
                  } else if (res != H_OK) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "get_access_token_from_refresh - Error database while validating refresh_token");
                    json_body = json_pack("{ss}", "error", "server_error");
                    ulfius_set_json_body_response(response, 500, json_body);
                  } else {
                    json_body = json_pack("{ss}", "error", "invalid_scope");
                    ulfius_set_json_body_response(response, 400, json_body);
                  }
                  json_decref(j_result2);
                } else {
                  access_token = generate_access_token(config, refresh_token, jwt_get_grant(jwt, "username"), GLEWLWYD_AUHORIZATION_TYPE_REFRESH_TOKEN, ip_source, new_scope_list, json_object_get(json_object_get(j_user, "user"), "additional_property_name")!=json_null()?json_string_value(json_object_get(json_object_get(j_user, "user"), "additional_property_name")):NULL, json_object_get(json_object_get(j_user, "user"), "additional_property_value")!=json_null()?json_string_value(json_object_get(json_object_get(j_user, "user"), "additional_property_value")):NULL, now);
                  o_free(new_scope_list);
                  if (access_token != NULL) {
                    json_body = json_pack("{sssssisi}",
                                                    "access_token",
                                                    access_token,
                                                    "token_type",
                                                    "bearer",
                                                    "expires_in",
                                                    config->access_token_expiration,
                                                    "iat",
                                                    now);
                    ulfius_set_json_body_response(response, 200, json_body);
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "get_access_token_from_refresh - Error generating access_token");
                    json_body = json_pack("{ss}", "error", "server_error");
                    ulfius_set_json_body_response(response, 500, json_body);
                  }
                  o_free(access_token);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_access_token_from_refresh - Error updating grt_last_seen");
                json_body = json_pack("{ss}", "error", "server_error");
                ulfius_set_json_body_response(response, 500, json_body);
              }
            } else {
              json_body = json_pack("{ss}", "error", "access_denied");
              ulfius_set_json_body_response(response, 401, json_body);
            }
          } else {
            json_body = json_pack("{ss}", "error", "server_error");
            ulfius_set_json_body_response(response, 500, json_body);
          }
          json_decref(j_user);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_access_token_from_refresh - Error decoding refresh_token");
          json_body = json_pack("{ss}", "error", "server_error");
          ulfius_set_json_body_response(response, 500, json_body);
        }
        jwt_free(jwt);
      } else if (res != H_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_access_token_from_refresh - Error executing j_query (1)");
        json_body = json_pack("{ss}", "error", "server_error");
        ulfius_set_json_body_response(response, 500, json_body);
      } else {
        json_body = json_pack("{ss}", "error", "invalid_grant");
        ulfius_set_json_body_response(response, 400, json_body);
      }
      o_free(token_hash);
      json_decref(j_result);
    } else {
      json_body = json_pack("{ss}", "error", "invalid_request");
      ulfius_set_json_body_response(response, 400, json_body);
    }
  } else {
    json_body = json_pack("{ss}", "error", "invalid_client");
    ulfius_set_json_body_response(response, 400, json_body);
  }
  json_decref(j_auth);
  json_decref(json_body);
  return U_OK;
}

/**
 * Invalidate a valid refresh_token
 */
int delete_refresh_token (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  char * token_hash, * clause_expired_at, * last_seen_value;
  json_t * j_query, * j_result;
  int res;
  const char * refresh_token = u_map_get(request->map_post_body, "refresh_token");
  time_t now;
  json_int_t grt_id;
  
  if (refresh_token != NULL) {
    time(&now);
    token_hash = generate_hash(config, config->hash_algorithm, refresh_token);
    
    if (config->conn->type == HOEL_DB_TYPE_MARIADB) {
      clause_expired_at = o_strdup("> NOW()");
    } else {
      clause_expired_at = o_strdup("> (strftime('%s','now'))");
    }

    j_query = json_pack("{sss[s]s{sssis{ssss}}}",
                        "table",
                        GLEWLWYD_TABLE_REFRESH_TOKEN,
                        "columns",
                          "grt_id",
                        "where",
                          "grt_hash",
                          token_hash,
                          "grt_enabled",
                          1,
                          "grt_expired_at",
                            "operator",
                            "raw",
                            "value",
                            clause_expired_at);
    o_free(clause_expired_at);
    o_free(token_hash);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK && json_array_size(j_result) > 0) {
      last_seen_value = msprintf(config->conn->type==HOEL_DB_TYPE_MARIADB?"FROM_UNIXTIME(%d)":"%d", now);
      grt_id = json_integer_value(json_object_get(json_array_get(j_result, 0), "grt_id"));
      j_query = json_pack("{sss{sis{ss}}s{sI}}",
                          "table",
                          GLEWLWYD_TABLE_REFRESH_TOKEN,
                          "set",
                            "grt_enabled",
                            0,
                            "grt_last_seen",
                              "raw",
                              last_seen_value,
                          "where",
                            "grt_id",
                            grt_id);
      o_free(last_seen_value);
      res = h_update(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res != H_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "Error database while setting refresh_token enabled to false");
        response->status = 500;
      }
    } else {
      response->status = 400;
    }
    json_decref(j_result);
  } else {
    response->status = 400;
  }
  return U_OK;
}

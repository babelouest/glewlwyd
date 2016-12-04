/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * Provides Json Web Tokens (jwt)
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

/**
 * authorization endpoint
 * handles the following response_types:
 *  - code
 *  - token
 *  - password
 *  - client_credentials
 * POST and GET methods only
 */
int callback_glewlwyd_authorization (const struct _u_request * request, struct _u_response * response, void * user_data) {
  const char * response_type = (0 == nstrcasecmp("POST", request->http_verb))?u_map_get(request->map_post_body, "response_type"):u_map_get(request->map_url, "response_type");
  int result = U_OK;
  char * redirect_url;
  
  if (0 == nstrcmp("code", response_type)) {
    if (0 == nstrcasecmp("GET", request->http_verb) && is_authorization_type_enabled((struct config_elements *)user_data, GLEWLWYD_AUHORIZATION_TYPE_CODE) == G_OK) {
      result = check_auth_type_auth_code_grant(request, response, user_data);
    } else {
      if (u_map_get(request->map_url, "redirect_uri") != NULL) {
        response->status = 302;
        redirect_url = msprintf("%s#error=unsupported_response_type%s%s", u_map_get(request->map_url, "redirect_uri"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        free(redirect_url);
      } else {
        response->status = 403;
      }
    }
  } else if (0 == nstrcmp("token", response_type)) {
    if (0 == nstrcasecmp("GET", request->http_verb) && is_authorization_type_enabled((struct config_elements *)user_data, GLEWLWYD_AUHORIZATION_TYPE_IMPLICIT) == G_OK) {
      result = check_auth_type_implicit_grant(request, response, user_data);
    } else {
      if (u_map_get(request->map_url, "redirect_uri") != NULL) {
        response->status = 302;
        redirect_url = msprintf("%s#error=unsupported_response_type%s%s", u_map_get(request->map_url, "redirect_uri"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        free(redirect_url);
      } else {
        response->status = 403;
      }
    }
  } else if (0 == nstrcmp("password", response_type)) {
    if (0 == nstrcasecmp("POST", request->http_verb) && is_authorization_type_enabled((struct config_elements *)user_data, GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS) == G_OK) {
      result = check_auth_type_resource_owner_pwd_cred(request, response, user_data);
    } else {
      response->status = 403;
    }
  } else if (0 == nstrcmp("client_credentials", response_type)) {
    if (0 == nstrcasecmp("POST", request->http_verb) && is_authorization_type_enabled((struct config_elements *)user_data, GLEWLWYD_AUHORIZATION_TYPE_CLIENT_CREDENTIALS) == G_OK) {
      result = check_auth_type_client_credentials_grant(request, response, user_data);
    } else {
      response->status = 403;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "response_type %s unknown", response_type);
    response->status = 400;
  }
  
  return result;
}

/**
 * Token endpoint
 * Handles the following response_types:
 *  - authorization_code
 *  - refresh_token
 * POST method only
 */
int callback_glewlwyd_token (const struct _u_request * request, struct _u_response * response, void * user_data) {
  const char * response_type = u_map_get(request->map_post_body, "response_type");
  int result = U_OK;
  
  if (0 == nstrcmp("authorization_code", response_type)) {
    if (0 == nstrcasecmp("POST", request->http_verb) && is_authorization_type_enabled((struct config_elements *)user_data, GLEWLWYD_AUHORIZATION_TYPE_AUTHORIZATION_CODE) == G_OK) {
      result = check_auth_type_access_token_request(request, response, user_data);
    } else {
      response->status = 403;
    }
  } else if (0 == nstrcmp("refresh_token", response_type)) {
    result = get_access_token_from_refresh(request, response, user_data);
  }
  return result;
}

/**
 * User authorization endpoint
 * Validates the user/password
 * then if user is valid, stores a cookie
 */
int callback_glewlwyd_user_authorization (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_result = auth_check_credentials(config, u_map_get(request->map_post_body, "username"), u_map_get(request->map_post_body, "password"));
  char * session_token;
  const char * ip_source = get_ip_source(request);
  time_t now;
  
  time(&now);
  if (check_result_value(j_result, G_OK)) {
    // Return scope in json body
    json_object_del(j_result, "result");
    response->json_body = json_copy(j_result);
    
    // Store session cookie
    session_token = generate_session_token(config, u_map_get(request->map_post_body, "username"), ip_source, now);
    ulfius_add_cookie_to_response(response, config->session_key, session_token, NULL, config->session_expiration, NULL, "/", 0, 0);
    free(session_token);
  } else if (check_result_value(j_result, G_ERROR_UNAUTHORIZED)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Glewlwyd - Error login/password for username %s at ip address %s", u_map_get(request->map_post_body, "username"), ip_source);
    response->status = 403;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_authorization - error checking credentials");
    response->status = 500;
  }
  json_decref(j_result);
  
  return U_OK;
}

/**
 * scope grant for a client_id by a user
 */
int callback_glewlwyd_user_scope_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  int res;
  json_t * j_scope, * j_session = session_check(((struct config_elements *)user_data), request);;
  
  // Check if user has access to scopes
  j_scope = auth_check_scope(((struct config_elements *)user_data), json_string_value(json_object_get(j_session, "username")), u_map_get(request->map_post_body, "scope"));
  if (!check_result_value(j_scope, G_OK)) {
    response->status = 403;
    res = U_OK;
  } else {
    res = grant_client_user_scope_access(config, u_map_get(request->map_post_body, "client_id"), json_string_value(json_object_get(j_session, "username")), u_map_get(request->map_post_body, "scope"));
  }
  json_decref(j_scope);
  json_decref(j_session);
  
  return res;
}

/**
 * default callback endpoint
 * return an error 404
 */
int callback_default (const struct _u_request * request, struct _u_response * response, void * user_data) {
  response->status = 404;
  response->json_body = json_pack("{ssss}", "error", "resource not found", "message", "no resource available at this address");
  return U_OK;
}

/**
 * static file callback endpoint
 */
int callback_glewlwyd_static_file (const struct _u_request * request, struct _u_response * response, void * user_data) {
  void * buffer = NULL;
  size_t length, res;
  FILE * f;
  char * file_requested;
  char * file_path;
  const char * content_type;

  file_requested = request->http_url + strlen(((struct config_elements *)user_data)->static_files_prefix) + 1;
  
  if (file_requested == NULL || strlen(file_requested) == 0 || 0 == nstrcmp("/", file_requested)) {
    file_requested = "/index.html";
  } else {
    if (strchr(file_requested, '?') != NULL) {
      *strchr(file_requested, '?') = '\0';
    }
  }
  
  file_path = msprintf("%s%s", ((struct config_elements *)user_data)->static_files_path, file_requested);

  if (access(file_path, F_OK) != -1) {
    f = fopen (file_path, "rb");
    if (f) {
      fseek (f, 0, SEEK_END);
      length = ftell (f);
      fseek (f, 0, SEEK_SET);
      buffer = malloc(length*sizeof(void));
      if (buffer) {
        res = fread (buffer, 1, length, f);
        if (res != length) {
          y_log_message(Y_LOG_LEVEL_WARNING, "callback_angharad_static_file - fread warning, reading %ld while expecting %ld", res, length);
        }
      }
      fclose (f);
    }

    if (buffer) {
      content_type = u_map_get_case(((struct config_elements *)user_data)->mime_types, get_filename_ext(file_requested));
      if (content_type == NULL) {
        content_type = u_map_get(((struct config_elements *)user_data)->mime_types, "*");
        y_log_message(Y_LOG_LEVEL_WARNING, "Static File Server - Unknown mime type for extension %s", get_filename_ext(file_requested));
      }
      response->binary_body = buffer;
      response->binary_body_length = length;
      u_map_put(response->map_header, "Content-Type", content_type);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Static File Server - Internal error in %s", request->http_url);
      response->json_body = json_pack("{ss}", "error", request->http_url);
      response->status = 500;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Static File Server - File %s not found", request->http_url);
    response->json_body = json_pack("{ss}", "not found", request->http_url);
    response->status = 404;
  }
  free(file_path);
  return U_OK;
}

/**
 * OPTIONS callback function
 * Send mandatory parameters for browsers to call REST APIs
 */
int callback_glewlwyd_options (const struct _u_request * request, struct _u_response * response, void * user_data) {
  u_map_put(response->map_header, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  u_map_put(response->map_header, "Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Bearer, Authorization");
  u_map_put(response->map_header, "Access-Control-Max-Age", "1800");
  return U_OK;
}

/**
 * root endpoint
 * redirects to static files address
 */
int callback_glewlwyd_root (const struct _u_request * request, struct _u_response * response, void * user_data) {
  response->status = 301;
  ulfius_add_header_to_response(response, "Location", ((struct config_elements *)user_data)->static_files_prefix);
  return U_OK;
};

/**
 * api description endpoint
 * send the location of prefixes
 */
int callback_glewlwyd_api_description (const struct _u_request * request, struct _u_response * response, void * user_data) {
  response->json_body = json_pack("{ssss}", 
                        "glewlwyd_prefix", 
                        ((struct config_elements *)user_data)->url_prefix,
                        "static_prefix",
                        ((struct config_elements *)user_data)->static_files_prefix);
  return U_OK;
};

/**
 * check if connected user has access to scope
 */
int callback_glewlwyd_check_auth_session_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_session = session_check(((struct config_elements *)user_data), request);
  int res = U_OK;
  
  if (!check_result_value(j_session, G_OK)) {
    res = U_ERROR_UNAUTHORIZED;
  } else {
    res = U_OK;
  }
  json_decref(j_session);
  return res;
}

int callback_glewlwyd_get_user_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session = session_check(config, request), * j_user;
  
  if (!check_result_value(j_session, G_OK)) {
    response->status = 500;
  } else {
    j_user = get_user_profile(config, json_string_value(json_object_get(j_session, "username")));
    if (check_result_value(j_user, G_OK)) {
      response->json_body = json_copy(json_object_get(j_user, "user"));
    }
    json_decref(j_user);
  }
  json_decref(j_session);
  return U_OK;
}

int callback_glewlwyd_delete_user_session (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  ulfius_add_cookie_to_response(response, config->session_key, "", NULL, 0, NULL, "/", 0, 0);
  return U_OK;
}

int callback_glewlwyd_get_user_scope_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session = session_check(config, request);
  json_t * j_scope_grant;
  
  if (!check_result_value(j_session, G_OK)) {
    response->status = 500;
  } else {
    j_scope_grant = get_user_scope_grant(config, json_string_value(json_object_get(j_session, "username")));
    if (check_result_value(j_scope_grant, G_OK)) {
      response->json_body = json_copy(json_object_get(j_scope_grant, "scope"));
    } else {
      response->status = 500;
    }
    json_decref(j_scope_grant);
  }
  json_decref(j_session);
  
  return U_OK;
}

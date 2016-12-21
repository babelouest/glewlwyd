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
 * POST and GET methods only
 */
int callback_glewlwyd_authorization (const struct _u_request * request, struct _u_response * response, void * user_data) {
  const char * response_type = u_map_get(request->map_url, "response_type");
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
  } else {
    if (u_map_get(request->map_url, "redirect_uri") != NULL) {
      response->status = 302;
      redirect_url = msprintf("%s#error=unsupported_response_type%s%s", u_map_get(request->map_url, "redirect_uri"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
      ulfius_add_header_to_response(response, "Location", redirect_url);
      free(redirect_url);
    } else {
      if (response_type != NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "response_type %s unknown", response_type);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "response_type is NULL");
      }
      response->status = 400;
    }
  }
  
  return result;
}

/**
 * Token endpoint
 * Handles the following response_types:
 *  - authorization_code
 *  - password
 *  - client_credentials
 *  - refresh_token
 *  - delete_token
 * POST method only
 */
int callback_glewlwyd_token (const struct _u_request * request, struct _u_response * response, void * user_data) {
  const char * grant_type = u_map_get(request->map_post_body, "grant_type");
  int result = U_OK;
  
  if (0 == nstrcmp("authorization_code", grant_type)) {
    if (is_authorization_type_enabled((struct config_elements *)user_data, GLEWLWYD_AUHORIZATION_TYPE_AUTHORIZATION_CODE) == G_OK) {
      result = check_auth_type_access_token_request(request, response, user_data);
    } else {
      response->status = 403;
    }
  } else if (0 == nstrcmp("password", grant_type)) {
    if (0 == nstrcasecmp("POST", request->http_verb) && is_authorization_type_enabled((struct config_elements *)user_data, GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS) == G_OK) {
      result = check_auth_type_resource_owner_pwd_cred(request, response, user_data);
    } else {
      response->status = 403;
    }
  } else if (0 == nstrcmp("client_credentials", grant_type)) {
    if (is_authorization_type_enabled((struct config_elements *)user_data, GLEWLWYD_AUHORIZATION_TYPE_CLIENT_CREDENTIALS) == G_OK) {
      result = check_auth_type_client_credentials_grant(request, response, user_data);
    } else {
      response->status = 403;
    }
  } else if (0 == nstrcmp("refresh_token", grant_type)) {
    result = get_access_token_from_refresh(request, response, user_data);
  } else if (0 == nstrcmp("delete_token", grant_type)) {
    result = delete_refresh_token(request, response, user_data);
  } else {
    if (grant_type != NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "grant_type %s unknown", grant_type);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "grant_type is NULL");
    }
    response->status = 400;
  }
  return result;
}

/**
 * User authorization endpoint
 * Validates the user/password
 * then if user is valid, stores a cookie
 */
int callback_glewlwyd_validate_user_session (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_result = auth_check_user_credentials(config, u_map_get(request->map_post_body, "username"), u_map_get(request->map_post_body, "password"));
  char * session_token;
  const char * ip_source = get_ip_source(request);
  time_t now;
  
  time(&now);
  if (check_result_value(j_result, G_OK)) {
    // Store session cookie
    session_token = generate_session_token(config, u_map_get(request->map_post_body, "username"), ip_source, now);
    ulfius_add_cookie_to_response(response, config->session_key, session_token, NULL, config->session_expiration, NULL, "/", 0, 0);
    free(session_token);
  } else if (check_result_value(j_result, G_ERROR_UNAUTHORIZED)) {
    y_log_message(Y_LOG_LEVEL_WARNING, "Error login/password for username %s at IP Address %s", u_map_get(request->map_post_body, "username"), ip_source);
    response->status = 403;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_check_user - error checking credentials");
    response->status = 500;
  }
  json_decref(j_result);
  
  return U_OK;
}

/**
 * scope grant for a client_id by a user
 */
int callback_glewlwyd_set_user_scope_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  int res;
  json_t * j_scope, * j_session;
  const char * token = NULL;
  
  // Check if user has access to scopes
  token = nstrstr(u_map_get(request->map_header, "Authorization"), "Bearer ");
  if (token != NULL && strlen(token) > strlen("Bearer ")) {
    token = token + strlen("Bearer ");
  } else {
    token = u_map_get(request->map_cookie, config->session_key);
  }
  j_session = session_get(config, token);
  j_scope = auth_check_user_scope(((struct config_elements *)user_data), json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")), u_map_get(request->map_post_body, "scope"));
  if (!check_result_value(j_scope, G_OK)) {
    response->status = 403;
    res = U_OK;
  } else {
    res = grant_client_user_scope_access(config, u_map_get(request->map_post_body, "client_id"), json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")), u_map_get(request->map_post_body, "scope"));
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
                        "api_prefix", 
                        ((struct config_elements *)user_data)->url_prefix,
                        "app_prefix",
                        ((struct config_elements *)user_data)->static_files_prefix);
  return U_OK;
};

/**
 * check if bearer token or session is valid
 */
int callback_glewlwyd_check_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session = NULL;
  int res = U_OK;
  const char * token = nstrstr(u_map_get(request->map_header, "Authorization"), "Bearer ");
  if (token != NULL && strlen(token) > strlen("Bearer ")) {
    token = token + strlen("Bearer ");
  } else {
    token = u_map_get(request->map_cookie, config->session_key);
  }
  
  j_session = access_token_check(config, token);
  if (!check_result_value(j_session, G_OK)) {
    res = U_ERROR_UNAUTHORIZED;
  } else {
    res = U_OK;
  }
  json_decref(j_session);
  return res;
}

/**
 * check if session is valid
 */
int callback_glewlwyd_check_user_session (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session = NULL;
  int res = U_OK;
  const char * token = u_map_get(request->map_cookie, config->session_key);
  
  j_session = access_token_check(config, token);
  if (!check_result_value(j_session, G_OK)) {
    res = U_ERROR_UNAUTHORIZED;
  } else {
    res = U_OK;
  }
  json_decref(j_session);
  return res;
}

int callback_glewlwyd_check_scope_admin (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session = NULL;
  int res = U_ERROR_UNAUTHORIZED;
  const char * token = nstrstr(u_map_get(request->map_header, "Authorization"), "Bearer ");
  char * scope_list_save, * saveptr, * scope;
  if (token != NULL && strlen(token) > strlen("Bearer ")) {
    token = token + strlen("Bearer ");
  } else {
    token = NULL;
  }
  
  j_session = access_token_check(config, token);
  if (check_result_value(j_session, G_OK)) {
    scope_list_save = nstrdup(json_string_value(json_object_get(json_object_get(j_session, "grants"), "scope")));
    scope = strtok_r(scope_list_save, " ", &saveptr);
    while (scope != NULL) {
      if (strcmp(scope, config->admin_scope) == 0) {
        res = U_OK;
      }
      scope = strtok_r(NULL, " ", &saveptr);
    }
    free(scope_list_save);
  }
  json_decref(j_session);
  return res;
}

int callback_glewlwyd_get_user_session_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session = NULL, * j_user = NULL;
  const char * token;
  
  if (u_map_get(request->map_url, "bearer") != NULL) {
    token = nstrstr(u_map_get(request->map_header, "Authorization"), "Bearer ");
    if (token != NULL && strlen(token) > strlen("Bearer ")) {
      token = token + strlen("Bearer ");
    } else {
      token = NULL;
    }
  } else {
    token = u_map_get(request->map_cookie, config->session_key);
  }

  j_session = session_get(config, token);
  if (check_result_value(j_session, G_OK)) {
    j_user = get_user_profile(config, json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")));
    if (check_result_value(j_user, G_OK)) {
      response->json_body = json_copy(json_object_get(j_user, "user"));
    }
    json_decref(j_user);
  } else {
    response->status = 500;
  }
  json_decref(j_session);
  return U_OK;
}

int callback_glewlwyd_get_user_session (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session = NULL, * j_user = NULL;
  const char * token = u_map_get(request->map_cookie, config->session_key);

  j_session = session_get(config, token);
  if (check_result_value(j_session, G_OK)) {
    j_user = get_user_profile(config, json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")));
    if (check_result_value(j_user, G_OK)) {
      response->json_body = json_copy(json_object_get(j_user, "user"));
    }
    json_decref(j_user);
  } else {
    response->status = 500;
  }
  json_decref(j_session);
  return U_OK;
}

int callback_glewlwyd_delete_user_session (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  ulfius_add_cookie_to_response(response, config->session_key, "", NULL, 0, NULL, "/", 0, 0);
  return U_OK;
}

int callback_glewlwyd_get_user_session_scope_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session = session_get(config, u_map_get(request->map_cookie, config->session_key));
  json_t * j_scope_grant;
  
  if (!check_result_value(j_session, G_OK)) {
    response->status = 500;
  } else {
    j_scope_grant = get_user_scope_grant(config, json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")));
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

int callback_glewlwyd_user_scope_delete (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  int res;
  json_t * j_scope, * j_session;
  
  // Check if user has access to scopes
  j_session = session_get(config, u_map_get(request->map_cookie, config->session_key));
  j_scope = auth_check_user_scope(((struct config_elements *)user_data), json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")), u_map_get(request->map_post_body, "scope"));
  if (!check_result_value(j_scope, G_OK)) {
    response->status = 403;
    res = U_OK;
  } else {
    res = delete_client_user_scope_access(config, u_map_get(request->map_post_body, "client_id"), json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")), u_map_get(request->map_post_body, "scope"));
  }
  json_decref(j_scope);
  json_decref(j_session);
  
  return res;
}

int callback_glewlwyd_get_authorization (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_result = get_authorization_type(config, u_map_get(request->map_url, "authorization_type"));
  
  if (check_result_value(j_result, G_OK)) {
    if (u_map_get(request->map_url, "authorization_type") != NULL) {
      response->json_body = json_copy(json_array_get(json_object_get(j_result, "authorization"), 0));
    } else {
      response->json_body = json_copy(json_object_get(j_result, "authorization"));
    }
  } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_authorization - Error getting authorization list");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_set_authorization (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_valid, * j_result = get_authorization_type(config, u_map_get(request->map_url, "authorization_type"));
  
  if (check_result_value(j_result, G_OK)) {
    j_valid = is_authorization_type_valid(config, request->json_body);
    if (j_valid != NULL && json_array_size(j_valid) == 0) {
      if (set_authorization_type(config, u_map_get(request->map_url, "authorization_type"), request->json_body) != G_OK) {
        response->status = 500;
      }
    } else if (j_valid != NULL && json_array_size(j_valid) > 0) {
      response->status = 400;
      response->json_body = json_copy(j_valid);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_authorization - Error is_authorization_type_valid");
      response->status = 500;
    }
    json_decref(j_valid);
  } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_authorization - Error getting authorization");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_get_list_scope (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_result = get_scope_list(config);
  
  if (check_result_value(j_result, G_OK)) {
    response->json_body = json_copy(json_object_get(j_result, "scope"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_list_scope - Error getting scope list");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_get_scope (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_result = get_scope(config, u_map_get(request->map_url, "scope"));
  
  if (check_result_value(j_result, G_OK)) {
    response->json_body = json_copy(json_object_get(j_result, "scope"));
  } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_list_scope - Error getting scope list");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_add_scope (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_result = is_scope_valid(config, request->json_body, 1);
  
  if (j_result != NULL && json_array_size(j_result) == 0) {
    if (add_scope(config, request->json_body) != G_OK) {
      response->status = 500;
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_scope - Error adding new scope");
    }
  } else if (j_result != NULL && json_array_size(j_result) > 0) {
    response->status = 400;
    response->json_body = json_copy(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_scope - Error is_scope_valid");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_set_scope (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_scope = get_scope(config, u_map_get(request->map_url, "scope")), * j_result;
  
  if (check_result_value(j_scope, G_OK)) {
    j_result = is_scope_valid(config, request->json_body, 0);
    if (j_result != NULL && json_array_size(j_result) == 0) {
      if (set_scope(config, u_map_get(request->map_url, "scope"), request->json_body) != G_OK) {
        response->status = 500;
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_scope - Error adding new scope");
      }
    } else if (j_result != NULL && json_array_size(j_result) > 0) {
      response->status = 400;
      response->json_body = json_copy(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_scope - Error is_scope_valid");
      response->status = 500;
    }
    json_decref(j_result);
  } else if (check_result_value(j_scope, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_scope - Error get_scope");
    response->status = 500;
  }
  json_decref(j_scope);
  return U_OK;
}

int callback_glewlwyd_delete_scope (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_scope = get_scope(config, u_map_get(request->map_url, "scope"));
  
  if (check_result_value(j_scope, G_OK)) {
    if (delete_scope(config, u_map_get(request->map_url, "scope")) != G_OK) {
      response->status = 500;
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_scope - Error adding new scope");
    }
  } else if (check_result_value(j_scope, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_scope - Error get_scope");
    response->status = 500;
  }
  json_decref(j_scope);
  return U_OK;
}

int callback_glewlwyd_get_list_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_get_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_add_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_set_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_delete_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_get_list_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_get_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_add_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_set_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_delete_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_get_list_resource (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_get_resource (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_add_resource (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_set_resource (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_delete_resource (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_set_user_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

int callback_glewlwyd_set_user_profile_no_auth (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_OK;
}

/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * Provides Json Web Tokens (jwt)
 * 
 * Callback functions definition
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
    y_log_message(Y_LOG_LEVEL_WARNING, "Security - Error login/password for username %s at IP Address %s", u_map_get(request->map_post_body, "username"), ip_source);
    response->status = 403;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_validate_user_session - error checking credentials");
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
  
  j_session = session_or_access_token_check(config, u_map_get(request->map_cookie, config->session_key), u_map_get(request->map_header, "Authorization"));
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
  char * url = msprintf("%s/", ((struct config_elements *)user_data)->static_files_prefix);
  if (url != NULL) {
    response->status = 301;
    ulfius_add_header_to_response(response, "Location", url);
    free(url);
  } else {
    response->status = 500;
  }
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
  
  j_session = session_or_access_token_check(config, u_map_get(request->map_cookie, config->session_key), u_map_get(request->map_header, "Authorization"));
  if (!check_result_value(j_session, G_OK)) {
    res = U_ERROR_UNAUTHORIZED;
  } else {
    res = U_OK;
  }
  json_decref(j_session);
  return res;
}

/**
 * check if bearer token has g_admin scope
 */
int callback_glewlwyd_check_scope_admin (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session = NULL;
  int res = U_ERROR_UNAUTHORIZED, i, count;
  char ** scope_list;
  
  j_session = access_token_check(config, u_map_get(request->map_header, "Authorization"));
  if (check_result_value(j_session, G_OK)) {
    count = split_string(json_string_value(json_object_get(json_object_get(j_session, "grants"), "scope")), " ", &scope_list);
    for (i=0; count > 0 && scope_list[i] != NULL; i++) {
      if (strcmp(scope_list[i], config->admin_scope) == 0) {
        res = U_OK;
        break;
      }
    }
    free_string_array(scope_list);
  }
  json_decref(j_session);
  return res;
}

/**
 * User session endpoints
 */
int callback_glewlwyd_get_user_session_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session = NULL, * j_user = NULL;
  
  j_session = session_check(config, u_map_get(request->map_cookie, config->session_key));
  if (check_result_value(j_session, G_OK)) {
    j_user = get_user(config, json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")), NULL);
    if (check_result_value(j_user, G_OK)) {
      json_object_del(json_object_get(j_user, "user"), "source");
      json_object_del(json_object_get(j_user, "user"), "enabled");
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

  j_session = session_or_access_token_check(config, u_map_get(request->map_cookie, config->session_key), u_map_get(request->map_header, "Authorization"));
  if (check_result_value(j_session, G_OK)) {
    j_user = get_user(config, json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")), NULL);
    if (check_result_value(j_user, G_OK)) {
      json_object_del(json_object_get(j_user, "user"), "source");
      json_object_del(json_object_get(j_user, "user"), "enabled");
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
  char * session_hash;
  json_t * j_session;
  
  if (u_map_get(request->map_cookie, config->session_key) != NULL && strlen(u_map_get(request->map_cookie, config->session_key)) > 0) {
    j_session = session_or_access_token_check(config, u_map_get(request->map_cookie, config->session_key), u_map_get(request->map_header, "Authorization"));
    if (check_result_value(j_session, G_OK)) {
      session_hash = generate_hash(config, config->hash_algorithm, u_map_get(request->map_cookie, config->session_key));
      if (revoke_session(config, json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")), session_hash) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_user_session - Error revoking session in database");
        response->status = 500;
      }
      free(session_hash);
    }
    json_decref(j_session);
  }
  ulfius_add_cookie_to_response(response, config->session_key, "", NULL, 0, NULL, "/", 0, 0);
  return U_OK;
}

/**
 * User scope grant endpoints
 */
int callback_glewlwyd_get_user_session_scope_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session = session_or_access_token_check(config, u_map_get(request->map_cookie, config->session_key), u_map_get(request->map_header, "Authorization"));
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
  j_session = session_or_access_token_check(config, u_map_get(request->map_cookie, config->session_key), u_map_get(request->map_header, "Authorization"));
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

/**
 * Authorization type endpoints
 */
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

/**
 * Scope CRUD endpoints
 */
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

/**
 * User CRUD endpoints
 */
int callback_glewlwyd_get_list_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  long int offset, limit;
  json_t * j_result;
  
  if (u_map_get(request->map_url, "offset") != NULL) {
    offset = strtol(u_map_get(request->map_url, "offset"), NULL, 10);
  } else {
    offset = 0;
  }
  
  if (u_map_get(request->map_url, "limit") != NULL) {
    limit = strtol(u_map_get(request->map_url, "limit"), NULL, 10);
  } else {
    limit = GLEWLWYD_DEFAULT_LIMIT;
  }
  
  j_result = get_user_list(config, u_map_get(request->map_url, "source"), u_map_get(request->map_url, "search"), offset>=0?offset:0, limit>0?limit:GLEWLWYD_DEFAULT_LIMIT);
  
  if (check_result_value(j_result, G_OK)) {
    response->json_body = json_copy(json_object_get(j_result, "user"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_list_user - Error getting user list");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_get_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_user;
  
  if (u_map_get(request->map_url, "source") == NULL || 0 == strcmp("all", u_map_get(request->map_url, "source")) || 0 == strcmp("ldap", u_map_get(request->map_url, "source")) || 0 == strcmp("database", u_map_get(request->map_url, "source"))) {
    j_user = get_user(config, u_map_get(request->map_url, "username"), u_map_get(request->map_url, "source"));
    if (check_result_value(j_user, G_OK)) {
      response->json_body = json_copy(json_object_get(j_user, "user"));
    } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
      response->status = 404;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_user - Error getting user");
      response->status = 500;
    }
    json_decref(j_user);
  } else {
    response->status = 400;
  }
  return U_OK;
}

int callback_glewlwyd_add_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_result = is_user_valid(config, request->json_body, 1);
  
  if (j_result != NULL && json_array_size(j_result) == 0) {
    if (add_user(config, request->json_body) != G_OK) {
      response->status = 500;
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_user - Error adding new user");
    }
  } else if (j_result != NULL && json_array_size(j_result) > 0) {
    response->status = 400;
    response->json_body = json_copy(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_user - Error is_user_valid");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_set_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_user, * j_result;
  
  if (u_map_get(request->map_url, "source") == NULL || 0 == strcmp("all", u_map_get(request->map_url, "source")) || 0 == strcmp("ldap", u_map_get(request->map_url, "source")) || 0 == strcmp("database", u_map_get(request->map_url, "source"))) {
    j_user = get_user(config, u_map_get(request->map_url, "username"), u_map_get(request->map_url, "source"));
    if (check_result_value(j_user, G_OK)) {
      j_result = is_user_valid(config, request->json_body, 0);
      if (j_result != NULL && json_array_size(j_result) == 0) {
        if (set_user(config, u_map_get(request->map_url, "username"), request->json_body, json_string_value(json_object_get(json_object_get(j_user, "user"), "source"))) != G_OK) {
          response->status = 500;
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user - Error adding new user");
        }
      } else if (j_result != NULL && json_array_size(j_result) > 0) {
        response->status = 400;
        response->json_body = json_copy(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user - Error is_user_valid");
        response->status = 500;
      }
      json_decref(j_result);
    } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
      response->status = 404;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user - Error getting user");
      response->status = 500;
    }
    json_decref(j_user);
  } else {
    response->status = 400;
  }
  return U_OK;
}

int callback_glewlwyd_delete_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_user;
  
  if (u_map_get(request->map_url, "source") == NULL || 0 == strcmp("all", u_map_get(request->map_url, "source")) || 0 == strcmp("ldap", u_map_get(request->map_url, "source")) || 0 == strcmp("database", u_map_get(request->map_url, "source"))) {
    j_user = get_user(config, u_map_get(request->map_url, "username"), u_map_get(request->map_url, "source"));
    if (check_result_value(j_user, G_OK)) {
      if (delete_user(config, u_map_get(request->map_url, "username"), json_string_value(json_object_get(json_object_get(j_user, "user"), "source"))) != G_OK) {
        response->status = 500;
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_user - Error deleting user");
      }
    } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
      response->status = 404;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_user - Error get_scope");
      response->status = 500;
    }
    json_decref(j_user);
  } else {
    response->status = 400;
  }
  return U_OK;
}

/**
 * User refresh_token endpoints
 */
int callback_glewlwyd_get_refresh_token_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  long int offset, limit;
  json_t * j_result;
  int valid = -1;
  if (u_map_get(request->map_url, "valid") != NULL) {
    if (strcmp("true", u_map_get(request->map_url, "valid")) == 0) {
      valid=1;
    } else {
      valid=0;
    }
  }
  
  if (u_map_get(request->map_url, "offset") != NULL) {
    offset = strtol(u_map_get(request->map_url, "offset"), NULL, 10);
  } else {
    offset = 0;
  }
  
  if (u_map_get(request->map_url, "limit") != NULL) {
    limit = strtol(u_map_get(request->map_url, "limit"), NULL, 10);
  } else {
    limit = GLEWLWYD_DEFAULT_LIMIT;
  }
  
  j_result = get_refresh_token_list(config, u_map_get(request->map_url, "username"), valid, offset>=0?offset:0, limit>0?limit:GLEWLWYD_DEFAULT_LIMIT);
  
  if (check_result_value(j_result, G_OK)) {
    response->json_body = json_copy(json_object_get(j_result, "token"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_refresh_token_user - Error getting token list");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_delete_refresh_token_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  int res;
  
  res = revoke_token(config, u_map_get(request->map_url, "username"), u_map_get(request->map_post_body, "token_hash"));
  if (res == G_ERROR_NOT_FOUND) {
    response->status = 404;
  } else if (res == G_ERROR_PARAM) {
    response->status = 400;
  } else if (res != G_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_refresh_token_user - Error revoking token list");
    response->status = 500;
  }
  return U_OK;
}

/**
 * User session endpoints
 */
int callback_glewlwyd_get_session_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  long int offset, limit;
  json_t * j_result;
  int valid = -1;
  if (u_map_get(request->map_url, "valid") != NULL) {
    if (strcmp("true", u_map_get(request->map_url, "valid")) == 0) {
      valid=1;
    } else {
      valid=0;
    }
  }
  
  if (u_map_get(request->map_url, "offset") != NULL) {
    offset = strtol(u_map_get(request->map_url, "offset"), NULL, 10);
  } else {
    offset = 0;
  }
  
  if (u_map_get(request->map_url, "limit") != NULL) {
    limit = strtol(u_map_get(request->map_url, "limit"), NULL, 10);
  } else {
    limit = GLEWLWYD_DEFAULT_LIMIT;
  }
  
  j_result = get_session_list(config, u_map_get(request->map_url, "username"), valid, offset>=0?offset:0, limit>0?limit:GLEWLWYD_DEFAULT_LIMIT);
  
  if (check_result_value(j_result, G_OK)) {
    response->json_body = json_copy(json_object_get(j_result, "session"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_session_user - Error getting session list");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_delete_session_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  int res;
  
  res = revoke_session(config, u_map_get(request->map_url, "username"), u_map_get(request->map_post_body, "session_hash"));
  if (res == G_ERROR_NOT_FOUND) {
    response->status = 404;
  } else if (res == G_ERROR_PARAM) {
    response->status = 400;
  } else if (res != G_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_session_user - Error revoking session");
    response->status = 500;
  }
  return U_OK;
}

/**
 * Client CRUD endpoints
 */
int callback_glewlwyd_get_list_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  long int offset, limit;
  json_t * j_result;
  
  if (u_map_get(request->map_url, "offset") != NULL) {
    offset = strtol(u_map_get(request->map_url, "offset"), NULL, 10);
  } else {
    offset = 0;
  }
  
  if (u_map_get(request->map_url, "limit") != NULL) {
    limit = strtol(u_map_get(request->map_url, "limit"), NULL, 10);
  } else {
    limit = GLEWLWYD_DEFAULT_LIMIT;
  }
  
  j_result = get_client_list(config, u_map_get(request->map_url, "source"), u_map_get(request->map_url, "search"), offset>=0?offset:0, limit>0?limit:GLEWLWYD_DEFAULT_LIMIT);
  
  if (check_result_value(j_result, G_OK)) {
    response->json_body = json_copy(json_object_get(j_result, "client"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_list_client - Error getting client list");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_get_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_client;
  
  if (u_map_get(request->map_url, "source") == NULL || 0 == strcmp("all", u_map_get(request->map_url, "source")) || 0 == strcmp("ldap", u_map_get(request->map_url, "source")) || 0 == strcmp("database", u_map_get(request->map_url, "source"))) {
    j_client = get_client(config, u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "source"));
    if (check_result_value(j_client, G_OK)) {
      response->json_body = json_copy(json_object_get(j_client, "client"));
    } else if (check_result_value(j_client, G_ERROR_NOT_FOUND)) {
      response->status = 404;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_client - Error getting client");
      response->status = 500;
    }
    json_decref(j_client);
  } else {
    response->status = 400;
  }
  return U_OK;
}

int callback_glewlwyd_add_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_result = is_client_valid(config, request->json_body, 1);
  
  if (j_result != NULL && json_array_size(j_result) == 0) {
    if (add_client(config, request->json_body) != G_OK) {
      response->status = 500;
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_client - Error adding new client");
    }
  } else if (j_result != NULL && json_array_size(j_result) > 0) {
    response->status = 400;
    response->json_body = json_copy(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_client - Error is_client_valid");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_set_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_client, * j_result;
  
  if (u_map_get(request->map_url, "source") == NULL || 0 == strcmp("all", u_map_get(request->map_url, "source")) || 0 == strcmp("ldap", u_map_get(request->map_url, "source")) || 0 == strcmp("database", u_map_get(request->map_url, "source"))) {
    j_client = get_client(config, u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "source"));
    if (check_result_value(j_client, G_OK)) {
      j_result = is_client_valid(config, request->json_body, 0);
      if (j_result != NULL && json_array_size(j_result) == 0) {
        if (set_client(config, u_map_get(request->map_url, "client_id"), request->json_body, json_string_value(json_object_get(json_object_get(j_client, "client"), "source"))) != G_OK) {
          response->status = 500;
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_client - Error adding new client");
        }
      } else if (j_result != NULL && json_array_size(j_result) > 0) {
        response->status = 400;
        response->json_body = json_copy(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_client - Error is_client_valid");
        response->status = 500;
      }
      json_decref(j_result);
    } else if (check_result_value(j_client, G_ERROR_NOT_FOUND)) {
      response->status = 404;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_client - Error getting client");
      response->status = 500;
    }
    json_decref(j_client);
  } else {
    response->status = 400;
  }
  return U_OK;
}

int callback_glewlwyd_delete_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_client;
  
  if (u_map_get(request->map_url, "source") == NULL || 0 == strcmp("all", u_map_get(request->map_url, "source")) || 0 == strcmp("ldap", u_map_get(request->map_url, "source")) || 0 == strcmp("database", u_map_get(request->map_url, "source"))) {
    j_client = get_client(config, u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "source"));
    if (check_result_value(j_client, G_OK)) {
      if (delete_client(config, u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(json_object_get(j_client, "client"), "source"))) != G_OK) {
        response->status = 500;
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_client - Error deleting client");
      }
    } else if (check_result_value(j_client, G_ERROR_NOT_FOUND)) {
      response->status = 404;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_client - Error get_scope");
      response->status = 500;
    }
    json_decref(j_client);
  } else {
    response->status = 400;
  }
  return U_OK;
}

/**
 * Resource CRUD endpoints
 */
int callback_glewlwyd_get_list_resource (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_result = get_resource_list(config);
  
  if (check_result_value(j_result, G_OK)) {
    response->json_body = json_copy(json_object_get(j_result, "resource"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_list_resource - Error getting resource list");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_get_resource (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_result = get_resource(config, u_map_get(request->map_url, "resource"));
  
  if (check_result_value(j_result, G_OK)) {
    response->json_body = json_copy(json_object_get(j_result, "resource"));
  } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_list_resource - Error getting resource list");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_add_resource (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_result = is_resource_valid(config, request->json_body, 1);
  
  if (j_result != NULL && json_array_size(j_result) == 0) {
    if (add_resource(config, request->json_body) != G_OK) {
      response->status = 500;
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_resource - Error adding new resource");
    }
  } else if (j_result != NULL && json_array_size(j_result) > 0) {
    response->status = 400;
    response->json_body = json_copy(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_resource - Error is_resource_valid");
    response->status = 500;
  }
  json_decref(j_result);
  return U_OK;
}

int callback_glewlwyd_set_resource (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_resource = get_resource(config, u_map_get(request->map_url, "resource")), * j_result;
  
  if (check_result_value(j_resource, G_OK)) {
    j_result = is_resource_valid(config, request->json_body, 0);
    if (j_result != NULL && json_array_size(j_result) == 0) {
      if (set_resource(config, u_map_get(request->map_url, "resource"), request->json_body) != G_OK) {
        response->status = 500;
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_resource - Error adding new resource");
      }
    } else if (j_result != NULL && json_array_size(j_result) > 0) {
      response->status = 400;
      response->json_body = json_copy(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_resource - Error is_resource_valid");
      response->status = 500;
    }
    json_decref(j_result);
  } else if (check_result_value(j_resource, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_resource - Error get_resource");
    response->status = 500;
  }
  json_decref(j_resource);
  return U_OK;
}

int callback_glewlwyd_delete_resource (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_resource = get_resource(config, u_map_get(request->map_url, "resource"));
  
  if (check_result_value(j_resource, G_OK)) {
    if (delete_resource(config, u_map_get(request->map_url, "resource")) != G_OK) {
      response->status = 500;
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_resource - Error adding new resource");
    }
  } else if (check_result_value(j_resource, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_resource - Error get_resource");
    response->status = 500;
  }
  json_decref(j_resource);
  return U_OK;
}

/**
 * User profile endpoints
 */
int callback_glewlwyd_set_user_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session = NULL, * j_user_valid = NULL;

  j_session = session_or_access_token_check(config, u_map_get(request->map_cookie, config->session_key), u_map_get(request->map_header, "Authorization"));
  if (check_result_value(j_session, G_OK)) {
    j_user_valid = is_user_profile_valid(config, json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")), request->json_body);
    if (j_user_valid != NULL && json_array_size(j_user_valid) == 0) {
      if (set_user_profile(config, json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")), request->json_body) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user_profile - Error setting profile");
        response->status = 500;
      }
    } else if (j_user_valid != NULL) {
      response->status = 400;
      response->json_body = json_copy(j_user_valid);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user_profile - Error is_user_profile_valid");
      response->status = 500;
    }
    json_decref(j_user_valid);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user_profile - Error get session");
    response->status = 500;
  }
  json_decref(j_session);
  return U_OK;
}

int callback_glewlwyd_send_reset_user_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_user = get_user(config, u_map_get(request->map_url, "username"), NULL);
  const char * ip_source = get_ip_source(request);
  
  y_log_message(Y_LOG_LEVEL_WARNING, "Security - Requesting reset password for user %s at IP Address %s", u_map_get(request->map_url, "username"), ip_source);
  
  if (check_result_value(j_user, G_OK)) {
    if (json_object_get(json_object_get(j_user, "user"), "email") != NULL && json_string_length(json_object_get(json_object_get(j_user, "user"), "email")) > 0) {
      if (send_reset_user_profile_email(config, u_map_get(request->map_url, "username"), ip_source) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_send_reset_user_profile - Error sending reset profile email");
        response->status = 500;
      }
    } else {
      response->status = 400;
      response->json_body = json_pack("{ss}", "error", "no email specified for user");
    }
  } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_send_reset_user_profile - Error getting user profile");
    response->status = 500;
  }
  json_decref(j_user);
  return U_OK;
}

int callback_glewlwyd_reset_user_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  int res;

  res = is_reset_user_profile_valid(config, u_map_get(request->map_url, "username"), u_map_get(request->map_post_body, "token"), u_map_get(request->map_post_body, "password"));
  if (res == G_OK) {
    if (reset_user_profile(config, u_map_get(request->map_url, "username"), u_map_get(request->map_post_body, "token"), u_map_get(request->map_post_body, "password")) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_reset_user_profile - Error setting profile");
      response->status = 500;
    }
  } else if (res == G_ERROR_NOT_FOUND) {
    response->status = 404;
  } else if (res == G_ERROR_PARAM) {
    response->json_body = json_pack("{ss}", "error", "error input parameters");
    response->status = 400;
  } else {
    response->status = 500;
  }
  return U_OK;
}

/**
 * User profile refresh_token endpoints
 */
int callback_glewlwyd_get_refresh_token_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  long int offset, limit;
  json_t * j_result, * j_session;
  int valid = -1;
  if (u_map_get(request->map_url, "valid") != NULL) {
    if (strcmp("true", u_map_get(request->map_url, "valid")) == 0) {
      valid=1;
    } else {
      valid=0;
    }
  }
  
  j_session = session_or_access_token_check(config, u_map_get(request->map_cookie, config->session_key), u_map_get(request->map_header, "Authorization"));
  if (check_result_value(j_session, G_OK)) {
    if (u_map_get(request->map_url, "offset") != NULL) {
      offset = strtol(u_map_get(request->map_url, "offset"), NULL, 10);
    } else {
      offset = 0;
    }
    
    if (u_map_get(request->map_url, "limit") != NULL) {
      limit = strtol(u_map_get(request->map_url, "limit"), NULL, 10);
    } else {
      limit = GLEWLWYD_DEFAULT_LIMIT;
    }
    
    j_result = get_refresh_token_list(config, json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")), valid, offset>=0?offset:0, limit>0?limit:GLEWLWYD_DEFAULT_LIMIT);
    
    if (check_result_value(j_result, G_OK)) {
      response->json_body = json_copy(json_object_get(j_result, "token"));
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_refresh_token_user - Error getting token list");
      response->status = 500;
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_refresh_token_user - Error get session");
    response->status = 500;
  }
  json_decref(j_session);
  return U_OK;
}

int callback_glewlwyd_delete_refresh_token_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session;
  int res;
  
  j_session = session_or_access_token_check(config, u_map_get(request->map_cookie, config->session_key), u_map_get(request->map_header, "Authorization"));
  if (check_result_value(j_session, G_OK)) {
    res = revoke_token(config, json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")), u_map_get(request->map_post_body, "token_hash"));
    if (res == G_ERROR_NOT_FOUND) {
      response->status = 404;
    } else if (res == G_ERROR_PARAM) {
      response->status = 400;
    } else if (res != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_refresh_token_user - Error revoking token list");
      response->status = 500;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_refresh_token_user - Error get session");
    response->status = 500;
  }
  json_decref(j_session);
  return U_OK;
}

/**
 * User profile session endpoints
 */
int callback_glewlwyd_get_session_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  long int offset, limit;
  json_t * j_result, * j_session;
  int valid = -1;

  if (u_map_get(request->map_url, "valid") != NULL) {
    if (strcmp("true", u_map_get(request->map_url, "valid")) == 0) {
      valid=1;
    } else {
      valid=0;
    }
  }
  
  j_session = session_or_access_token_check(config, u_map_get(request->map_cookie, config->session_key), u_map_get(request->map_header, "Authorization"));
  if (check_result_value(j_session, G_OK)) {
    if (u_map_get(request->map_url, "offset") != NULL) {
      offset = strtol(u_map_get(request->map_url, "offset"), NULL, 10);
    } else {
      offset = 0;
    }
    
    if (u_map_get(request->map_url, "limit") != NULL) {
      limit = strtol(u_map_get(request->map_url, "limit"), NULL, 10);
    } else {
      limit = GLEWLWYD_DEFAULT_LIMIT;
    }
    
    j_result = get_session_list(config, json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")), valid, offset>=0?offset:0, limit>0?limit:GLEWLWYD_DEFAULT_LIMIT);
    
    if (check_result_value(j_result, G_OK)) {
      response->json_body = json_copy(json_object_get(j_result, "session"));
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_session_user - Error getting session list");
      response->status = 500;
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_session_user - Error get session");
    response->status = 500;
  }
  json_decref(j_session);
  return U_OK;
}

int callback_glewlwyd_delete_session_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session;
  int res;
  
  j_session = session_or_access_token_check(config, u_map_get(request->map_cookie, config->session_key), u_map_get(request->map_header, "Authorization"));
  if (check_result_value(j_session, G_OK)) {
    res = revoke_session(config, json_string_value(json_object_get(json_object_get(j_session, "grants"), "username")), u_map_get(request->map_post_body, "session_hash"));
    if (res == G_ERROR_NOT_FOUND) {
      response->status = 404;
    } else if (res == G_ERROR_PARAM) {
      response->status = 400;
    } else if (res != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_session_user - Error revoking session");
      response->status = 500;
    } else {
      response->status = 200;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_session_user - Error get session");
    response->status = 500;
  }
  json_decref(j_session);
  return U_OK;
}

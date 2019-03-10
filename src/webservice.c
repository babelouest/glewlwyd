/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Callback functions definition
 *
 * Copyright 2016-2019 Nicolas Mora <mail@babelouest.org>
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
                        ((struct config_elements *)user_data)->admin_scope,
                        "profile_scope",
                        ((struct config_elements *)user_data)->profile_scope);
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

int callback_glewlwyd_check_user_session (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  char * session_uid;
  json_t * j_user;
  int ret;
  
  if ((session_uid = get_session_id(config, request)) != NULL) {
    j_user = get_user_for_session(config, session_uid);
    if (check_result_value(j_user, G_OK) && json_object_get(json_object_get(j_user, "user"), "enabled") == json_true()) {
      response->shared_data = json_deep_copy(json_object_get(j_user, "user"));
      ret = U_CALLBACK_CONTINUE;
    } else {
      ret = U_CALLBACK_UNAUTHORIZED;
    }
    json_decref(j_user);
  } else {
    ret = U_CALLBACK_UNAUTHORIZED;
  }
  o_free(session_uid);
  return ret;
}

int callback_glewlwyd_check_admin_session (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  char * session_uid;
  json_t * j_user, * j_element;
  int ret;
  size_t index;
  
  if ((session_uid = get_session_id(config, request)) != NULL) {
    j_user = get_user_for_session(config, session_uid);
    if (check_result_value(j_user, G_OK) && json_object_get(json_object_get(j_user, "user"), "enabled") == json_true()) {
      ret = U_CALLBACK_UNAUTHORIZED;
      json_array_foreach(json_object_get(json_object_get(j_user, "user"), "scope"), index, j_element) {
        if (0 == o_strcmp(json_string_value(j_element), config->admin_scope)) {
          response->shared_data = json_deep_copy(json_object_get(j_user, "user"));
          ret = U_CALLBACK_CONTINUE;
        }
      }
    } else {
      ret = U_CALLBACK_UNAUTHORIZED;
    }
    json_decref(j_user);
  } else {
    ret = U_CALLBACK_UNAUTHORIZED;
  }
  o_free(session_uid);
  return ret;
}

int callback_glewlwyd_close_check_session (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (response->shared_data != NULL) {
    json_decref((json_t *)response->shared_data);
  }
  if (request->callback_position < 2) {
    ulfius_set_empty_body_response(response, 404);
  }
  return U_CALLBACK_COMPLETE;
}

int callback_glewlwyd_user_auth (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_param = ulfius_get_json_body_request(request, NULL), * j_result = NULL;
  const char * ip_source = get_ip_source(request);
  char * session_uid, session_str_array[129];
  time_t now;
  
  time(&now);
  if (j_param != NULL) {
    if (json_object_get(j_param, "username") != NULL && json_is_string(json_object_get(j_param, "username")) && json_string_length(json_object_get(j_param, "username"))) {
      if (json_object_get(j_param, "scheme_type") == NULL || 0 == o_strcmp(json_string_value(json_object_get(j_param, "scheme_type")), "password")) {
        if (json_object_get(j_param, "password") != NULL && json_is_string(json_object_get(j_param, "password")) && json_string_length(json_object_get(j_param, "password"))) {
          j_result = auth_check_user_credentials(config, json_string_value(json_object_get(j_param, "username")), json_string_value(json_object_get(j_param, "password")));
          if (check_result_value(j_result, G_OK)) {
            if ((session_uid = get_session_id(config, request)) == NULL) {
              session_uid = o_strdup(rand_string(session_str_array, 128));
            }
            if (user_session_update(config, session_uid, u_map_get_case(request->map_header, "user-agent"), json_string_value(json_object_get(j_param, "username")), NULL, NULL) != G_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_auth - Error user_session_update (1)");
              response->status = 500;
            } else {
              ulfius_add_cookie_to_response(response, GLEWLWYD_DEFAULT_SESSION_KEY, session_uid, NULL, GLEWLWYD_DEFAULT_SESSION_EXPIRATION_COOKIE, NULL, "/", 0, 0);
            }
            o_free(session_uid);
          } else {
            if (check_result_value(j_result, G_ERROR_UNAUTHORIZED)) {
              y_log_message(Y_LOG_LEVEL_WARNING, "Security - Error login/password for username %s at IP Address %s", json_string_value(json_object_get(j_param, "username")), ip_source);
            }
            if ((session_uid = get_session_id(config, request)) != NULL && user_session_update(config, session_uid, u_map_get_case(request->map_header, "user-agent"), json_string_value(json_object_get(j_param, "username")), NULL, NULL) != G_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_auth - Error user_session_update (2)");
            }
            o_free(session_uid);
            response->status = 401;
          }
          json_decref(j_result);
        } else if (json_object_get(j_param, "password") != NULL && !json_is_string(json_object_get(j_param, "password"))) {
          ulfius_set_string_body_response(response, 400, "password must be a string");
        } else {
          session_uid = get_session_id(config, request);
          j_result = get_users_for_session(config, session_uid);
          if (check_result_value(j_result, G_OK)) {
            // Refresh username to set as default
            if (user_session_update(config, u_map_get(request->map_cookie, GLEWLWYD_DEFAULT_SESSION_KEY), u_map_get_case(request->map_header, "user-agent"), json_string_value(json_object_get(j_param, "username")), NULL, NULL) != G_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_auth - Error user_session_update (3)");
              response->status = 500;
            }
          } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
            response->status = 401;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_auth - Error get_users_for_session");
            response->status = 500;
          }
          o_free(session_uid);
          json_decref(j_result);
        }
      } else {
        if (json_object_get(j_param, "scheme_type") != NULL && json_is_string(json_object_get(j_param, "scheme_type")) && json_string_length(json_object_get(j_param, "scheme_name")) && json_object_get(j_param, "scheme_name") != NULL && json_is_string(json_object_get(j_param, "scheme_name")) && json_string_length(json_object_get(j_param, "scheme_name")) && json_object_get(j_param, "value") != NULL && json_is_object(json_object_get(j_param, "value"))) {
          j_result = auth_check_user_scheme(config, json_string_value(json_object_get(j_param, "scheme_type")), json_string_value(json_object_get(j_param, "scheme_name")), json_string_value(json_object_get(j_param, "username")), json_object_get(j_param, "value"));
          if (check_result_value(j_result, G_ERROR_PARAM)) {
            ulfius_set_string_body_response(response, 400, "bad scheme parameters");
          } else if (check_result_value(j_result, G_ERROR_UNAUTHORIZED)) {
            response->status = 401;
          } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
            response->status = 404;
          } else if (check_result_value(j_result, G_OK)) {
            if ((session_uid = get_session_id(config, request)) == NULL) {
              session_uid = o_strdup(rand_string(session_str_array, 128));
            }
            if (user_session_update(config, session_uid, u_map_get_case(request->map_header, "user-agent"), json_string_value(json_object_get(j_param, "username")), json_string_value(json_object_get(j_param, "scheme_type")), json_string_value(json_object_get(j_param, "scheme_name"))) != G_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_auth - Error user_session_update (4)");
              response->status = 500;
            } else {
              ulfius_add_cookie_to_response(response, GLEWLWYD_DEFAULT_SESSION_KEY, session_uid, NULL, GLEWLWYD_DEFAULT_SESSION_EXPIRATION_COOKIE, NULL, "/", 0, 0);
            }
            o_free(session_uid);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_auth - Error auth_check_user_scheme");
            response->status = 500;
          }
          json_decref(j_result);
        } else {
          ulfius_set_string_body_response(response, 400, "scheme_type, scheme_name and value are mandatory");
        }
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

int callback_glewlwyd_user_auth_trigger (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_param = ulfius_get_json_body_request(request, NULL), * j_result = NULL;

  if (j_param != NULL) {
    if (json_object_get(j_param, "username") != NULL && json_is_string(json_object_get(j_param, "username")) && json_string_length(json_object_get(j_param, "username"))) {
      if (json_object_get(j_param, "scheme_type") != NULL && json_is_string(json_object_get(j_param, "scheme_type")) && json_string_length(json_object_get(j_param, "scheme_type")) && json_object_get(j_param, "scheme_name") != NULL && json_is_string(json_object_get(j_param, "scheme_name")) && json_string_length(json_object_get(j_param, "scheme_name"))) {
        j_result = auth_trigger_user_scheme(config, json_string_value(json_object_get(j_param, "scheme_type")), json_string_value(json_object_get(j_param, "scheme_name")), json_string_value(json_object_get(j_param, "username")), j_param);
        if (check_result_value(j_result, G_ERROR_PARAM)) {
          ulfius_set_string_body_response(response, 400, "bad scheme parameters");
        } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
          response->status = 404;
        } else if (check_result_value(j_result, G_ERROR_UNAUTHORIZED)) {
          response->status = 401;
        } else if (check_result_value(j_result, G_OK)) {
          ulfius_set_json_body_response(response, 200, json_object_get(j_result, "trigger"));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_auth_trigger - Error auth_check_user_scheme");
          response->status = 500;
        }
        json_decref(j_result);
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

int callback_glewlwyd_user_delete_session (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session;
  char * session_uid = get_session_id(config, request);
  
  if (session_uid != NULL && o_strlen(session_uid)) {
    j_session = get_users_for_session(config, session_uid);
    if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
      response->status = 404;
    } else if (!check_result_value(j_session, G_OK)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_delete_session - Error get_user_for_session");
      response->status = 500;
    } else if (user_session_delete(config, session_uid) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_delete_session - Error user_session_delete");
      response->status = 500;
    } else {
      ulfius_add_cookie_to_response(response, GLEWLWYD_DEFAULT_SESSION_KEY, "", NULL, -1, NULL, NULL, 0, 0);
    }
    json_decref(j_session);
  } else {
    response->status = 404;
  }
  o_free(session_uid);
  
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_user_get_schemes_from_scopes (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_result;
  char * session_uid = get_session_id(config, request);

  if (u_map_get(request->map_url, "scope") != NULL) {
    j_result = get_validated_auth_scheme_list_from_scope_list(config, u_map_get(request->map_url, "scope"), session_uid);
    if (check_result_value(j_result, G_OK)) {
      ulfius_set_json_body_response(response, 200, json_object_get(j_result, "scheme"));
    } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
      response->status = 404;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_get_schemes_from_scopes - Error get_validated_auth_scheme_list_from_scope_list");
      response->status = 500;
    }
    json_decref(j_result);
  } else {
    response->status = 400;
  }
  o_free(session_uid);
  
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_user_session_scope_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_user = (json_t *)response->shared_data, * j_scope_list;
  
  if (config != NULL && j_user != NULL) {
    j_scope_list = get_granted_scopes_for_client(config, j_user, u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope_list"));
    if (check_result_value(j_scope_list, G_OK)) {
      ulfius_set_json_body_response(response, 200, json_object_get(j_scope_list, "grant"));
    } else if (check_result_value(j_scope_list, G_ERROR_NOT_FOUND)) {
      response->status = 404;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_user_session_scope_grant - Error get_granted_scopes_for_client");
      response->status = 500;
    }
    json_decref(j_scope_list);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_user_session_scope_grant - Error config or j_user is NULL");
    response->status = 500;
  }
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_set_user_session_scope_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_user = (json_t *)response->shared_data, * j_body = ulfius_get_json_body_request(request, NULL), * j_client;
  int res;
  
  if (config != NULL && j_user != NULL) {
    if (json_object_get(j_body, "scope") != NULL && json_is_string(json_object_get(j_body, "scope"))) {
      j_client = get_client(config, u_map_get(request->map_url, "client_id"), NULL);
      if (check_result_value(j_client, G_OK)) {
        res = set_granted_scopes_for_client(config, j_user, u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(j_body, "scope")));
        if (res == G_ERROR_NOT_FOUND) {
          response->status = 404;
        } else if (res == G_ERROR_PARAM) {
          response->status = 400;
        } else if (res == G_ERROR_UNAUTHORIZED) {
          response->status = 401;
        } else if (res != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user_session_scope_grant - Error set_granted_scopes_for_client");
          response->status = 500;
        }
      } else if (check_result_value(j_client, G_ERROR_NOT_FOUND)) {
        response->status = 404;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user_session_scope_grant - Error get_client");
        response->status = 500;
      }
      json_decref(j_client);
    } else {
      response->status = 400;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user_session_scope_grant - Error config or j_user is NULL");
    response->status = 500;
  }
  json_decref(j_body);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_module_type_list (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_module_type;
  
  j_module_type = get_module_type_list(config);
  if (check_result_value(j_module_type, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_module_type, "module"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_module_type_list - Error get_module_type_list");
    response->status = 500;
  }
  json_decref(j_module_type);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_user_module_list (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_module;
  
  j_module = get_user_module_list(config);
  if (check_result_value(j_module, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_module, "module"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_user_module_list - Error get_user_module_list");
    response->status = 500;
  }
  json_decref(j_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_user_module (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_module;
  
  j_module = get_user_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_module, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_module, "module"));
  } else if (check_result_value(j_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_user_module - Error get_user_module");
    response->status = 500;
  }
  json_decref(j_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_add_user_module (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_module, * j_module_valid;
  
  j_module = ulfius_get_json_body_request(request, NULL);
  if (j_module != NULL) {
    j_module_valid = is_user_module_valid(config, j_module, 1);
    if (check_result_value(j_module_valid, G_OK)) {
      if (add_user_module(config, j_module) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_user_module - Error add_user_module");
        response->status = 500;
      }
    } else if (check_result_value(j_module_valid, G_ERROR_PARAM)) {
      ulfius_set_json_body_response(response, 400, json_object_get(j_module_valid, "error"));
    } else if (!check_result_value(j_module_valid, G_OK)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_user_module - Error is_user_module_valid");
      response->status = 500;
    }
    json_decref(j_module_valid);
  } else {
    response->status = 400;
  }
  json_decref(j_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_set_user_module (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_module, * j_module_valid, * j_search_module;
  
  j_search_module = get_user_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_search_module, G_OK)) {
    j_module = ulfius_get_json_body_request(request, NULL);
    if (j_module != NULL) {
      j_module_valid = is_user_module_valid(config, j_module, 0);
      if (check_result_value(j_module_valid, G_OK)) {
        if (set_user_module(config, u_map_get(request->map_url, "name"), j_module) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user_module - Error set_user_module");
          response->status = 500;
        }
      } else if (check_result_value(j_module_valid, G_ERROR_PARAM)) {
        ulfius_set_json_body_response(response, 400, json_object_get(j_module_valid, "error"));
      } else if (!check_result_value(j_module_valid, G_OK)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user_module - Error is_user_module_valid");
        response->status = 500;
      }
      json_decref(j_module_valid);
    } else {
      response->status = 400;
    }
    json_decref(j_module);
  } else if (check_result_value(j_search_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user_module - Error get_user_module");
    response->status = 500;
  }
  json_decref(j_search_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_delete_user_module (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_search_module;
  
  j_search_module = get_user_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_search_module, G_OK)) {
    if (delete_user_module(config, u_map_get(request->map_url, "name")) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_user_module - Error delete_user_module");
      response->status = 500;
    }
  } else if (check_result_value(j_search_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_user_module - Error get_user_module");
    response->status = 500;
  }
  json_decref(j_search_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_manage_user_module (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_search_module;
  int res;
  
  j_search_module = get_user_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_search_module, G_OK)) {
    if (0 == o_strcmp("enable", u_map_get(request->map_url, "action"))) {
      res = manage_user_module(config, u_map_get(request->map_url, "name"), GLEWLWYD_MODULE_ACTION_START);
      if (res == G_ERROR_PARAM) {
        response->status = 400;
      } else if (res != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_manage_user_module - Error manage_user_module enable");
        response->status = 500;
      }
    } else if (0 == o_strcmp("disable", u_map_get(request->map_url, "action"))) {
      res = manage_user_module(config, u_map_get(request->map_url, "name"), GLEWLWYD_MODULE_ACTION_STOP);
      if (res == G_ERROR_PARAM) {
        response->status = 400;
      } else if (res != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_manage_user_module - Error manage_user_module disable");
        response->status = 500;
      }
    } else {
      response->status = 400;
    }
  } else if (check_result_value(j_search_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_manage_user_module - Error get_user_module");
    response->status = 500;
  }
  json_decref(j_search_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_user_auth_scheme_module_list (const struct _u_request * request, struct _u_response * response, void * user_auth_scheme_data) {
  struct config_elements * config = (struct config_elements *)user_auth_scheme_data;
  json_t * j_module;
  
  j_module = get_user_auth_scheme_module_list(config);
  if (check_result_value(j_module, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_module, "module"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_user_auth_scheme_module_list - Error get_user_auth_scheme_module_list");
    response->status = 500;
  }
  json_decref(j_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_user_auth_scheme_module (const struct _u_request * request, struct _u_response * response, void * user_auth_scheme_data) {
  struct config_elements * config = (struct config_elements *)user_auth_scheme_data;
  json_t * j_module;
  
  j_module = get_user_auth_scheme_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_module, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_module, "module"));
  } else if (check_result_value(j_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_user_auth_scheme_module - Error get_user_auth_scheme_module");
    response->status = 500;
  }
  json_decref(j_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_add_user_auth_scheme_module (const struct _u_request * request, struct _u_response * response, void * user_auth_scheme_data) {
  struct config_elements * config = (struct config_elements *)user_auth_scheme_data;
  json_t * j_module, * j_module_valid;
  
  j_module = ulfius_get_json_body_request(request, NULL);
  if (j_module != NULL) {
    j_module_valid = is_user_auth_scheme_module_valid(config, j_module, 1);
    if (check_result_value(j_module_valid, G_OK)) {
      if (add_user_auth_scheme_module(config, j_module) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_user_auth_scheme_module - Error add_user_auth_scheme_module");
        response->status = 500;
      }
    } else if (check_result_value(j_module_valid, G_ERROR_PARAM)) {
      ulfius_set_json_body_response(response, 400, json_object_get(j_module_valid, "error"));
    } else if (!check_result_value(j_module_valid, G_OK)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_user_auth_scheme_module - Error is_user_auth_scheme_module_valid");
      response->status = 500;
    }
    json_decref(j_module_valid);
  } else {
    response->status = 400;
  }
  json_decref(j_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_set_user_auth_scheme_module (const struct _u_request * request, struct _u_response * response, void * user_auth_scheme_data) {
  struct config_elements * config = (struct config_elements *)user_auth_scheme_data;
  json_t * j_module, * j_module_valid, * j_search_module;
  
  j_search_module = get_user_auth_scheme_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_search_module, G_OK)) {
    j_module = ulfius_get_json_body_request(request, NULL);
    if (j_module != NULL) {
      j_module_valid = is_user_auth_scheme_module_valid(config, j_module, 0);
      if (check_result_value(j_module_valid, G_OK)) {
        if (set_user_auth_scheme_module(config, u_map_get(request->map_url, "name"), j_module) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user_auth_scheme_module - Error set_user_auth_scheme_module");
          response->status = 500;
        }
      } else if (check_result_value(j_module_valid, G_ERROR_PARAM)) {
        ulfius_set_json_body_response(response, 400, json_object_get(j_module_valid, "error"));
      } else if (!check_result_value(j_module_valid, G_OK)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user_auth_scheme_module - Error is_user_auth_scheme_module_valid");
        response->status = 500;
      }
      json_decref(j_module_valid);
    } else {
      response->status = 400;
    }
    json_decref(j_module);
  } else if (check_result_value(j_search_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user_auth_scheme_module - Error get_user_auth_scheme_module");
    response->status = 500;
  }
  json_decref(j_search_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_delete_user_auth_scheme_module (const struct _u_request * request, struct _u_response * response, void * user_auth_scheme_data) {
  struct config_elements * config = (struct config_elements *)user_auth_scheme_data;
  json_t * j_search_module;
  
  j_search_module = get_user_auth_scheme_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_search_module, G_OK)) {
    if (delete_user_auth_scheme_module(config, u_map_get(request->map_url, "name")) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_user_auth_scheme_module - Error delete_user_auth_scheme_module");
      response->status = 500;
    }
  } else if (check_result_value(j_search_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_user_auth_scheme_module - Error get_user_auth_scheme_module");
    response->status = 500;
  }
  json_decref(j_search_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_manage_user_auth_scheme_module (const struct _u_request * request, struct _u_response * response, void * user_auth_scheme_data) {
  struct config_elements * config = (struct config_elements *)user_auth_scheme_data;
  json_t * j_search_module;
  int res;
  
  j_search_module = get_user_auth_scheme_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_search_module, G_OK)) {
    if (0 == o_strcmp("enable", u_map_get(request->map_url, "action"))) {
      res = manage_user_auth_scheme_module(config, u_map_get(request->map_url, "name"), GLEWLWYD_MODULE_ACTION_START);
      if (res == G_ERROR_PARAM) {
        response->status = 400;
      } else if (res != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_manage_user_auth_scheme_module - Error manage_user_auth_scheme_module enable");
        response->status = 500;
      }
    } else if (0 == o_strcmp("disable", u_map_get(request->map_url, "action"))) {
      res = manage_user_auth_scheme_module(config, u_map_get(request->map_url, "name"), GLEWLWYD_MODULE_ACTION_STOP);
      if (res == G_ERROR_PARAM) {
        response->status = 400;
      } else if (res != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_manage_user_auth_scheme_module - Error manage_user_auth_scheme_module disable");
        response->status = 500;
      }
    } else {
      response->status = 400;
    }
  } else if (check_result_value(j_search_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_manage_user_auth_scheme_module - Error get_user_auth_scheme_module");
    response->status = 500;
  }
  json_decref(j_search_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_client_module_list (const struct _u_request * request, struct _u_response * response, void * client_data) {
  struct config_elements * config = (struct config_elements *)client_data;
  json_t * j_module;
  
  j_module = get_client_module_list(config);
  if (check_result_value(j_module, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_module, "module"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_client_module_list - Error get_client_module_list");
    response->status = 500;
  }
  json_decref(j_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_client_module (const struct _u_request * request, struct _u_response * response, void * client_data) {
  struct config_elements * config = (struct config_elements *)client_data;
  json_t * j_module;
  
  j_module = get_client_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_module, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_module, "module"));
  } else if (check_result_value(j_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_client_module - Error get_client_module");
    response->status = 500;
  }
  json_decref(j_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_add_client_module (const struct _u_request * request, struct _u_response * response, void * client_data) {
  struct config_elements * config = (struct config_elements *)client_data;
  json_t * j_module, * j_module_valid;
  
  j_module = ulfius_get_json_body_request(request, NULL);
  if (j_module != NULL) {
    j_module_valid = is_client_module_valid(config, j_module, 1);
    if (check_result_value(j_module_valid, G_OK)) {
      if (add_client_module(config, j_module) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_client_module - Error add_client_module");
        response->status = 500;
      }
    } else if (check_result_value(j_module_valid, G_ERROR_PARAM)) {
      ulfius_set_json_body_response(response, 400, json_object_get(j_module_valid, "error"));
    } else if (!check_result_value(j_module_valid, G_OK)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_client_module - Error is_client_module_valid");
      response->status = 500;
    }
    json_decref(j_module_valid);
  } else {
    response->status = 400;
  }
  json_decref(j_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_set_client_module (const struct _u_request * request, struct _u_response * response, void * client_data) {
  struct config_elements * config = (struct config_elements *)client_data;
  json_t * j_module, * j_module_valid, * j_search_module;
  
  j_search_module = get_client_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_search_module, G_OK)) {
    j_module = ulfius_get_json_body_request(request, NULL);
    if (j_module != NULL) {
      j_module_valid = is_client_module_valid(config, j_module, 0);
      if (check_result_value(j_module_valid, G_OK)) {
        if (set_client_module(config, u_map_get(request->map_url, "name"), j_module) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_client_module - Error set_client_module");
          response->status = 500;
        }
      } else if (check_result_value(j_module_valid, G_ERROR_PARAM)) {
        ulfius_set_json_body_response(response, 400, json_object_get(j_module_valid, "error"));
      } else if (!check_result_value(j_module_valid, G_OK)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_client_module - Error is_client_module_valid");
        response->status = 500;
      }
      json_decref(j_module_valid);
    } else {
      response->status = 400;
    }
    json_decref(j_module);
  } else if (check_result_value(j_search_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_client_module - Error get_client_module");
    response->status = 500;
  }
  json_decref(j_search_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_delete_client_module (const struct _u_request * request, struct _u_response * response, void * client_data) {
  struct config_elements * config = (struct config_elements *)client_data;
  json_t * j_search_module;
  
  j_search_module = get_client_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_search_module, G_OK)) {
    if (delete_client_module(config, u_map_get(request->map_url, "name")) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_client_module - Error delete_client_module");
      response->status = 500;
    }
  } else if (check_result_value(j_search_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_client_module - Error get_client_module");
    response->status = 500;
  }
  json_decref(j_search_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_manage_client_module (const struct _u_request * request, struct _u_response * response, void * client_data) {
  struct config_elements * config = (struct config_elements *)client_data;
  json_t * j_search_module;
  int res;
  
  j_search_module = get_client_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_search_module, G_OK)) {
    if (0 == o_strcmp("enable", u_map_get(request->map_url, "action"))) {
      res = manage_client_module(config, u_map_get(request->map_url, "name"), GLEWLWYD_MODULE_ACTION_START);
      if (res == G_ERROR_PARAM) {
        response->status = 400;
      } else if (res != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_manage_client_module - Error manage_client_module enable");
        response->status = 500;
      }
    } else if (0 == o_strcmp("disable", u_map_get(request->map_url, "action"))) {
      res = manage_client_module(config, u_map_get(request->map_url, "name"), GLEWLWYD_MODULE_ACTION_STOP);
      if (res == G_ERROR_PARAM) {
        response->status = 400;
      } else if (res != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_manage_client_module - Error manage_client_module disable");
        response->status = 500;
      }
    } else {
      response->status = 400;
    }
  } else if (check_result_value(j_search_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_manage_client_module - Error get_client_module");
    response->status = 500;
  }
  json_decref(j_search_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_plugin_module_list (const struct _u_request * request, struct _u_response * response, void * plugin_data) {
  struct config_elements * config = (struct config_elements *)plugin_data;
  json_t * j_module;
  
  j_module = get_plugin_module_list(config);
  if (check_result_value(j_module, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_module, "module"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_plugin_module_list - Error get_plugin_module_list");
    response->status = 500;
  }
  json_decref(j_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_plugin_module (const struct _u_request * request, struct _u_response * response, void * plugin_data) {
  struct config_elements * config = (struct config_elements *)plugin_data;
  json_t * j_module;
  
  j_module = get_plugin_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_module, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_module, "module"));
  } else if (check_result_value(j_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_plugin_module - Error get_plugin_module");
    response->status = 500;
  }
  json_decref(j_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_add_plugin_module (const struct _u_request * request, struct _u_response * response, void * plugin_data) {
  struct config_elements * config = (struct config_elements *)plugin_data;
  json_t * j_module, * j_module_valid;
  
  j_module = ulfius_get_json_body_request(request, NULL);
  if (j_module != NULL) {
    j_module_valid = is_plugin_module_valid(config, j_module, 1);
    if (check_result_value(j_module_valid, G_OK)) {
      if (add_plugin_module(config, j_module) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_plugin_module - Error add_plugin_module");
        response->status = 500;
      }
    } else if (check_result_value(j_module_valid, G_ERROR_PARAM)) {
      ulfius_set_json_body_response(response, 400, json_object_get(j_module_valid, "error"));
    } else if (!check_result_value(j_module_valid, G_OK)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_plugin_module - Error is_plugin_module_valid");
      response->status = 500;
    }
    json_decref(j_module_valid);
  } else {
    response->status = 400;
  }
  json_decref(j_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_set_plugin_module (const struct _u_request * request, struct _u_response * response, void * plugin_data) {
  struct config_elements * config = (struct config_elements *)plugin_data;
  json_t * j_module, * j_module_valid, * j_search_module;
  
  j_search_module = get_plugin_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_search_module, G_OK)) {
    j_module = ulfius_get_json_body_request(request, NULL);
    if (j_module != NULL) {
      j_module_valid = is_plugin_module_valid(config, j_module, 0);
      if (check_result_value(j_module_valid, G_OK)) {
        if (set_plugin_module(config, u_map_get(request->map_url, "name"), j_module) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_plugin_module - Error set_plugin_module");
          response->status = 500;
        }
      } else if (check_result_value(j_module_valid, G_ERROR_PARAM)) {
        ulfius_set_json_body_response(response, 400, json_object_get(j_module_valid, "error"));
      } else if (!check_result_value(j_module_valid, G_OK)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_plugin_module - Error is_plugin_module_valid");
        response->status = 500;
      }
      json_decref(j_module_valid);
    } else {
      response->status = 400;
    }
    json_decref(j_module);
  } else if (check_result_value(j_search_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_plugin_module - Error get_plugin_module");
    response->status = 500;
  }
  json_decref(j_search_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_delete_plugin_module (const struct _u_request * request, struct _u_response * response, void * plugin_data) {
  struct config_elements * config = (struct config_elements *)plugin_data;
  json_t * j_search_module;
  
  j_search_module = get_plugin_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_search_module, G_OK)) {
    if (delete_plugin_module(config, u_map_get(request->map_url, "name")) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_plugin_module - Error delete_plugin_module");
      response->status = 500;
    }
  } else if (check_result_value(j_search_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_plugin_module - Error get_plugin_module");
    response->status = 500;
  }
  json_decref(j_search_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_manage_plugin_module (const struct _u_request * request, struct _u_response * response, void * plugin_data) {
  struct config_elements * config = (struct config_elements *)plugin_data;
  json_t * j_search_module;
  int res;
  
  j_search_module = get_plugin_module(config, u_map_get(request->map_url, "name"));
  if (check_result_value(j_search_module, G_OK)) {
    if (0 == o_strcmp("enable", u_map_get(request->map_url, "action"))) {
      res = manage_plugin_module(config, u_map_get(request->map_url, "name"), GLEWLWYD_MODULE_ACTION_START);
      if (res == G_ERROR_PARAM) {
        response->status = 400;
      } else if (res != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_manage_plugin_module - Error manage_plugin_module enable");
        response->status = 500;
      }
    } else if (0 == o_strcmp("disable", u_map_get(request->map_url, "action"))) {
      res = manage_plugin_module(config, u_map_get(request->map_url, "name"), GLEWLWYD_MODULE_ACTION_STOP);
      if (res == G_ERROR_PARAM) {
        response->status = 400;
      } else if (res != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_manage_plugin_module - Error manage_plugin_module disable");
        response->status = 500;
      }
    } else {
      response->status = 400;
    }
  } else if (check_result_value(j_search_module, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_manage_plugin_module - Error get_plugin_module");
    response->status = 500;
  }
  json_decref(j_search_module);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_user_list (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_user_list;
  size_t offset = 0, limit = GLEWLWYD_DEFAULT_LIMIT_SIZE;
  long int l_converted = 0;
  char * endptr = NULL;
  
  if (u_map_get(request->map_url, "offset") != NULL) {
    l_converted = strtol(u_map_get(request->map_url, "offset"), &endptr, 10);
    if (!(*endptr) && l_converted > 0) {
      offset = (size_t)l_converted;
    }
  }
  if (u_map_get(request->map_url, "limit") != NULL) {
    l_converted = strtol(u_map_get(request->map_url, "limit"), &endptr, 10);
    if (!(*endptr) && l_converted > 0) {
      limit = (size_t)l_converted;
    }
  }
  j_user_list = get_user_list(config, u_map_get(request->map_url, "pattern"), offset, limit, u_map_get(request->map_url, "source"));
  if (check_result_value(j_user_list, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_user_list, "user"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_user_list - Error get_user_list");
    response->status = 500;
  }
  json_decref(j_user_list);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_user;
  
  j_user = get_user(config, u_map_get(request->map_url, "username"), u_map_get(request->map_url, "source"));
  if (check_result_value(j_user, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_user, "user"));
  } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_user - Error j_user");
    response->status = 500;
  }
  json_decref(j_user);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_add_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_user, * j_user_valid, * j_search_user, * j_body;
  
  j_user = ulfius_get_json_body_request(request, NULL);
  if (j_user != NULL) {
    j_user_valid = is_user_valid(config, NULL, j_user, 1, u_map_get(request->map_url, "source"));
    if (check_result_value(j_user_valid, G_OK)) {
      j_search_user = get_user(config, json_string_value(json_object_get(j_user, "username")), u_map_get(request->map_url, "source"));
      if (check_result_value(j_search_user, G_ERROR_NOT_FOUND)) {
        if (add_user(config, j_user, u_map_get(request->map_url, "source")) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_user - Error add_user");
          response->status = 500;
        }
      } else if (check_result_value(j_search_user, G_OK)) {
        j_body = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "username already exists");
        ulfius_set_json_body_response(response, 400, j_body);
        json_decref(j_body);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_user - Error get_user");
        response->status = 500;
      }
      json_decref(j_search_user);
    } else if (check_result_value(j_user_valid, G_ERROR_PARAM)) {
      ulfius_set_json_body_response(response, 400, json_object_get(j_user_valid, "user"));
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_user - Error is_user_valid");
      response->status = 500;
    }
    json_decref(j_user_valid);
  } else {
    response->status = 400;
  }
  json_decref(j_user);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_set_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_user, * j_user_valid, * j_search_user;
  
  j_search_user = get_user(config, u_map_get(request->map_url, "username"), u_map_get(request->map_url, "source"));
  if (check_result_value(j_search_user, G_OK)) {
    j_user = ulfius_get_json_body_request(request, NULL);
    if (j_user != NULL) {
      j_user_valid = is_user_valid(config, u_map_get(request->map_url, "username"), j_user, 0, json_string_value(json_object_get(j_search_user, "source")));
      if (check_result_value(j_user_valid, G_OK)) {
        if (set_user(config, u_map_get(request->map_url, "username"), j_user, json_string_value(json_object_get(j_search_user, "source"))) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user - Error set_user");
          response->status = 500;
        }
      } else if (check_result_value(j_user_valid, G_ERROR_PARAM)) {
        ulfius_set_json_body_response(response, 400, json_object_get(j_user_valid, "user"));
      } else if (!check_result_value(j_user_valid, G_OK)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user - Error is_user_valid");
        response->status = 500;
      }
      json_decref(j_user_valid);
    } else {
      response->status = 400;
    }
    json_decref(j_user);
  } else if (check_result_value(j_search_user, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_user - Error get_user");
    response->status = 500;
  }
  json_decref(j_search_user);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_delete_user (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_search_user;
  
  j_search_user = get_user(config, u_map_get(request->map_url, "username"), u_map_get(request->map_url, "source"));
  if (check_result_value(j_search_user, G_OK)) {
    if (delete_user(config, u_map_get(request->map_url, "username"), json_string_value(json_object_get(j_search_user, "source"))) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_user - Error set_user");
      response->status = 500;
    }
  } else if (check_result_value(j_search_user, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_user - Error get_user");
    response->status = 500;
  }
  json_decref(j_search_user);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_client_list (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_client_list;
  size_t offset = 0, limit = GLEWLWYD_DEFAULT_LIMIT_SIZE;
  long int l_converted = 0;
  char * endptr = NULL;
  
  if (u_map_get(request->map_url, "offset") != NULL) {
    l_converted = strtol(u_map_get(request->map_url, "offset"), &endptr, 10);
    if (!(*endptr) && l_converted > 0) {
      offset = (size_t)l_converted;
    }
  }
  if (u_map_get(request->map_url, "limit") != NULL) {
    l_converted = strtol(u_map_get(request->map_url, "limit"), &endptr, 10);
    if (!(*endptr) && l_converted > 0) {
      limit = (size_t)l_converted;
    }
  }
  j_client_list = get_client_list(config, u_map_get(request->map_url, "pattern"), offset, limit, u_map_get(request->map_url, "source"));
  if (check_result_value(j_client_list, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_client_list, "client"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_client_list - Error get_client_list");
    response->status = 500;
  }
  json_decref(j_client_list);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_client;
  
  j_client = get_client(config, u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "source"));
  if (check_result_value(j_client, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_client, "client"));
  } else if (check_result_value(j_client, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_client - Error j_client");
    response->status = 500;
  }
  json_decref(j_client);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_add_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_client, * j_client_valid, * j_search_client, * j_body;
  
  j_client = ulfius_get_json_body_request(request, NULL);
  if (j_client != NULL) {
    j_client_valid = is_client_valid(config, NULL, j_client, 1, u_map_get(request->map_url, "source"));
    if (check_result_value(j_client_valid, G_OK)) {
      j_search_client = get_client(config, json_string_value(json_object_get(j_client, "client_id")), u_map_get(request->map_url, "source"));
      if (check_result_value(j_search_client, G_ERROR_NOT_FOUND)) {
        if (add_client(config, j_client, u_map_get(request->map_url, "source")) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_client - Error add_client");
          response->status = 500;
        }
      } else if (check_result_value(j_search_client, G_OK)) {
        j_body = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "client_id already exists");
        ulfius_set_json_body_response(response, 400, j_body);
        json_decref(j_body);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_client - Error get_client");
        response->status = 500;
      }
      json_decref(j_search_client);
    } else if (check_result_value(j_client_valid, G_ERROR_PARAM)) {
      ulfius_set_json_body_response(response, 400, json_object_get(j_client_valid, "client"));
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_client - Error is_client_valid");
      response->status = 500;
    }
    json_decref(j_client_valid);
  } else {
    response->status = 400;
  }
  json_decref(j_client);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_set_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_client, * j_client_valid, * j_search_client;
  
  j_search_client = get_client(config, u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "source"));
  if (check_result_value(j_search_client, G_OK)) {
    j_client = ulfius_get_json_body_request(request, NULL);
    if (j_client != NULL) {
      j_client_valid = is_client_valid(config, u_map_get(request->map_url, "client_id"), j_client, 0, json_string_value(json_object_get(j_search_client, "source")));
      if (check_result_value(j_client_valid, G_OK)) {
        if (set_client(config, u_map_get(request->map_url, "client_id"), j_client, json_string_value(json_object_get(j_search_client, "source"))) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_client - Error set_client");
          response->status = 500;
        }
      } else if (check_result_value(j_client_valid, G_ERROR_PARAM)) {
        ulfius_set_json_body_response(response, 400, json_object_get(j_client_valid, "client"));
      } else if (!check_result_value(j_client_valid, G_OK)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_client - Error is_client_valid");
        response->status = 500;
      }
      json_decref(j_client_valid);
    } else {
      response->status = 400;
    }
    json_decref(j_client);
  } else if (check_result_value(j_search_client, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_client - Error get_client");
    response->status = 500;
  }
  json_decref(j_search_client);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_delete_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_search_client;
  
  j_search_client = get_client(config, u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "source"));
  if (check_result_value(j_search_client, G_OK)) {
    if (delete_client(config, u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(j_search_client, "source"))) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_client - Error set_client");
      response->status = 500;
    }
  } else if (check_result_value(j_search_client, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_client - Error get_client");
    response->status = 500;
  }
  json_decref(j_search_client);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_scope_list (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_scope_list;
  size_t offset = 0, limit = GLEWLWYD_DEFAULT_LIMIT_SIZE;
  long int l_converted = 0;
  char * endptr = NULL;
  
  if (u_map_get(request->map_url, "offset") != NULL) {
    l_converted = strtol(u_map_get(request->map_url, "offset"), &endptr, 10);
    if (!(*endptr) && l_converted > 0) {
      offset = (size_t)l_converted;
    }
  }
  if (u_map_get(request->map_url, "limit") != NULL) {
    l_converted = strtol(u_map_get(request->map_url, "limit"), &endptr, 10);
    if (!(*endptr) && l_converted > 0) {
      limit = (size_t)l_converted;
    }
  }
  j_scope_list = get_scope_list(config, u_map_get(request->map_url, "pattern"), offset, limit);
  if (check_result_value(j_scope_list, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_scope_list, "scope"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_scope_list - Error get_scope_list");
    response->status = 500;
  }
  json_decref(j_scope_list);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_get_scope (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_scope;
  
  j_scope = get_scope(config, u_map_get(request->map_url, "scope"));
  if (check_result_value(j_scope, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_scope, "scope"));
  } else if (check_result_value(j_scope, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_get_scope - Error get_scope");
    response->status = 500;
  }
  json_decref(j_scope);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_add_scope (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_scope, * j_scope_valid, * j_search_scope, * j_body;
  
  j_scope = ulfius_get_json_body_request(request, NULL);
  if (j_scope != NULL) {
    j_scope_valid = is_scope_valid(config, NULL, j_scope, 1);
    if (check_result_value(j_scope_valid, G_OK)) {
      j_search_scope = get_scope(config, json_string_value(json_object_get(j_scope, "name")));
      if (check_result_value(j_search_scope, G_ERROR_NOT_FOUND)) {
        if (add_scope(config, j_scope) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_scope - Error add_scope");
          response->status = 500;
        }
      } else if (check_result_value(j_search_scope, G_OK)) {
        j_body = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "scope already exists");
        ulfius_set_json_body_response(response, 400, j_body);
        json_decref(j_body);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_scope - Error get_scope");
        response->status = 500;
      }
      json_decref(j_search_scope);
    } else if (check_result_value(j_scope_valid, G_ERROR_PARAM)) {
      ulfius_set_json_body_response(response, 400, json_object_get(j_scope_valid, "error"));
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_add_scope - Error is_scope_valid");
      response->status = 500;
    }
    json_decref(j_scope_valid);
  } else {
    response->status = 400;
  }
  json_decref(j_scope);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_set_scope (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_scope, * j_scope_valid, * j_search_scope;
  
  j_search_scope = get_scope(config, u_map_get(request->map_url, "scope"));
  if (check_result_value(j_search_scope, G_OK)) {
    j_scope = ulfius_get_json_body_request(request, NULL);
    if (j_scope != NULL) {
      j_scope_valid = is_scope_valid(config, u_map_get(request->map_url, "scope"), j_scope, 0);
      if (check_result_value(j_scope_valid, G_OK)) {
        if (set_scope(config, u_map_get(request->map_url, "scope"), j_scope) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_scope - Error set_scope");
          response->status = 500;
        }
      } else if (check_result_value(j_scope_valid, G_ERROR_PARAM)) {
        ulfius_set_json_body_response(response, 400, json_object_get(j_scope_valid, "error"));
      } else if (!check_result_value(j_scope_valid, G_OK)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_scope - Error is_scope_valid");
        response->status = 500;
      }
      json_decref(j_scope_valid);
    } else {
      response->status = 400;
    }
    json_decref(j_scope);
  } else if (check_result_value(j_search_scope, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_set_scope - Error get_scope");
    response->status = 500;
  }
  json_decref(j_search_scope);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_delete_scope (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_search_scope;
  
  j_search_scope = get_scope(config, u_map_get(request->map_url, "scope"));
  if (check_result_value(j_search_scope, G_OK)) {
    if (delete_scope(config, u_map_get(request->map_url, "scope")) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_scope - Error set_scope");
      response->status = 500;
    }
  } else if (check_result_value(j_search_scope, G_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_delete_scope - Error get_scope");
    response->status = 500;
  }
  json_decref(j_search_scope);
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_user_get_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session;
  char * session_uid = get_session_id(config, request);
  
  if (session_uid != NULL && o_strlen(session_uid)) {
    j_session = get_users_for_session(config, session_uid);
    if (check_result_value(j_session, G_OK)) {
      ulfius_set_json_body_response(response, 200, json_object_get(j_session, "session"));
    } else if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
      response->status = 401;
      ulfius_add_cookie_to_response(response, GLEWLWYD_DEFAULT_SESSION_KEY, "", NULL, -1, NULL, NULL, 0, 0);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_get_session - Error get_user_for_session");
      response->status = 500;
    }
    json_decref(j_session);
  } else {
    response->status = 401;
    ulfius_add_cookie_to_response(response, GLEWLWYD_DEFAULT_SESSION_KEY, "", NULL, -1, NULL, NULL, 0, 0);
  }
  o_free(session_uid);
  
  return U_CALLBACK_CONTINUE;
}

int callback_glewlwyd_user_update_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_session, * j_profile, * j_result;
  char * session_uid = get_session_id(config, request);

  if (session_uid != NULL && o_strlen(session_uid)) {
    j_session = get_user_for_session(config, session_uid);
    if (check_result_value(j_session, G_OK)) {
      j_profile = ulfius_get_json_body_request(request, NULL);
      if (j_profile != NULL && json_is_object(j_profile)) {
        j_result = user_set_profile(config, json_string_value(json_object_get(json_object_get(j_session, "user"), "username")), j_profile);
        if (check_result_value(j_result, G_ERROR_PARAM)) {
          ulfius_set_json_body_response(response, 400, json_object_get(j_result, "error"));
        } else if (!check_result_value(j_result, G_OK)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_update_profile - Error user_set_profile");
          response->status = 500;
        }
        json_decref(j_result);
      } else {
        response->status = 400;
      }
      json_decref(j_profile);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_glewlwyd_user_update_profile - Error get_user_for_session");
      response->status = 500;
    }
    json_decref(j_session);
  } else {
    response->status = 404;
    ulfius_add_cookie_to_response(response, GLEWLWYD_DEFAULT_SESSION_KEY, "", NULL, -1, NULL, NULL, 0, 0);
  }
  o_free(session_uid);
  
  return U_CALLBACK_CONTINUE;
}


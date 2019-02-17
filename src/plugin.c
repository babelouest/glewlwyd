#include <string.h>
#include <ctype.h>
#include "glewlwyd.h"

int glewlwyd_callback_add_plugin_endpoint(struct config_plugin * config, const char * method, const char * prefix, const char * url, unsigned int priority, int (* callback)(const struct _u_request * request, struct _u_response * response, void * user_data), void * user_data) {
  int ret;
  char * p_url;

  if (config != NULL && config->glewlwyd_config != NULL && config->glewlwyd_config->instance != NULL && method != NULL && prefix != NULL && url != NULL && callback != NULL) {
    p_url = msprintf("%s/%s", prefix, url);
    if (p_url != NULL) {
      y_log_message(Y_LOG_LEVEL_INFO, "add url %s %s/%s", method, config->glewlwyd_config->api_prefix, p_url);
      if (ulfius_add_endpoint_by_val(config->glewlwyd_config->instance, method, config->glewlwyd_config->api_prefix, p_url, GLEWLWYD_CALLBACK_PRIORITY_PLUGIN + priority, callback, user_data) != U_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_add_plugin_endpoint - Error ulfius_add_endpoint_by_val %s - %s/%s", method, config->glewlwyd_config->api_prefix, p_url);
        ret = G_ERROR;
      } else {
        ret = G_OK;
      }
      o_free(p_url);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_add_plugin_endpoint - Error allocating resources for p_url");
      ret = G_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_add_plugin_endpoint - Error input paramters");
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int glewlwyd_callback_remove_plugin_endpoint(struct config_plugin * config, const char * method, const char * prefix, const char * url) {
  int ret;
  char * p_url;

  if (config != NULL && config->glewlwyd_config != NULL && config->glewlwyd_config->instance != NULL && method != NULL && prefix != NULL && url != NULL) {
    p_url = msprintf("%s/%s", prefix, url);
    if (p_url != NULL) {
      ret = ulfius_remove_endpoint_by_val(config->glewlwyd_config->instance, method, config->glewlwyd_config->api_prefix, p_url);
      o_free(p_url);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_remove_plugin_endpoint - Error allocating resources for p_url");
      ret = G_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_remove_plugin_endpoint - Error input paramters");
    ret = G_ERROR_PARAM;
  }
  return ret;
}

json_t * glewlwyd_callback_is_session_valid(struct config_plugin * config, const struct _u_request * request, const char * scope_list) {
  json_t * j_user, * j_return, * j_scope_allowed;
  
  if (config != NULL && request != NULL) {
    j_user = get_user_for_session(config->glewlwyd_config, u_map_get(request->map_cookie, GLEWLWYD_DEFAULT_SESSION_KEY));
    // Check if session is valid
    if (check_result_value(j_user, G_OK)) {
      if (scope_list != NULL) {
        // For all allowed scope, check that the current session has a valid session
        j_scope_allowed = get_validated_auth_scheme_list_from_scope_list(config->glewlwyd_config, scope_list, u_map_get(request->map_cookie, GLEWLWYD_DEFAULT_SESSION_KEY));
        if (check_result_value(j_scope_allowed, G_OK)) {
          j_return = json_pack("{sis{sOsO}}", "result", G_OK, "session", "scope", json_object_get(j_scope_allowed, "scheme"), "user", json_object_get(j_user, "user"));
        } else if (check_result_value(j_scope_allowed, G_ERROR_UNAUTHORIZED)) {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
        json_decref(j_scope_allowed);
      } else {
        // TODO
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      }
    } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

/**
 * TODO
 */
json_t * glewlwyd_callback_is_user_valid(struct config_plugin * config, const char * username, const char * password, const char * scope_list) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "glewlwyd_callback_is_user_valid - Not implemented");
  return NULL;
}

json_t * glewlwyd_callback_is_client_valid(struct config_plugin * config, const char * client_id, const char * password, const char * scope_list) {
  json_t * j_return, * j_client, * j_client_credentials, * j_element;
  int password_checked = 1, scope_checked = 1, i, scope_allowed;
  char ** scope_array = NULL;
  size_t index;

  if (config != NULL && client_id != NULL) {
    j_client = get_client(config->glewlwyd_config, client_id);
    if (check_result_value(j_client, G_OK) && json_object_get(json_object_get(j_client, "client"), "enabled") == json_true()) {
      if (password != NULL) {
        j_client_credentials = auth_check_client_credentials(config->glewlwyd_config, client_id, password);
        if (!check_result_value(j_client_credentials, G_OK)) {
          password_checked = 0;
        }
        json_decref(j_client_credentials);
      }
      if (scope_list != NULL) {
        if (split_string(scope_list, " ", &scope_array) > 0) {
          for (i=0; scope_array[i] != NULL; i++) {
            scope_allowed = 0;
            json_array_foreach(json_object_get(json_object_get(j_client, "client"), "scope"), index, j_element) {
              if (0 == o_strcmp(scope_array[i], json_string_value(j_element))) {
                scope_allowed = 1;
              }
            }
            if (!scope_allowed) {
              scope_checked = 0;
              j_return = json_pack("{si}", "result", G_ERROR);
              break;
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_is_client_valid - Error get_client");
          scope_checked = 0;
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        free_string_array(scope_array);
      }
      if (password_checked && scope_checked) {
        j_return = json_pack("{sisO}", "result", G_OK, "client", json_object_get(j_client, "client"));
      }

    } else if (check_result_value(j_client, G_ERROR_NOT_FOUND) || json_object_get(json_object_get(j_client, "client"), "enabled") != json_true()) {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_is_client_valid - Error get_client");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_client);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

json_t * glewlwyd_callback_get_client_granted_scopes(struct config_plugin * config, const char * client_id, const char * username, const char * scope_list) {
  json_t * j_user = get_user(config->glewlwyd_config, username), * j_grant = NULL;
  if (check_result_value(j_user, G_OK)) {
    j_grant = get_granted_scopes_for_client(config->glewlwyd_config, json_object_get(j_user, "user"), client_id, scope_list);
  } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)){
    j_grant = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_get_client_granted_scopes - Error get_user");
    j_grant = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_user);
  return j_grant;
}

char * glewlwyd_callback_get_login_url(struct config_plugin * config, const char * client_id, const char * scope_list, const char * callback_url) {
  char * encoded_callback_url = NULL, * encoded_client_id = NULL, * encoded_scope_list = NULL, * login_url;
  if (callback_url != NULL) {
    encoded_callback_url = url_encode(callback_url);
  }
  if (client_id != NULL) {
    encoded_client_id = url_encode(client_id);
  }
  if (scope_list != NULL) {
    encoded_scope_list = url_encode(scope_list);
  }
  login_url = msprintf("%s/%s?%s%s%s%s%s%s",
                       config->glewlwyd_config->external_url,
                       config->glewlwyd_config->login_url,
                       (encoded_client_id!=NULL?"client_id=":""),
                       (encoded_client_id!=NULL?encoded_client_id:""),
                       (encoded_scope_list!=NULL?"&scope=":""),
                       (encoded_scope_list!=NULL?encoded_scope_list:""),
                       (encoded_callback_url!=NULL?"&callback_url=":""),
                       (encoded_callback_url!=NULL?encoded_callback_url:""));
  o_free(encoded_callback_url);
  o_free(encoded_client_id);
  o_free(encoded_scope_list);
  return login_url;
}

char * glewlwyd_callback_get_plugin_external_url(struct config_plugin * config, const char * name) {
  return msprintf("%s/%s/%s", config->glewlwyd_config->external_url, config->glewlwyd_config->api_prefix, name);
}

char * glewlwyd_callback_generate_hash(struct config_plugin * config, const char * data) {
  return generate_hash(config->glewlwyd_config, config->glewlwyd_config->hash_algorithm, data);
}

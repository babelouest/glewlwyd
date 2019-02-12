#include "glewlwyd.h"

int glewlwyd_callback_add_plugin_endpoint(struct config_plugin * config, const char * method, const char * prefix, const char * url, unsigned int priority, int (* callback)(const struct _u_request * request, struct _u_response * response, void * user_data), void * user_data) {
  int ret;
  char * p_url;

  if (config != NULL && config->glewlwyd_config != NULL && config->glewlwyd_config->instance != NULL && method != NULL && prefix != NULL && url != NULL && callback != NULL) {
    p_url = msprintf("%s/%s", prefix, url);
    if (p_url != NULL) {
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

/**
 * TODO
 */
json_t * glewlwyd_callback_is_session_valid(struct config_plugin * config, const char * session_id, const char * scope_list) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "glewlwyd_callback_is_session_valid - Not implemented");
  return NULL;
}

/**
 * TODO
 */
json_t * glewlwyd_callback_is_user_valid(struct config_plugin * config, const char * username, const char * password, const char * scope_list) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "glewlwyd_callback_is_user_valid - Not implemented");
  return NULL;
}

/**
 * TODO
 */
json_t * glewlwyd_callback_is_client_valid(struct config_plugin * config, const char * client_id, const char * password, const char * scope_list) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "glewlwyd_callback_is_client_valid - Not implemented");
  return NULL;
}

/**
 * TODO
 */
json_t * glewlwyd_callback_get_client_granted_scopes(struct config_plugin * config, const char * client_id, const char * username, const char * scope_list) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "glewlwyd_callback_is_client_granted_scopes - Not implemented");
  return NULL;
}

/**
 * TODO
 */
char * glewlwyd_callback_get_login_url(struct config_plugin * config, const char * client_id, const char * scope_list, const char * callback_url) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "glewlwyd_callback_get_login_url - Not implemented");
  return NULL;
}

/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * main functions definitions
 * and main process start
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
#include <getopt.h>
#include <libconfig.h>
#include <signal.h>
#include <dirent.h>
#include <dlfcn.h>
#include <gnutls/gnutls.h>
#include <crypt.h>

#include "glewlwyd.h"

/**
 *
 * Main function
 * 
 * Initialize config structure, parse the arguments and the config file
 * Then run the webservice
 *
 */
int main (int argc, char ** argv) {
  struct config_elements * config = o_malloc(sizeof(struct config_elements));
  int res;
  
  srand(time(NULL));
  if (config == NULL) {
    fprintf(stderr, "Memory error - config\n");
    return 1;
  } else if ((config->config_p = o_malloc(sizeof(struct config_plugin))) == NULL) {
    fprintf(stderr, "Memory error - config_p\n");
    o_free(config);
    return 1;
  }

  // Init plugin config structure
  config->config_p->glewlwyd_config = config;
  config->config_p->glewlwyd_callback_add_plugin_endpoint = &glewlwyd_callback_add_plugin_endpoint;
  config->config_p->glewlwyd_callback_remove_plugin_endpoint = &glewlwyd_callback_remove_plugin_endpoint;
  config->config_p->glewlwyd_callback_check_session_valid = &glewlwyd_callback_check_session_valid;
  config->config_p->glewlwyd_callback_check_user_valid = &glewlwyd_callback_check_user_valid;
  config->config_p->glewlwyd_callback_check_client_valid = &glewlwyd_callback_check_client_valid;
  config->config_p->glewlwyd_callback_get_client_granted_scopes = &glewlwyd_callback_get_client_granted_scopes;
  config->config_p->glewlwyd_callback_get_plugin_external_url = &glewlwyd_callback_get_plugin_external_url;
  config->config_p->glewlwyd_callback_get_login_url = &glewlwyd_callback_get_login_url;
  config->config_p->glewlwyd_callback_generate_hash = &glewlwyd_callback_generate_hash;
  
  // Init config structure with default values
  config->config_file = NULL;
  config->port = GLEWLWYD_DEFAULT_PORT;
  config->api_prefix = NULL;
  config->external_url = NULL;
  config->log_mode = Y_LOG_MODE_NONE;
  config->log_level = Y_LOG_LEVEL_NONE;
  config->log_file = NULL;
  config->allow_origin = o_strdup(GLEWLWYD_DEFAULT_ALLOW_ORIGIN);
  config->use_secure_connection = 0;
  config->secure_connection_key_file = NULL;
  config->secure_connection_pem_file = NULL;
  config->conn = NULL;
  config->session_key = o_strdup(GLEWLWYD_DEFAULT_SESSION_KEY);
  config->session_expiration = GLEWLWYD_DEFAULT_SESSION_EXPIRATION_COOKIE;
  config->salt_length = GLEWLWYD_DEFAULT_SALT_LENGTH;
  config->hash_algorithm = o_strdup(GLEWLWYD_DEFAULT_HASH_ALGORITHM);
  config->login_url = NULL;
  config->user_module_path = NULL;
  config->user_module_list = NULL;
  config->user_module_instance_list = NULL;
  config->client_module_path = NULL;
  config->client_module_list = NULL;
  config->client_module_instance_list = NULL;
  config->user_auth_scheme_module_path = NULL;
  config->user_auth_scheme_module_list = NULL;
  config->user_auth_scheme_module_instance_list = NULL;
  config->plugin_module_path = NULL;
  config->plugin_module_list = NULL;
  config->plugin_module_instance_list = NULL;
  config->admin_scope = NULL;
  config->profile_scope = NULL;
  
  config->static_file_config = o_malloc(sizeof(struct _static_file_config));
  if (config->static_file_config == NULL) {
    fprintf(stderr, "Error allocating resources for config->static_file_config, aborting\n");
    return 2;
  }
  config->static_file_config->files_path = NULL;
  config->static_file_config->url_prefix = NULL;
  config->static_file_config->redirect_on_404 = "/";
  config->static_file_config->map_header = o_malloc(sizeof(struct _u_map));
  if (config->static_file_config->map_header == NULL) {
    fprintf(stderr, "init - Error allocating resources for config->static_file_config->map_header, aborting\n");
    return 2;
  }
  u_map_init(config->static_file_config->map_header);
  config->static_file_config->mime_types = o_malloc(sizeof(struct _u_map));
  if (config->static_file_config->mime_types == NULL) {
    fprintf(stderr, "init - Error allocating resources for config->static_file_config->mime_types, aborting\n");
    return 2;
  }
  u_map_init(config->static_file_config->mime_types);
  u_map_put(config->static_file_config->mime_types, "*", "application/octet-stream");
  config->instance = o_malloc(sizeof(struct _u_instance));
  if (config->instance == NULL) {
    fprintf(stderr, "Error allocating resources for config->instance, aborting\n");
    return 2;
  }
  
  ulfius_init_instance(config->instance, config->port, NULL, NULL);

  if (pthread_mutex_init(&global_handler_close_lock, NULL) || 
      pthread_cond_init(&global_handler_close_cond, NULL)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "init - Error initializing global_handler_close_lock or global_handler_close_cond");
  }
  // Catch end signals to make a clean exit
  if (signal (SIGQUIT, exit_handler) == SIG_ERR || 
      signal (SIGINT, exit_handler) == SIG_ERR || 
      signal (SIGTERM, exit_handler) == SIG_ERR || 
      signal (SIGHUP, exit_handler) == SIG_ERR) {
    fprintf(stderr, "init - Error initializing end signal\n");
    return 1;
  }
  
  // First we parse command line arguments
  if (!build_config_from_args(argc, argv, config)) {
    fprintf(stderr, "Error reading command-line parameters\n");
    print_help(stderr);
    exit_server(&config, GLEWLWYD_ERROR);
  }
  
  // Then we parse configuration file
  // They have lower priority than command line parameters
  if (!build_config_from_file(config)) {
    fprintf(stderr, "Error config file\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  
  // Check if all mandatory configuration variables are present and correctly typed
  if (!check_config(config)) {
    fprintf(stderr, "Error initializing configuration\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  
  // Initialize user modules
  if (init_user_module_list(config) != G_OK) {
    fprintf(stderr, "Error initializing user modules\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  if (load_user_module_instance_list(config) != G_OK) {
    fprintf(stderr, "Error loading user modules instances\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  
  // Initialize client modules
  if (init_client_module_list(config) != G_OK) {
    fprintf(stderr, "Error initializing client modules\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  if (load_client_module_instance_list(config) != G_OK) {
    fprintf(stderr, "Error loading client modules instances\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  
  // Initialize user auth scheme modules
  if (init_user_auth_scheme_module_list(config) != G_OK) {
    fprintf(stderr, "Error initializing user auth scheme modules\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  if (load_user_auth_scheme_module_instance_list(config) != G_OK) {
    fprintf(stderr, "Error loading user auth scheme modules instances\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  
  // Initialize plugins
  if (init_plugin_module_list(config) != G_OK) {
    fprintf(stderr, "Error initializing plugins modules\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  if (load_plugin_module_instance_list(config) != G_OK) {
    fprintf(stderr, "Error loading plugins modules instances\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  
  // At this point, we declare all API endpoints and configure 
  
  // Authentication
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_auth, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/auth/trigger/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_auth_trigger, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_get_session, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/auth/schemes/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_get_schemes_from_scopes, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_delete_session, (void*)config);

  // Grant scopes endpoints
  ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/auth/grant/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_user_session, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/auth/grant/:client_id/:scope_list", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user_session_scope_grant, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/auth/grant/:client_id/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_user_session_scope_grant, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/auth/grant/*", GLEWLWYD_CALLBACK_PRIORITY_CLOSE, &callback_glewlwyd_close_check_session, (void*)config);

  // Modules check session
  ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/mod/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_admin_session, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/mod/*", GLEWLWYD_CALLBACK_PRIORITY_CLOSE, &callback_glewlwyd_close_check_session, (void*)config);

  // Get all module types available
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/type/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_module_type_list, (void*)config);
  
  // User modules management
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/user/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user_module_list, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/user/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/mod/user/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_user_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/mod/user/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_user_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/mod/user/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_user_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/mod/user/:name/:action", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_manage_user_module, (void*)config);

  // User auth scheme modules management
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/scheme/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user_auth_scheme_module_list, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/scheme/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user_auth_scheme_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/mod/scheme/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_user_auth_scheme_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/mod/scheme/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_user_auth_scheme_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/mod/scheme/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_user_auth_scheme_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/mod/scheme/:name/:action", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_manage_user_auth_scheme_module, (void*)config);

  // Client modules management
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/client/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_client_module_list, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/client/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_client_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/mod/client/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_client_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/mod/client/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_client_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/mod/client/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_client_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/mod/client/:name/:action", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_manage_client_module, (void*)config);

  // Plugin modules management
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/plugin/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_plugin_module_list, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/plugin/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_plugin_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/mod/plugin/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_plugin_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/mod/plugin/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_plugin_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/mod/plugin/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_plugin_module, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/mod/plugin/:name/:action", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_manage_plugin_module, (void*)config);

  // Other configuration
  ulfius_add_endpoint_by_val(config->instance, "GET", "/config", NULL, GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_server_configuration, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "OPTIONS", NULL, "*", GLEWLWYD_CALLBACK_PRIORITY_ZERO, &callback_glewlwyd_options, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->static_file_config->url_prefix, "*", GLEWLWYD_CALLBACK_PRIORITY_FILE, &callback_static_file, (void*)config->static_file_config);
  ulfius_set_default_endpoint(config->instance, &callback_default, (void*)config);

  // Set default headers
  u_map_put(config->instance->default_headers, "Access-Control-Allow-Origin", config->allow_origin);
  u_map_put(config->instance->default_headers, "Access-Control-Allow-Credentials", "true");
  u_map_put(config->instance->default_headers, "Cache-Control", "no-store");
  u_map_put(config->instance->default_headers, "Pragma", "no-cache");

  y_log_message(Y_LOG_LEVEL_INFO, "Start glewlwyd on port %d, prefix: %s, secure: %s", config->instance->port, config->api_prefix, config->use_secure_connection?"true":"false");
  
  if (config->use_secure_connection) {
    char * key_file = get_file_content(config->secure_connection_key_file);
    char * pem_file = get_file_content(config->secure_connection_pem_file);
    if (key_file != NULL && pem_file != NULL) {
      res = ulfius_start_secure_framework(config->instance, key_file, pem_file);
    } else {
      res = U_ERROR_PARAMS;
    }
    o_free(key_file);
    o_free(pem_file);
  } else {
    res = ulfius_start_framework(config->instance);
  }
  if (res == U_OK) {
    // Wait until stop signal is broadcasted
    pthread_mutex_lock(&global_handler_close_lock);
    pthread_cond_wait(&global_handler_close_cond, &global_handler_close_lock);
    pthread_mutex_unlock(&global_handler_close_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error starting glewlwyd webserver");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  if (pthread_mutex_destroy(&global_handler_close_lock) ||
      pthread_cond_destroy(&global_handler_close_cond)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error destroying global_handler_close_lock or global_handler_close_cond");
  }
  exit_server(&config, GLEWLWYD_STOP);
  return 0;
}

/**
 * Exit properly the server by closing opened connections, databases and files
 */
void exit_server(struct config_elements ** config, int exit_value) {
  int i;
  
  if (config != NULL && *config != NULL) {
    /* stop framework */
    ulfius_stop_framework((*config)->instance);
    ulfius_clean_instance((*config)->instance);
    h_close_db((*config)->conn);
    h_clean_connection((*config)->conn);
    
    // Cleaning data
    o_free((*config)->instance);
    
    for (i=0; i<pointer_list_size((*config)->user_module_instance_list); i++) {
      struct _user_module_instance * instance = (struct _user_module_instance *)pointer_list_get_at((*config)->user_module_instance_list, i);
      if (instance != NULL) {
        if (instance->enabled && instance->module->user_module_close((*config), instance->cls) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error user_module_close for instance '%s'/'%s'", instance->module->name, instance->name);
        }
        o_free(instance->name);
        o_free(instance);
      }
    }
    pointer_list_clean((*config)->user_module_instance_list);
    o_free((*config)->user_module_instance_list);
    
    for (i=0; i<pointer_list_size((*config)->user_module_list); i++) {
      struct _user_module * module = (struct _user_module *)pointer_list_get_at((*config)->user_module_list, i);
      if (module != NULL) {
        if (module->user_module_unload((*config)) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error user_module_close for module '%s'", module->name);
        }
/* 
 * dlclose() makes valgrind not useful when it comes to libraries
 * they say it's not relevant to use it anyway
 * I'll let it here until I'm sure
 */
#ifndef DEBUG
        if (dlclose(module->file_handle)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error dlclose for module '%s'", module->name);
        }
#endif
        o_free(module->name);
        o_free(module->display_name);
        o_free(module->description);
        o_free(module->parameters);
        o_free(module);
      }
    }
    pointer_list_clean((*config)->user_module_list);
    o_free((*config)->user_module_list);
    
    for (i=0; i<pointer_list_size((*config)->client_module_instance_list); i++) {
      struct _client_module_instance * instance = (struct _client_module_instance *)pointer_list_get_at((*config)->client_module_instance_list, i);
      if (instance != NULL) {
        if (instance->enabled && instance->module->client_module_close((*config), instance->cls) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error client_module_close for instance '%s'/'%s'", instance->module->name, instance->name);
        }
        o_free(instance->name);
        o_free(instance);
      }
    }
    pointer_list_clean((*config)->client_module_instance_list);
    o_free((*config)->client_module_instance_list);
    
    for (i=0; i<pointer_list_size((*config)->client_module_list); i++) {
      struct _client_module * module = (struct _client_module *)pointer_list_get_at((*config)->client_module_list, i);
      if (module != NULL) {
        if (module->client_module_unload((*config)) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error client_module_close for module '%s'", module->name);
        }
/* 
 * dlclose() makes valgrind not useful when it comes to libraries
 * they say it's not relevant to use it anyway
 * I'll let it here until I'm sure
 */
#ifndef DEBUG
        if (dlclose(module->file_handle)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error dlclose for module '%s'", module->name);
        }
#endif
        o_free(module->name);
        o_free(module->display_name);
        o_free(module->description);
        o_free(module->parameters);
        o_free(module);
      }
    }
    pointer_list_clean((*config)->client_module_list);
    o_free((*config)->client_module_list);
    
    for (i=0; i<pointer_list_size((*config)->user_auth_scheme_module_instance_list); i++) {
      struct _user_auth_scheme_module_instance * instance = (struct _user_auth_scheme_module_instance *)pointer_list_get_at((*config)->user_auth_scheme_module_instance_list, i);
      if (instance != NULL) {
        if (instance->enabled && instance->module->user_auth_scheme_module_close((*config), instance->cls) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error user_auth_scheme_module_close for instance '%s'/'%s'", instance->module->name, instance->name);
        }
        o_free(instance->name);
        o_free(instance);
      }
    }
    pointer_list_clean((*config)->user_auth_scheme_module_instance_list);
    o_free((*config)->user_auth_scheme_module_instance_list);
    
    for (i=0; i<pointer_list_size((*config)->user_auth_scheme_module_list); i++) {
      struct _user_auth_scheme_module * module = (struct _user_auth_scheme_module *)pointer_list_get_at((*config)->user_auth_scheme_module_list, i);
      if (module != NULL) {
        if (module->user_auth_scheme_module_unload((*config)) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error user_auth_scheme_module_close for module '%s'", module->name);
        }
#ifndef DEBUG
        if (dlclose(module->file_handle)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error dlclose for module '%s'", module->name);
        }
#endif
        o_free(module->name);
        o_free(module->display_name);
        o_free(module->description);
        o_free(module->parameters);
        o_free(module);
      }
    }
    pointer_list_clean((*config)->user_auth_scheme_module_list);
    o_free((*config)->user_auth_scheme_module_list);
    
    for (i=0; i<pointer_list_size((*config)->plugin_module_instance_list); i++) {
      struct _plugin_module_instance * instance = (struct _plugin_module_instance *)pointer_list_get_at((*config)->plugin_module_instance_list, i);
      if (instance != NULL) {
        if (instance->enabled && instance->module->plugin_module_close((*config)->config_p, instance->cls) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error plugin_module_close for instance '%s'/'%s'", instance->module->name, instance->name);
        }
        o_free(instance->name);
        o_free(instance);
      }
    }
    pointer_list_clean((*config)->plugin_module_instance_list);
    o_free((*config)->plugin_module_instance_list);
    
    for (i=0; i<pointer_list_size((*config)->plugin_module_list); i++) {
      struct _plugin_module * module = (struct _plugin_module *)pointer_list_get_at((*config)->plugin_module_list, i);
      if (module != NULL) {
        if (module->plugin_module_unload((*config)->config_p) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error plugin_module_unload for module '%s'", module->name);
        }
#ifndef DEBUG
        if (dlclose(module->file_handle)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error dlclose for module '%s'", module->name);
        }
#endif
        o_free(module->name);
        o_free(module->display_name);
        o_free(module->description);
        o_free(module->parameters);
        o_free(module);
      }
    }
    pointer_list_clean((*config)->plugin_module_list);
    o_free((*config)->plugin_module_list);
    
    o_free((*config)->config_file);
    o_free((*config)->api_prefix);
    o_free((*config)->admin_scope);
    o_free((*config)->profile_scope);
    o_free((*config)->external_url);
    o_free((*config)->log_file);
    o_free((*config)->allow_origin);
    o_free((*config)->secure_connection_key_file);
    o_free((*config)->secure_connection_pem_file);
    o_free((*config)->session_key);
    o_free((*config)->hash_algorithm);
    o_free((*config)->login_url);
    o_free((*config)->user_module_path);
    o_free((*config)->client_module_path);
    o_free((*config)->user_auth_scheme_module_path);
    o_free((*config)->plugin_module_path);
    
    if ((*config)->static_file_config != NULL) {
      u_map_clean_full((*config)->static_file_config->mime_types);
      u_map_clean_full((*config)->static_file_config->map_header);
      o_free((*config)->static_file_config->files_path);
      o_free((*config)->static_file_config->url_prefix);
      o_free((*config)->static_file_config);
    }
    
    o_free((*config)->config_p);
    o_free(*config);
    (*config) = NULL;
  }

  y_close_logs();
  exit(exit_value);
}

/**
 * Initialize the application configuration based on the command line parameters
 */
int build_config_from_args(int argc, char ** argv, struct config_elements * config) {
  int next_option;
  const char * short_options = "c::p::u::m::l::f::h::v::";
  char * tmp = NULL, * to_free = NULL, * one_log_mode = NULL;
  static const struct option long_options[]= {
    {"config-file", optional_argument, NULL, 'c'},
    {"port", optional_argument, NULL, 'p'},
    {"url-prefix", optional_argument, NULL, 'u'},
    {"log-mode", optional_argument, NULL, 'm'},
    {"log-level", optional_argument, NULL, 'l'},
    {"log-file", optional_argument, NULL, 'f'},
    {"help", optional_argument, NULL, 'h'},
    {"version", optional_argument, NULL, 'v'},
    {NULL, 0, NULL, 0}
  };
  
  if (config != NULL) {
    do {
      next_option = getopt_long(argc, argv, short_options, long_options, NULL);
      
      switch (next_option) {
        case 'c':
          if (optarg != NULL) {
            config->config_file = o_strdup(optarg);
            if (config->config_file == NULL) {
              fprintf(stderr, "Error allocating config->config_file, exiting\n");
              return 0;
            }
          } else {
            fprintf(stderr, "Error!\nNo config file specified\n");
            return 0;
          }
          break;
        case 'p':
          if (optarg != NULL) {
            config->instance->port = strtol(optarg, NULL, 10);
            if (config->instance->port <= 0 || config->instance->port > 65535) {
              fprintf(stderr, "Error!\nInvalid TCP Port number\n\tPlease specify an integer value between 1 and 65535");
              return 0;
            }
          } else {
            fprintf(stderr, "Error!\nNo TCP Port number specified\n");
            return 0;
          }
          break;
        case 'u':
          if (optarg != NULL) {
            config->api_prefix = o_strdup(optarg);
            if (config->api_prefix == NULL) {
              fprintf(stderr, "Error allocating config->api_prefix, exiting\n");
              return 0;
            }
          } else {
            fprintf(stderr, "Error!\nNo URL prefix specified\n");
            return 0;
          }
          break;
        case 'm':
          if (optarg != NULL) {
            tmp = o_strdup(optarg);
            if (tmp == NULL) {
              fprintf(stderr, "Error allocating log_mode, exiting\n");
              return 0;
            }
            one_log_mode = strtok(tmp, ",");
            while (one_log_mode != NULL) {
              if (0 == strncmp("console", one_log_mode, strlen("console"))) {
                config->log_mode += Y_LOG_MODE_CONSOLE;
              } else if (0 == strncmp("syslog", one_log_mode, strlen("syslog"))) {
                config->log_mode += Y_LOG_MODE_SYSLOG;
              } else if (0 == strncmp("journald", one_log_mode, strlen("journald"))) {
                config->log_mode += Y_LOG_MODE_JOURNALD;
              } else if (0 == strncmp("file", one_log_mode, strlen("file"))) {
                config->log_mode += Y_LOG_MODE_FILE;
              }
              one_log_mode = strtok(NULL, ",");
            }
            o_free(to_free);
          } else {
            fprintf(stderr, "Error!\nNo mode specified\n");
            return 0;
          }
          break;
        case 'l':
          if (optarg != NULL) {
            if (0 == strncmp("NONE", optarg, strlen("NONE"))) {
              config->log_level = Y_LOG_LEVEL_NONE;
            } else if (0 == strncmp("ERROR", optarg, strlen("ERROR"))) {
              config->log_level = Y_LOG_LEVEL_ERROR;
            } else if (0 == strncmp("WARNING", optarg, strlen("WARNING"))) {
              config->log_level = Y_LOG_LEVEL_WARNING;
            } else if (0 == strncmp("INFO", optarg, strlen("INFO"))) {
              config->log_level = Y_LOG_LEVEL_INFO;
            } else if (0 == strncmp("DEBUG", optarg, strlen("DEBUG"))) {
              config->log_level = Y_LOG_LEVEL_DEBUG;
            }
          } else {
            fprintf(stderr, "Error!\nNo log level specified\n");
            return 0;
          }
          break;
        case 'f':
          if (optarg != NULL) {
            config->log_file = o_strdup(optarg);
            if (config->log_file == NULL) {
              fprintf(stderr, "Error allocating config->log_file, exiting\n");
              return 0;
            }
          } else {
            fprintf(stderr, "Error!\nNo log file specified\n");
            return 0;
          }
          break;
        case 'h':
          print_help(stdout);
          return 0;
          break;
        case 'v':
          fprintf(stdout, "%s\n", _GLEWLWYD_VERSION_);
          return 0;
          break;
      }
      
    } while (next_option != -1);
    
    // If none exists, exit failure
    if (config->config_file == NULL) {
      fprintf(stderr, "No configuration file found, please specify a configuration file path\n");
      return 0;
    }
    
    return 1;
  } else {
    return 0;
  }
  
}

/**
 * Print help message to output file specified
 */
void print_help(FILE * output) {
  fprintf(output, "\nGlewlwyd OAuth2 authentication server\n");
  fprintf(output, "\n");
  fprintf(output, "Version %s\n", _GLEWLWYD_VERSION_);
  fprintf(output, "\n");
  fprintf(output, "Copyright 2016-2018 Nicolas Mora <mail@babelouest.org>\n");
  fprintf(output, "\n");
  fprintf(output, "This program is free software; you can redistribute it and/or\n");
  fprintf(output, "modify it under the terms of the GNU GENERAL PUBLIC LICENSE\n");
  fprintf(output, "License as published by the Free Software Foundation;\n");
  fprintf(output, "version 3 of the License.\n");
  fprintf(output, "\n");
  fprintf(output, "Command-line options:\n");
  fprintf(output, "\n");
  fprintf(output, "-c --config-file=PATH\n");
  fprintf(output, "\tPath to configuration file\n");
  fprintf(output, "-p --port=PORT\n");
  fprintf(output, "\tPort to listen to\n");
  fprintf(output, "-u --url-prefix=PREFIX\n");
  fprintf(output, "\tAPI URL prefix\n");
  fprintf(output, "-m --log-mode=MODE\n");
  fprintf(output, "\tLog Mode\n");
  fprintf(output, "\tconsole, syslog or file\n");
  fprintf(output, "\tIf you want multiple modes, separate them with a comma \",\"\n");
  fprintf(output, "\tdefault: console\n");
  fprintf(output, "-l --log-level=LEVEL\n");
  fprintf(output, "\tLog level\n");
  fprintf(output, "\tNONE, ERROR, WARNING, INFO, DEBUG\n");
  fprintf(output, "\tdefault: INFO\n");
  fprintf(output, "-f --log-file=PATH\n");
  fprintf(output, "\tPath for log file if log mode file is specified\n");
  fprintf(output, "-v --version\n");
  fprintf(output, "\tPrint Glewlwyd's current version\n\n");
  fprintf(output, "-h --help\n");
  fprintf(output, "\tPrint this message\n\n");
}

/**
 * handles signal catch to exit properly when ^C is used for example
 * I don't like global variables but it looks fine to people who designed this
 */
void exit_handler(int signal) {
  pthread_mutex_lock(&global_handler_close_lock);
  pthread_cond_signal(&global_handler_close_cond);
  pthread_mutex_unlock(&global_handler_close_lock);
}

/**
 * Initialize the application configuration based on the config file content
 * Read the config file, get mandatory variables and devices
 */
int build_config_from_file(struct config_elements * config) {
  
  config_t cfg;
  config_setting_t * root = NULL, * database = NULL, * mime_type_list = NULL, * mime_type = NULL;
  const char * str_value = NULL, * str_value_2 = NULL, * str_value_3 = NULL, * str_value_4 = NULL, * str_value_5 = NULL;
  int int_value = 0, i;
  char * one_log_mode;
  
  config_init(&cfg);
  
  if (!config_read_file(&cfg, config->config_file)) {
    fprintf(stderr, "Error parsing config file %s\nOn line %d error: %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
    config_destroy(&cfg);
    return 0;
  }
  
  if (config->instance->port == GLEWLWYD_DEFAULT_PORT) {
    // Get Port number to listen to
    if (config_lookup_int(&cfg, "port", &int_value) == CONFIG_TRUE) {
      config->instance->port = (uint)int_value;
    }
  }
  
  if (config->api_prefix == NULL && config_lookup_string(&cfg, "api_prefix", &str_value) == CONFIG_TRUE) {
    config->api_prefix = o_strdup(str_value);
    if (config->api_prefix == NULL) {
      fprintf(stderr, "Error allocating config->api_prefix, exiting\n");
      config_destroy(&cfg);
      return 0;
    }
  }

  if (config->log_mode == Y_LOG_MODE_NONE) {
    // Get log mode
    if (config_lookup_string(&cfg, "log_mode", &str_value) == CONFIG_TRUE) {
      one_log_mode = strtok((char *)str_value, ",");
      while (one_log_mode != NULL) {
        if (0 == strncmp("console", one_log_mode, strlen("console"))) {
          config->log_mode += Y_LOG_MODE_CONSOLE;
        } else if (0 == strncmp("syslog", one_log_mode, strlen("syslog"))) {
          config->log_mode += Y_LOG_MODE_SYSLOG;
        } else if (0 == strncmp("journald", one_log_mode, strlen("journald"))) {
          config->log_mode += Y_LOG_MODE_JOURNALD;
        } else if (0 == strncmp("file", one_log_mode, strlen("file"))) {
          config->log_mode += Y_LOG_MODE_FILE;
          // Get log file path
          if (config->log_file == NULL) {
            if (config_lookup_string(&cfg, "log_file", &str_value_2) == CONFIG_TRUE) {
              config->log_file = o_strdup(str_value_2);
              if (config->log_file == NULL) {
                fprintf(stderr, "Error allocating config->log_file, exiting\n");
                config_destroy(&cfg);
                return 0;
              }
            }
          }
        } else {
          fprintf(stderr, "Error, logging mode '%s' unknown\n", one_log_mode);
          config_destroy(&cfg);
          return 0;
        }
        one_log_mode = strtok(NULL, ",");
      }
    }
  }
  
  if (config->log_level == Y_LOG_LEVEL_NONE) {
    // Get log level
    if (config_lookup_string(&cfg, "log_level", &str_value) == CONFIG_TRUE) {
      if (0 == strncmp("NONE", str_value, strlen("NONE"))) {
        config->log_level = Y_LOG_LEVEL_NONE;
      } else if (0 == strncmp("ERROR", str_value, strlen("ERROR"))) {
        config->log_level = Y_LOG_LEVEL_ERROR;
      } else if (0 == strncmp("WARNING", str_value, strlen("WARNING"))) {
        config->log_level = Y_LOG_LEVEL_WARNING;
      } else if (0 == strncmp("INFO", str_value, strlen("INFO"))) {
        config->log_level = Y_LOG_LEVEL_INFO;
      } else if (0 == strncmp("DEBUG", str_value, strlen("DEBUG"))) {
        config->log_level = Y_LOG_LEVEL_DEBUG;
      }
    }
  }

  if (!y_init_logs(GLEWLWYD_LOG_NAME, config->log_mode, config->log_level, config->log_file, "Starting Glewlwyd SSO authentication service")) {
    fprintf(stderr, "Error initializing logs\n");
    return 0;
  }
  
  if (config->allow_origin == NULL) {
    // Get allow-origin value for CORS
    if (config_lookup_string(&cfg, "allow_origin", &str_value) == CONFIG_TRUE) {
      config->allow_origin = o_strdup(str_value);
      if (config->allow_origin == NULL) {
        fprintf(stderr, "Error allocating config->allow_origin, exiting\n");
        config_destroy(&cfg);
        return 0;
      }
    }
  }
  
  if (config_lookup_string(&cfg, "session_key", &str_value) == CONFIG_TRUE) {
    o_free(config->session_key);
    config->session_key = strdup(str_value);
  }
  
  if (config_lookup_string(&cfg, "external_url", &str_value) != CONFIG_TRUE) {
    fprintf(stderr, "external_url is mandatory, exiting\n");
    config_destroy(&cfg);
    return 0;
  } else {
    config->external_url = strdup(str_value);
    if (config->external_url == NULL) {
      fprintf(stderr, "Error allocating resources for config->external_url, exiting\n");
      config_destroy(&cfg);
      return 0;
    }
  }
  
  if (config_lookup_string(&cfg, "login_url", &str_value) != CONFIG_TRUE) {
    fprintf(stderr, "login_url is mandatory, exiting\n");
    config_destroy(&cfg);
    return 0;
  } else {
    config->login_url = strdup(str_value);
    if (config->login_url == NULL) {
      fprintf(stderr, "Error allocating resources for config->login_url, exiting\n");
      config_destroy(&cfg);
      return 0;
    }
  }
  
  // Get path that serve static files
  if (config_lookup_string(&cfg, "static_files_path", &str_value) == CONFIG_TRUE) {
    config->static_file_config->files_path = o_strdup(str_value);
    if (config->static_file_config->files_path == NULL) {
      fprintf(stderr, "Error allocating config->files_path, exiting\n");
      config_destroy(&cfg);
      return 0;
    }
  }
  
  // Populate mime types u_map
  mime_type_list = config_lookup(&cfg, "static_files_mime_types");
  if (mime_type_list != NULL) {
    int len = config_setting_length(mime_type_list);
    for (i=0; i<len; i++) {
      mime_type = config_setting_get_elem(mime_type_list, i);
      if (mime_type != NULL) {
        if (config_setting_lookup_string(mime_type, "extension", &str_value) == CONFIG_TRUE && 
            config_setting_lookup_string(mime_type, "mime_type", &str_value_2) == CONFIG_TRUE) {
          u_map_put(config->static_file_config->mime_types, str_value, str_value_2);
        }
      }
    }
  }
  
  if (config_lookup_bool(&cfg, "use_secure_connection", &int_value) == CONFIG_TRUE) {
    if (config_lookup_string(&cfg, "secure_connection_key_file", &str_value) == CONFIG_TRUE && 
        config_lookup_string(&cfg, "secure_connection_pem_file", &str_value_2) == CONFIG_TRUE) {
      config->use_secure_connection = int_value;
      config->secure_connection_key_file = o_strdup(str_value);
      config->secure_connection_pem_file = o_strdup(str_value_2);
    } else {
      fprintf(stderr, "Error secure connection is active but certificate is not valid, exiting\n");
      config_destroy(&cfg);
      return 0;
    }
  }
  
  // Get token hash algorithm
  if (config_lookup_string(&cfg, "hash_algorithm", &str_value) == CONFIG_TRUE) {
    o_free(config->hash_algorithm);
    config->hash_algorithm = o_strdup(str_value);
    if (config->hash_algorithm == NULL) {
      fprintf(stderr, "Error allocating config->hash_algorithm, exiting\n");
      config_destroy(&cfg);
      return 0;
    } else if (config->hash_algorithm == NULL || 
              (strcmp("SHA1", config->hash_algorithm) &&
              strcmp("SHA256", config->hash_algorithm) &&
              strcmp("SHA512", config->hash_algorithm) &&
              strcmp("MD5", config->hash_algorithm))) {
      config_destroy(&cfg);
      fprintf(stderr, "Error token hash algorithm: %s\n", config->hash_algorithm);
      return 0;
    }
  }
  
  root = config_root_setting(&cfg);
  database = config_setting_get_member(root, "database");
  if (database != NULL) {
    if (config_setting_lookup_string(database, "type", &str_value) == CONFIG_TRUE) {
      if (0) {
        // I know, this is for the code below to work
#ifdef _HOEL_SQLITE
      } else if (0 == strncmp(str_value, "sqlite3", strlen("sqlite3"))) {
        if (config_setting_lookup_string(database, "path", &str_value_2) == CONFIG_TRUE) {
          config->conn = h_connect_sqlite(str_value_2);
          if (config->conn == NULL) {
            fprintf(stderr, "Error opening sqlite database %s\n", str_value_2);
            config_destroy(&cfg);
            return 0;
          } else {
            if (h_exec_query_sqlite(config->conn, "PRAGMA foreign_keys = ON;") != H_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "Error executing sqlite3 query 'PRAGMA foreign_keys = ON;'");
              config_destroy(&cfg);
              return 0;
            }
          }
        } else {
          config_destroy(&cfg);
          fprintf(stderr, "Error, no sqlite database specified\n");
          return 0;
        }
#endif
#ifdef _HOEL_MARIADB
      } else if (0 == strncmp(str_value, "mariadb", strlen("mariadb"))) {
        config_setting_lookup_string(database, "host", &str_value_2);
        config_setting_lookup_string(database, "user", &str_value_3);
        config_setting_lookup_string(database, "password", &str_value_4);
        config_setting_lookup_string(database, "dbname", &str_value_5);
        config_setting_lookup_int(database, "port", &int_value);
        config->conn = h_connect_mariadb(str_value_2, str_value_3, str_value_4, str_value_5, int_value, NULL);
        if (config->conn == NULL) {
          fprintf(stderr, "Error opening mariadb database %s\n", str_value_5);
          config_destroy(&cfg);
          return 0;
        }
#endif
      } else {
        config_destroy(&cfg);
        fprintf(stderr, "Error, database type unknown\n");
        return 0;
      }
    } else {
      config_destroy(&cfg);
      fprintf(stderr, "Error, no database type found\n");
      return 0;
    }
  } else {
    config_destroy(&cfg);
    fprintf(stderr, "Error, no database setting found\n");
    return 0;
  }

  if (config_lookup_string(&cfg, "admin_scope", &str_value) == CONFIG_TRUE) {
    config->admin_scope = strdup(str_value);
  }
  
  if (config_lookup_string(&cfg, "profile_scope", &str_value) == CONFIG_TRUE) {
    config->profile_scope = strdup(str_value);
  }
  
  if (config_lookup_string(&cfg, "user_module_path", &str_value) == CONFIG_TRUE) {
    config->user_module_path = strdup(str_value);
  } else {
    config_destroy(&cfg);
    fprintf(stderr, "Error, user_module_path is mandatory\n");
    return 0;
  }
  
  if (config_lookup_string(&cfg, "client_module_path", &str_value) == CONFIG_TRUE) {
    config->client_module_path = strdup(str_value);
  } else {
    config_destroy(&cfg);
    fprintf(stderr, "Error, client_module_path is mandatory\n");
    return 0;
  }
  
  if (config_lookup_string(&cfg, "user_auth_scheme_module_path", &str_value) == CONFIG_TRUE) {
    config->user_auth_scheme_module_path = strdup(str_value);
  } else {
    config_destroy(&cfg);
    fprintf(stderr, "Error, user_auth_scheme_module_path is mandatory\n");
    return 0;
  }
  
  if (config_lookup_string(&cfg, "plugin_module_path", &str_value) == CONFIG_TRUE) {
    config->plugin_module_path = strdup(str_value);
  } else {
    config_destroy(&cfg);
    fprintf(stderr, "Error, plugin_module_path is mandatory\n");
    return 0;
  }
  
  config_destroy(&cfg);
  return 1;
}

/**
 * Check if all mandatory configuration parameters are present and correct
 * Initialize some parameters with default value if not set
 */
int check_config(struct config_elements * config) {

  if (config->instance->port == -1) {
    config->instance->port = GLEWLWYD_DEFAULT_PORT;
  }
  
  if (config->api_prefix == NULL) {
    config->api_prefix = o_strdup(GLEWLWYD_DEFAULT_PREFIX);
    if (config->api_prefix == NULL) {
      fprintf(stderr, "Error allocating api_prefix, exit\n");
      return 0;
    }
  }
  
  if (config->log_mode == Y_LOG_MODE_NONE) {
    config->log_mode = Y_LOG_MODE_CONSOLE;
  }
  
  if (config->log_level == Y_LOG_LEVEL_NONE) {
    config->log_level = Y_LOG_LEVEL_ERROR;
  }
  
  if (config->log_mode == Y_LOG_MODE_FILE && config->log_file == NULL) {
    fprintf(stderr, "Error, you must specify a log file if log mode is set to file\n");
    print_help(stderr);
    return 0;
  }
  
  return 1;
}

int module_instance_parameters_check(const char * module_parameters, const char * instance_parameters) {
  json_t * j_parameters = json_loads(module_parameters, JSON_DECODE_ANY, NULL), * j_instance_parameters = json_loads(instance_parameters, JSON_DECODE_ANY, NULL), * j_parameter, * j_value;
  int ret = G_OK;
  const char * key;
  
  json_object_foreach(j_parameters, key, j_parameter) {
    if (json_object_get(j_parameter, "mandatory") == json_true() && json_object_get(j_instance_parameters, key) == NULL) {
      ret = G_ERROR_PARAM;
      break;
    } else if ((j_value = json_object_get(j_instance_parameters, key)) != NULL) {
      if ((0 == o_strcmp("string", json_string_value(json_object_get(j_parameter, "type"))) || 0 == o_strcmp("list", json_string_value(json_object_get(j_parameter, "type")))) && !json_is_string(j_value)) {
        ret = G_ERROR_PARAM;
        break;
      } else if (0 == o_strcmp("number", json_string_value(json_object_get(j_parameter, "type"))) && !json_is_number(j_value)) {
        ret = G_ERROR_PARAM;
        break;
      } else if (0 == o_strcmp("boolean", json_string_value(json_object_get(j_parameter, "type"))) && !json_is_boolean(j_value)) {
        ret = G_ERROR_PARAM;
        break;
      }
    }
  }
  json_decref(j_parameters);
  json_decref(j_instance_parameters);
  
  return ret;
}

static int parameter_check(json_t * j_parameter) {
  int ret = G_OK;
  json_t * j_element;
  size_t index;
  
  if (j_parameter != NULL && json_is_object(j_parameter)) {
    if (json_object_get(j_parameter, "type") != NULL && json_is_string(json_object_get(j_parameter, "type")) && 
        (0 == o_strcmp("string", json_string_value(json_object_get(j_parameter, "type"))) ||
        0 == o_strcmp("number", json_string_value(json_object_get(j_parameter, "type"))) ||
        0 == o_strcmp("boolean", json_string_value(json_object_get(j_parameter, "type"))) ||
        0 == o_strcmp("list", json_string_value(json_object_get(j_parameter, "type"))))) {
      if (0 == o_strcmp("list", json_string_value(json_object_get(j_parameter, "type"))) && 
          json_object_get(j_parameter, "values") != NULL && 
          json_is_array(json_object_get(j_parameter, "values")) &&
          json_array_size(json_object_get(j_parameter, "values")) > 0) {
        json_array_foreach(json_object_get(j_parameter, "values"), index, j_element) {
          if (!json_is_string(j_element)) {
            ret = G_ERROR_PARAM;
          }
        }
      }
      if (ret == G_OK && json_object_get(j_parameter, "mandatory") != NULL && !json_is_boolean(json_object_get(j_parameter, "mandatory"))) {
        ret = G_ERROR_PARAM;
      }
    } else {
      ret = G_ERROR_PARAM;
    }
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int module_parameters_check(const char * module_parameters) {
  json_t * j_parameters = json_loads(module_parameters, JSON_DECODE_ANY, NULL), * j_parameter;
  int ret = G_OK;
  const char * key;
  
  if (j_parameters != NULL) {
    if (json_is_object(j_parameters)) {
      json_object_foreach(j_parameters, key, j_parameter) {
        if ((ret = parameter_check(j_parameter)) != G_OK) {
          char * tmp = json_dumps(j_parameter, JSON_ENCODE_ANY);
          y_log_message(Y_LOG_LEVEL_ERROR, "Error, parameter '%s:%s' is not valid", key, tmp);
          o_free(tmp);
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error, parameters '%s' is not a JSON object", module_parameters);
      ret = G_ERROR_PARAM;
    }
    json_decref(j_parameters);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error, parameters '%s' is not a valid JSON structure", module_parameters);
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int init_user_module_list(struct config_elements * config) {
  int ret = G_OK;
  struct _user_module * cur_user_module = NULL;
  DIR * modules_directory;
  struct dirent * in_file;
  char * file_path;
  void * file_handle;
  
  config->user_module_list = o_malloc(sizeof(struct _pointer_list));
  if (config->user_module_list != NULL) {
    pointer_list_init(config->user_module_list);
    // read module_path and load modules
    if (NULL == (modules_directory = opendir(config->user_module_path))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "init_user_module_list - Error reading libraries folder %s", config->user_module_path);
      ret = G_ERROR;
    } else {
      while ((in_file = readdir(modules_directory))) {
        if (in_file->d_type == DT_REG) {
          file_path = msprintf("%s/%s", config->user_module_path, in_file->d_name);
          
          if (file_path == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "init_user_module_list - Error allocating resources for file_path");
            ret = G_ERROR_MEMORY;
          } else {
            file_handle = dlopen(file_path, RTLD_LAZY);
            
            if (file_handle != NULL) {
              cur_user_module = o_malloc(sizeof(struct _user_module));
              if (cur_user_module != NULL) {
                cur_user_module->name = NULL;
                cur_user_module->parameters = NULL;
                cur_user_module->file_handle = file_handle;
                *(void **) (&cur_user_module->user_module_load) = dlsym(file_handle, "user_module_load");
                *(void **) (&cur_user_module->user_module_unload) = dlsym(file_handle, "user_module_unload");
                *(void **) (&cur_user_module->user_module_init) = dlsym(file_handle, "user_module_init");
                *(void **) (&cur_user_module->user_module_close) = dlsym(file_handle, "user_module_close");
                *(void **) (&cur_user_module->user_module_get_list) = dlsym(file_handle, "user_module_get_list");
                *(void **) (&cur_user_module->user_module_get) = dlsym(file_handle, "user_module_get");
                *(void **) (&cur_user_module->user_module_add) = dlsym(file_handle, "user_module_add");
                *(void **) (&cur_user_module->user_module_update) = dlsym(file_handle, "user_module_update");
                *(void **) (&cur_user_module->user_module_update_profile) = dlsym(file_handle, "user_module_update_profile");
                *(void **) (&cur_user_module->user_module_delete) = dlsym(file_handle, "user_module_delete");
                *(void **) (&cur_user_module->user_module_check_password) = dlsym(file_handle, "user_module_check_password");
                *(void **) (&cur_user_module->user_module_update_password) = dlsym(file_handle, "user_module_update_password");
                
                if (cur_user_module->user_module_load != NULL &&
                    cur_user_module->user_module_unload != NULL &&
                    cur_user_module->user_module_init != NULL &&
                    cur_user_module->user_module_close != NULL &&
                    cur_user_module->user_module_get_list != NULL &&
                    cur_user_module->user_module_get != NULL &&
                    cur_user_module->user_module_add != NULL &&
                    cur_user_module->user_module_update != NULL &&
                    cur_user_module->user_module_update_profile != NULL &&
                    cur_user_module->user_module_delete != NULL &&
                    cur_user_module->user_module_check_password != NULL &&
                    cur_user_module->user_module_update_password != NULL) {
                  if (cur_user_module->user_module_load(config, &cur_user_module->name, &cur_user_module->display_name, &cur_user_module->description, &cur_user_module->parameters) == G_OK) {
                    if (module_parameters_check(cur_user_module->parameters) == G_OK) {
                      if (pointer_list_append(config->user_module_list, (void*)cur_user_module)) {
                        y_log_message(Y_LOG_LEVEL_INFO, "Loading user module %s - %s", file_path, cur_user_module->name);
                      } else {
                        cur_user_module->user_module_unload(config);
                        dlclose(file_handle);
                        o_free(cur_user_module);
                        y_log_message(Y_LOG_LEVEL_ERROR, "init_user_module_list - Error pointer_list_append");
                        ret = G_ERROR;
                      }
                    } else {
                      dlclose(file_handle);
                      y_log_message(Y_LOG_LEVEL_ERROR, "User module %s, parameters are incorrect, abort loading", cur_user_module->name);
                      ret = G_ERROR_PARAM;
                    }
                  } else {
                    dlclose(file_handle);
                    o_free(cur_user_module);
                    y_log_message(Y_LOG_LEVEL_ERROR, "init_user_module_list - Error user_module_init for module %s", file_path);
                    ret = G_ERROR_MEMORY;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "init_user_module_list - Error module %s has not all required functions", file_path);
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_load: %s", (cur_user_module->user_module_load != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_unload: %s", (cur_user_module->user_module_unload != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_init: %s", (cur_user_module->user_module_init != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_close: %s", (cur_user_module->user_module_close != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_get_list: %s", (cur_user_module->user_module_get_list != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_get: %s", (cur_user_module->user_module_get != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_add: %s", (cur_user_module->user_module_add != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_update: %s", (cur_user_module->user_module_update != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_update_profile: %s", (cur_user_module->user_module_update_profile != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_delete: %s", (cur_user_module->user_module_delete != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_check_password: %s", (cur_user_module->user_module_check_password != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_update_password: %s", (cur_user_module->user_module_update_password != NULL?"found":"not found"));
                  dlclose(file_handle);
                  o_free(cur_user_module);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "init_user_module_list - Error allocating resources for cur_user_module");
                dlclose(file_handle);
                ret = G_ERROR_MEMORY;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "init_user_module_list - Error opening module file %s, reason: %s", file_path, dlerror());
            }
          }
          o_free(file_path);
        }
      }
      closedir(modules_directory);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "init_user_module_list - Error allocating resources for config->user_module_list");
    ret = G_ERROR_MEMORY;
  }
  
  return ret;
}

int load_user_module_instance_list(struct config_elements * config) {
  json_t * j_query, * j_result, * j_instance;
  int res, ret, i;
  size_t index;
  struct _user_module_instance * cur_instance;
  struct _user_module * module = NULL;
  
  config->user_module_instance_list = o_malloc(sizeof(struct _pointer_list));
  if (config->user_module_instance_list != NULL) {
    pointer_list_init(config->user_module_instance_list);
    j_query = json_pack("{sss[ssss]ss}",
                        "table",
                        GLEWLWYD_TABLE_USER_MODULE_INSTANCE,
                        "columns",
                          "gumi_module AS module",
                          "gumi_name AS name",
                          "gumi_order AS order_by",
                          "gumi_parameters AS parameters",
                        "order_by",
                        "gumi_order");
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      json_array_foreach(j_result, index, j_instance) {
        module = NULL;
        for (i=0; i<pointer_list_size(config->user_module_list); i++) {
          module = (struct _user_module *)pointer_list_get_at(config->user_module_list, i);
          if (0 == o_strcmp(module->name, json_string_value(json_object_get(j_instance, "module")))) {
            break;
          } else {
            module = NULL;
          }
        }
        if (module != NULL) {
          cur_instance = o_malloc(sizeof(struct _user_module_instance));
          if (cur_instance != NULL) {
            cur_instance->cls = NULL;
            cur_instance->name = o_strdup(json_string_value(json_object_get(j_instance, "name")));
            cur_instance->module = module;
            if (pointer_list_append(config->user_module_instance_list, cur_instance)) {
              if (module->user_module_init(config, json_string_value(json_object_get(j_instance, "parameters")), &cur_instance->cls) == G_OK) {
                cur_instance->enabled = 1;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error init module %s/%s", module->name, json_string_value(json_object_get(j_instance, "name")));
                cur_instance->enabled = 0;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error reallocating resources for user_module_instance_list");
              o_free(cur_instance->name);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error allocating resources for cur_instance");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error module  %s not found", json_string_value(json_object_get(j_instance, "module")));
        }
      }
      json_decref(j_result);
      ret = G_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error executing j_query");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error allocating resource for config->user_module_instance_list");
    ret = G_ERROR_MEMORY;
  }
  return ret;
}

struct _user_module_instance * get_user_module_instance(struct config_elements * config, const char * name) {
  int i;
  struct _user_module_instance * cur_instance;

  for (i=0; i<pointer_list_size(config->user_module_instance_list); i++) {
    cur_instance = (struct _user_module_instance *)pointer_list_get_at(config->user_module_instance_list, i);
    if (cur_instance != NULL && 0 == o_strcmp(cur_instance->name, name)) {
      return cur_instance;
    }
  }
  return NULL;
}

int init_user_auth_scheme_module_list(struct config_elements * config) {
  int ret = G_OK;
  struct _user_auth_scheme_module * cur_user_auth_scheme_module = NULL;
  DIR * modules_directory;
  struct dirent * in_file;
  char * file_path;
  void * file_handle;
  
  config->user_auth_scheme_module_list = o_malloc(sizeof(struct _pointer_list));
  if (config->user_auth_scheme_module_list != NULL) {
    pointer_list_init(config->user_auth_scheme_module_list);
    // read module_path and load modules
    if (NULL == (modules_directory = opendir(config->user_auth_scheme_module_path))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "init_user_auth_scheme_module_list - Error reading libraries folder %s", config->user_auth_scheme_module_path);
      ret = G_ERROR;
    } else {
      while ((in_file = readdir(modules_directory))) {
        if (in_file->d_type == DT_REG) {
          file_path = msprintf("%s/%s", config->user_auth_scheme_module_path, in_file->d_name);
          
          if (file_path == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "init_user_auth_scheme_module_list - Error allocating resources for file_path");
            ret = G_ERROR_MEMORY;
          } else {
            file_handle = dlopen(file_path, RTLD_LAZY);
            
            if (file_handle != NULL) {
              cur_user_auth_scheme_module = o_malloc(sizeof(struct _user_auth_scheme_module));
              if (cur_user_auth_scheme_module != NULL) {
                cur_user_auth_scheme_module->name = NULL;
                cur_user_auth_scheme_module->file_handle = file_handle;
                *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_load) = dlsym(file_handle, "user_auth_scheme_module_load");
                *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_unload) = dlsym(file_handle, "user_auth_scheme_module_unload");
                *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_init) = dlsym(file_handle, "user_auth_scheme_module_init");
                *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_close) = dlsym(file_handle, "user_auth_scheme_module_close");
                *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_validate) = dlsym(file_handle, "user_auth_scheme_module_validate");
                *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_trigger) = dlsym(file_handle, "user_auth_scheme_module_trigger");
                *(void **) (&cur_user_auth_scheme_module->user_can_use_scheme) = dlsym(file_handle, "user_can_use_scheme");
                
                if (cur_user_auth_scheme_module->user_auth_scheme_module_load != NULL &&
                    cur_user_auth_scheme_module->user_auth_scheme_module_unload != NULL &&
                    cur_user_auth_scheme_module->user_auth_scheme_module_init != NULL &&
                    cur_user_auth_scheme_module->user_auth_scheme_module_close != NULL &&
                    cur_user_auth_scheme_module->user_auth_scheme_module_validate != NULL &&
                    cur_user_auth_scheme_module->user_auth_scheme_module_trigger != NULL &&
                    cur_user_auth_scheme_module->user_can_use_scheme != NULL) {
                  if (cur_user_auth_scheme_module->user_auth_scheme_module_load(config, &cur_user_auth_scheme_module->name, &cur_user_auth_scheme_module->display_name, &cur_user_auth_scheme_module->description, &cur_user_auth_scheme_module->parameters) == G_OK) {
                    if (pointer_list_append(config->user_auth_scheme_module_list, cur_user_auth_scheme_module)) {
                      y_log_message(Y_LOG_LEVEL_INFO, "Loading user auth scheme module %s - %s", file_path, cur_user_auth_scheme_module->name);
                    } else {
                      cur_user_auth_scheme_module->user_auth_scheme_module_unload(config);
                      dlclose(file_handle);
                      o_free(cur_user_auth_scheme_module);
                      y_log_message(Y_LOG_LEVEL_ERROR, "init_user_auth_scheme_module_list - Error reallocating resources for user_auth_scheme_module_list");
                      ret = G_ERROR_MEMORY;
                    }
                  } else {
                    dlclose(file_handle);
                    o_free(cur_user_auth_scheme_module);
                    y_log_message(Y_LOG_LEVEL_ERROR, "init_user_auth_scheme_module_list - Error user_auth_scheme_module_load for module %s", file_path);
                    ret = G_ERROR_MEMORY;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "init_user_auth_scheme_module_list - Error module %s has not all required functions", file_path);
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_load: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_load != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_unload: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_unload != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_init: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_init != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_close: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_close != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_validate: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_validate != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_trigger: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_trigger != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - user_can_use_scheme: %s", (cur_user_auth_scheme_module->user_can_use_scheme != NULL?"found":"not found"));
                  dlclose(file_handle);
                  o_free(cur_user_auth_scheme_module);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "init_user_auth_scheme_module_list - Error allocating resources for cur_user_auth_scheme_module");
                dlclose(file_handle);
                ret = G_ERROR_MEMORY;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "init_user_auth_scheme_module_list - Error opening module file %s, reason: %s", file_path, dlerror());
            }
          }
          o_free(file_path);
        }
      }
      closedir(modules_directory);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "init_user_auth_scheme_module_list - Error allocating resources for config->user_auth_scheme_module_list");
    ret = G_ERROR_MEMORY;
  }
  
  return ret;
}

int load_user_auth_scheme_module_instance_list(struct config_elements * config) {
  json_t * j_query, * j_result, * j_instance;
  int res, ret, i;
  size_t index;
  struct _user_auth_scheme_module_instance * cur_instance;
  struct _user_auth_scheme_module * module = NULL;
  
  config->user_auth_scheme_module_instance_list = o_malloc(sizeof(struct _pointer_list));
  if (config->user_auth_scheme_module_instance_list != NULL) {
    pointer_list_init(config->user_auth_scheme_module_instance_list);
    j_query = json_pack("{sss[sssss]}",
                        "table",
                        GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE,
                        "columns",
                          "guasmi_id",
                          "guasmi_module AS module",
                          "guasmi_name AS name",
                          "guasmi_expiration",
                          "guasmi_parameters AS parameters");
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      json_array_foreach(j_result, index, j_instance) {
        module = NULL;
        for (i=0; i<pointer_list_size(config->user_auth_scheme_module_list); i++) {
          module = (struct _user_auth_scheme_module *)pointer_list_get_at(config->user_auth_scheme_module_list, i);
          if (0 == o_strcmp(module->name, json_string_value(json_object_get(j_instance, "module")))) {
            break;
          } else {
            module = NULL;
          }
        }
        if (module != NULL) {
          cur_instance = o_malloc(sizeof(struct _user_auth_scheme_module_instance));
          if (cur_instance != NULL) {
            cur_instance->cls = NULL;
            cur_instance->name = o_strdup(json_string_value(json_object_get(j_instance, "name")));
            cur_instance->module = module;
            cur_instance->guasmi_id = json_integer_value(json_object_get(j_instance, "guasmi_id"));
            cur_instance->guasmi_expiration = json_integer_value(json_object_get(j_instance, "guasmi_expiration"));
            if (pointer_list_append(config->user_auth_scheme_module_instance_list, cur_instance)) {
              if (module->user_auth_scheme_module_init(config, json_string_value(json_object_get(j_instance, "parameters")), &cur_instance->cls) == G_OK) {
                cur_instance->enabled = 1;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error init module %s/%s", module->name, json_string_value(json_object_get(j_instance, "name")));
                cur_instance->enabled = 0;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error reallocating resources for user_auth_scheme_module_instance_list");
              o_free(cur_instance->name);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error allocating resources for cur_instance");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error module  %s not found", json_string_value(json_object_get(j_instance, "module")));
        }
      }
      json_decref(j_result);
      ret = G_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error executing j_query");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error allocating resources for config->user_auth_scheme_module_instance_list");
    ret = G_ERROR_MEMORY;
  }
  return ret;
}

struct _user_auth_scheme_module_instance * get_user_auth_scheme_module_instance(struct config_elements * config, const char * name) {
  int i;
  struct _user_auth_scheme_module_instance * cur_instance;

  for (i=0; i<pointer_list_size(config->user_auth_scheme_module_instance_list); i++) {
    cur_instance = pointer_list_get_at(config->user_auth_scheme_module_instance_list, i);
    if (0 == o_strcmp(cur_instance->name, name)) {
      return cur_instance;
    }
  }
  return NULL;
}

int init_client_module_list(struct config_elements * config) {
  int ret = G_OK;
  struct _client_module * cur_client_module = NULL;
  DIR * modules_directory;
  struct dirent * in_file;
  char * file_path;
  void * file_handle;
  
  config->client_module_list = o_malloc(sizeof(struct _pointer_list));
  if (config->client_module_list != NULL) {
    pointer_list_init(config->client_module_list);
    // read module_path and load modules
    if (NULL == (modules_directory = opendir(config->client_module_path))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "init_client_module_list - Error reading libraries folder %s", config->client_module_path);
      ret = G_ERROR;
    } else {
      while ((in_file = readdir(modules_directory))) {
        if (in_file->d_type == DT_REG) {
          file_path = msprintf("%s/%s", config->client_module_path, in_file->d_name);
          
          if (file_path == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "init_client_module_list - Error allocating resources for file_path");
            ret = G_ERROR_MEMORY;
          } else {
            file_handle = dlopen(file_path, RTLD_LAZY);
            
            if (file_handle != NULL) {
              cur_client_module = o_malloc(sizeof(struct _client_module));
              if (cur_client_module != NULL) {
                cur_client_module->name = NULL;
                cur_client_module->file_handle = file_handle;
                *(void **) (&cur_client_module->client_module_load) = dlsym(file_handle, "client_module_load");
                *(void **) (&cur_client_module->client_module_unload) = dlsym(file_handle, "client_module_unload");
                *(void **) (&cur_client_module->client_module_init) = dlsym(file_handle, "client_module_init");
                *(void **) (&cur_client_module->client_module_close) = dlsym(file_handle, "client_module_close");
                *(void **) (&cur_client_module->client_module_get_list) = dlsym(file_handle, "client_module_get_list");
                *(void **) (&cur_client_module->client_module_get) = dlsym(file_handle, "client_module_get");
                *(void **) (&cur_client_module->client_module_add) = dlsym(file_handle, "client_module_add");
                *(void **) (&cur_client_module->client_module_update) = dlsym(file_handle, "client_module_update");
                *(void **) (&cur_client_module->client_module_delete) = dlsym(file_handle, "client_module_delete");
                *(void **) (&cur_client_module->client_module_check_password) = dlsym(file_handle, "client_module_check_password");
                *(void **) (&cur_client_module->client_module_update_password) = dlsym(file_handle, "client_module_update_password");
                
                if (cur_client_module->client_module_load != NULL &&
                    cur_client_module->client_module_unload != NULL &&
                    cur_client_module->client_module_init != NULL &&
                    cur_client_module->client_module_close != NULL &&
                    cur_client_module->client_module_get_list != NULL &&
                    cur_client_module->client_module_get != NULL &&
                    cur_client_module->client_module_add != NULL &&
                    cur_client_module->client_module_update != NULL &&
                    cur_client_module->client_module_delete != NULL &&
                    cur_client_module->client_module_check_password != NULL &&
                    cur_client_module->client_module_update_password != NULL) {
                  if (cur_client_module->client_module_load(config, &cur_client_module->name, &cur_client_module->display_name, &cur_client_module->description, &cur_client_module->parameters) == G_OK) {
                    if (pointer_list_append(config->client_module_list, cur_client_module)) {
                      y_log_message(Y_LOG_LEVEL_INFO, "Loading client module %s - %s", file_path, cur_client_module->name);
                    } else {
                      cur_client_module->client_module_unload(config);
                      dlclose(file_handle);
                      o_free(cur_client_module);
                      y_log_message(Y_LOG_LEVEL_ERROR, "init_client_module_list - Error reallocating resources for client_module_list");
                      ret = G_ERROR_MEMORY;
                    }
                  } else {
                    dlclose(file_handle);
                    o_free(cur_client_module);
                    y_log_message(Y_LOG_LEVEL_ERROR, "init_client_module_list - Error client_module_init for module %s", file_path);
                    ret = G_ERROR_MEMORY;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "init_client_module_list - Error module %s has not all required functions", file_path);
                  y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_load: %s", (cur_client_module->client_module_load != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_unload: %s", (cur_client_module->client_module_unload != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_init: %s", (cur_client_module->client_module_init != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_close: %s", (cur_client_module->client_module_close != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_get_list: %s", (cur_client_module->client_module_get_list != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_get: %s", (cur_client_module->client_module_get != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_add: %s", (cur_client_module->client_module_add != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_update: %s", (cur_client_module->client_module_update != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_delete: %s", (cur_client_module->client_module_delete != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_check_password: %s", (cur_client_module->client_module_check_password != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_update_password: %s", (cur_client_module->client_module_update_password != NULL?"found":"not found"));
                  dlclose(file_handle);
                  o_free(cur_client_module);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "init_client_module_list - Error allocating resources for cur_client_module");
                dlclose(file_handle);
                ret = G_ERROR_MEMORY;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "init_client_module_list - Error opening module file %s, reason: %s", file_path, dlerror());
            }
          }
          o_free(file_path);
        }
      }
      closedir(modules_directory);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "init_client_module_list - Error allocating resources for config->client_module_list");
    ret = G_ERROR_MEMORY;
  }
  
  return ret;
}

int load_client_module_instance_list(struct config_elements * config) {
  json_t * j_query, * j_result, * j_instance;
  int res, ret, i;
  size_t index;
  struct _client_module_instance * cur_instance;
  struct _client_module * module = NULL;
  
  config->client_module_instance_list = o_malloc(sizeof(struct _pointer_list));
  if (config->client_module_instance_list != NULL) {
    pointer_list_init(config->client_module_instance_list);
    j_query = json_pack("{sss[ssss]ss}",
                        "table",
                        GLEWLWYD_TABLE_CLIENT_MODULE_INSTANCE,
                        "columns",
                          "gcmi_module AS module",
                          "gcmi_name AS name",
                          "gcmi_order AS order_by",
                          "gcmi_parameters AS parameters",
                        "order_by",
                        "gcmi_order");
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      json_array_foreach(j_result, index, j_instance) {
        module = NULL;
        for (i=0; i<pointer_list_size(config->client_module_list); i++) {
          module = pointer_list_get_at(config->client_module_list, i);
          if (0 == o_strcmp(module->name, json_string_value(json_object_get(j_instance, "module")))) {
            break;
          } else {
            module = NULL;
          }
        }
        if (module != NULL) {
          cur_instance = o_malloc(sizeof(struct _client_module_instance));
          if (cur_instance != NULL) {
            cur_instance->cls = NULL;
            cur_instance->name = o_strdup(json_string_value(json_object_get(j_instance, "name")));
            cur_instance->module = module;
            if (pointer_list_append(config->client_module_instance_list, cur_instance)) {
              if (module->client_module_init(config, json_string_value(json_object_get(j_instance, "parameters")), &cur_instance->cls) == G_OK) {
                cur_instance->enabled = 1;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_instance_list - Error init module %s/%s", module->name, json_string_value(json_object_get(j_instance, "name")));
                cur_instance->enabled = 0;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_instance_list - Error reallocating resources for client_module_instance_list");
              o_free(cur_instance->name);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_instance_list - Error allocating resources for cur_instance");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_instance_list - Error module  %s not found", json_string_value(json_object_get(j_instance, "module")));
        }
      }
      json_decref(j_result);
      ret = G_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_instance_list - Error executing j_query");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_instance_list - Error allocating resources for config->client_module_instance_list");
    ret = G_ERROR;
  }
  return ret;
}

struct _client_module_instance * get_client_module_instance(struct config_elements * config, const char * name) {
  int i;
  struct _client_module_instance * cur_instance;

  for (i=0; i<pointer_list_size(config->client_module_instance_list); i++) {
    cur_instance = pointer_list_get_at(config->client_module_instance_list, i);
    if (0 == o_strcmp(cur_instance->name, name)) {
      return cur_instance;
    }
  }
  return NULL;
}

int init_plugin_module_list(struct config_elements * config) {
  int ret = G_OK;
  struct _plugin_module * cur_plugin_module = NULL;
  DIR * modules_directory;
  struct dirent * in_file;
  char * file_path;
  void * file_handle;
  
  config->plugin_module_list = o_malloc(sizeof(struct _pointer_list));
  if (config->plugin_module_list != NULL) {
    pointer_list_init(config->plugin_module_list);
    // read module_path and load modules
    if (NULL == (modules_directory = opendir(config->plugin_module_path))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "init_plugin_module_list - Error reading libraries folder %s", config->plugin_module_path);
      ret = G_ERROR;
    } else {
      while ((in_file = readdir(modules_directory))) {
        if (in_file->d_type == DT_REG) {
          file_path = msprintf("%s/%s", config->plugin_module_path, in_file->d_name);
          
          if (file_path == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "init_plugin_module_list - Error allocating resources for file_path");
            ret = G_ERROR_MEMORY;
          } else {
            file_handle = dlopen(file_path, RTLD_LAZY);
            
            if (file_handle != NULL) {
              cur_plugin_module = o_malloc(sizeof(struct _client_module));
              if (cur_plugin_module != NULL) {
                cur_plugin_module->name = NULL;
                cur_plugin_module->file_handle = file_handle;
                *(void **) (&cur_plugin_module->plugin_module_load) = dlsym(file_handle, "plugin_module_load");
                *(void **) (&cur_plugin_module->plugin_module_unload) = dlsym(file_handle, "plugin_module_unload");
                *(void **) (&cur_plugin_module->plugin_module_init) = dlsym(file_handle, "plugin_module_init");
                *(void **) (&cur_plugin_module->plugin_module_close) = dlsym(file_handle, "plugin_module_close");
                
                if (cur_plugin_module->plugin_module_load != NULL &&
                    cur_plugin_module->plugin_module_unload != NULL &&
                    cur_plugin_module->plugin_module_init != NULL &&
                    cur_plugin_module->plugin_module_close != NULL) {
                  if (cur_plugin_module->plugin_module_load(config->config_p, &cur_plugin_module->name, &cur_plugin_module->display_name, &cur_plugin_module->description, &cur_plugin_module->parameters) == G_OK) {
                    if (pointer_list_append(config->plugin_module_list, cur_plugin_module)) {
                      y_log_message(Y_LOG_LEVEL_INFO, "Loading client module %s - %s", file_path, cur_plugin_module->name);
                    } else {
                      cur_plugin_module->plugin_module_unload(config->config_p);
                      dlclose(file_handle);
                      o_free(cur_plugin_module);
                      y_log_message(Y_LOG_LEVEL_ERROR, "init_plugin_module_list - Error reallocating resources for client_module_list");
                      ret = G_ERROR_MEMORY;
                    }
                  } else {
                    dlclose(file_handle);
                    o_free(cur_plugin_module);
                    y_log_message(Y_LOG_LEVEL_ERROR, "init_plugin_module_list - Error client_module_init for module %s", file_path);
                    ret = G_ERROR_MEMORY;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "init_plugin_module_list - Error module %s has not all required functions", file_path);
                  y_log_message(Y_LOG_LEVEL_ERROR, " - plugin_module_load: %s", (cur_plugin_module->plugin_module_load != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - plugin_module_unload: %s", (cur_plugin_module->plugin_module_unload != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - plugin_module_init: %s", (cur_plugin_module->plugin_module_init != NULL?"found":"not found"));
                  y_log_message(Y_LOG_LEVEL_ERROR, " - plugin_module_close: %s", (cur_plugin_module->plugin_module_close != NULL?"found":"not found"));
                  dlclose(file_handle);
                  o_free(cur_plugin_module);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "init_plugin_module_list - Error allocating resources for cur_client_module");
                dlclose(file_handle);
                ret = G_ERROR_MEMORY;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "init_plugin_module_list - Error opening module file %s, reason: %s", file_path, dlerror());
            }
          }
          o_free(file_path);
        }
      }
      closedir(modules_directory);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "init_plugin_module_list - Error allocating resources for config->client_module_list");
    ret = G_ERROR_MEMORY;
  }
  
  return ret;
}

int load_plugin_module_instance_list(struct config_elements * config) {
  json_t * j_query, * j_result, * j_instance;
  int res, ret, i;
  size_t index;
  struct _plugin_module_instance * cur_instance;
  struct _plugin_module * module = NULL;
  
  config->plugin_module_instance_list = o_malloc(sizeof(struct _pointer_list));
  if (config->plugin_module_instance_list != NULL) {
    pointer_list_init(config->plugin_module_instance_list);
    j_query = json_pack("{sss[sss]}",
                        "table",
                        GLEWLWYD_TABLE_PLUGIN_MODULE_INSTANCE,
                        "columns",
                          "gpmi_module AS module",
                          "gpmi_name AS name",
                          "gpmi_parameters AS parameters");
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      json_array_foreach(j_result, index, j_instance) {
        module = NULL;
        for (i=0; i<pointer_list_size(config->plugin_module_list); i++) {
          module = pointer_list_get_at(config->plugin_module_list, i);
          if (0 == o_strcmp(module->name, json_string_value(json_object_get(j_instance, "module")))) {
            break;
          } else {
            module = NULL;
          }
        }
        if (module != NULL) {
          cur_instance = o_malloc(sizeof(struct _plugin_module_instance));
          if (cur_instance != NULL) {
            cur_instance->cls = NULL;
            cur_instance->name = o_strdup(json_string_value(json_object_get(j_instance, "name")));
            cur_instance->module = module;
            if (pointer_list_append(config->plugin_module_instance_list, cur_instance)) {
              if (module->plugin_module_init(config->config_p, json_string_value(json_object_get(j_instance, "parameters")), &cur_instance->cls) == G_OK) {
                cur_instance->enabled = 1;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error init module %s/%s", module->name, json_string_value(json_object_get(j_instance, "name")));
                cur_instance->enabled = 0;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error reallocating resources for client_module_instance_list");
              o_free(cur_instance->name);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error allocating resources for cur_instance");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error module  %s not found", json_string_value(json_object_get(j_instance, "module")));
        }
      }
      json_decref(j_result);
      ret = G_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error executing j_query");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error allocating resources for config->client_module_instance_list");
    ret = G_ERROR;
  }
  return ret;
}

struct _plugin_module_instance * get_plugin_module_instance(struct config_elements * config, const char * name) {
  int i;
  struct _plugin_module_instance * cur_instance;

  for (i=0; i<pointer_list_size(config->plugin_module_instance_list); i++) {
    cur_instance = (struct _plugin_module_instance *)pointer_list_get_at(config->plugin_module_instance_list, i);
    if (cur_instance != NULL && 0 == o_strcmp(cur_instance->name, name)) {
      return cur_instance;
    }
  }
  return NULL;
}

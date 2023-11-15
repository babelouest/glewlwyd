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
 * Copyright 2016-2021 Nicolas Mora <mail@babelouest.org>
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
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "glewlwyd.h"

static pthread_mutex_t global_handler_close_lock;
static pthread_cond_t  global_handler_close_cond;

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
  struct _http_compression_config http_comression_config;
  int res, use_config_file = 0, use_config_env = 0;
  struct sockaddr_in bind_address, bind_address_metrics;
  pthread_t signal_thread_id;
  pthread_mutexattr_t mutexattr;
  static sigset_t close_signals;
  char * tmp, * tmp2;

  ulfius_global_init();

  if (config == NULL) {
    fprintf(stderr, "Memory error - config\n");
    return 1;
  } else if ((config->config_p = o_malloc(sizeof(struct config_plugin))) == NULL) {
    fprintf(stderr, "Memory error - config_p\n");
    o_free(config);
    return 1;
  } else if ((config->config_m = o_malloc(sizeof(struct config_module))) == NULL) {
    fprintf(stderr, "Memory error - config_m\n");
    o_free(config->config_p);
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
  config->config_p->glewlwyd_callback_trigger_session_used = &glewlwyd_callback_trigger_session_used;
  config->config_p->glewlwyd_callback_get_session_age = &glewlwyd_callback_get_session_age;
  config->config_p->glewlwyd_callback_get_plugin_external_url = &glewlwyd_callback_get_plugin_external_url;
  config->config_p->glewlwyd_callback_get_login_url = &glewlwyd_callback_get_login_url;
  config->config_p->glewlwyd_callback_generate_hash = &glewlwyd_callback_generate_hash;
  config->config_p->glewlwyd_callback_update_issued_for = &glewlwyd_callback_update_issued_for;
  config->config_p->glewlwyd_plugin_callback_get_user_list = &glewlwyd_plugin_callback_get_user_list;
  config->config_p->glewlwyd_plugin_callback_get_user = &glewlwyd_plugin_callback_get_user;
  config->config_p->glewlwyd_plugin_callback_get_user_profile = &glewlwyd_plugin_callback_get_user_profile;
  config->config_p->glewlwyd_plugin_callback_is_user_valid = &glewlwyd_plugin_callback_is_user_valid;
  config->config_p->glewlwyd_plugin_callback_add_user = &glewlwyd_plugin_callback_add_user;
  config->config_p->glewlwyd_plugin_callback_set_user = &glewlwyd_plugin_callback_set_user;
  config->config_p->glewlwyd_plugin_callback_user_update_password = &glewlwyd_plugin_callback_user_update_password;
  config->config_p->glewlwyd_plugin_callback_delete_user = &glewlwyd_plugin_callback_delete_user;
  config->config_p->glewlwyd_plugin_callback_get_client_list = &glewlwyd_plugin_callback_get_client_list;
  config->config_p->glewlwyd_plugin_callback_get_client = &glewlwyd_plugin_callback_get_client;
  config->config_p->glewlwyd_plugin_callback_is_client_valid = &glewlwyd_plugin_callback_is_client_valid;
  config->config_p->glewlwyd_plugin_callback_add_client = &glewlwyd_plugin_callback_add_client;
  config->config_p->glewlwyd_plugin_callback_set_client = &glewlwyd_plugin_callback_set_client;
  config->config_p->glewlwyd_plugin_callback_delete_client = &glewlwyd_plugin_callback_delete_client;
  config->config_p->glewlwyd_plugin_callback_scheme_register = &glewlwyd_plugin_callback_scheme_register;
  config->config_p->glewlwyd_plugin_callback_scheme_register_get = &glewlwyd_plugin_callback_scheme_register_get;
  config->config_p->glewlwyd_plugin_callback_scheme_deregister = &glewlwyd_plugin_callback_scheme_deregister;
  config->config_p->glewlwyd_plugin_callback_scheme_can_use = &glewlwyd_plugin_callback_scheme_can_use;
  config->config_p->glewlwyd_plugin_callback_get_scheme_list = &glewlwyd_plugin_callback_get_scheme_list;
  config->config_p->glewlwyd_plugin_callback_get_scheme_module = &glewlwyd_plugin_callback_get_scheme_module;
  config->config_p->glewlwyd_plugin_callback_metrics_add_metric = &glewlwyd_plugin_callback_metrics_add_metric;
  config->config_p->glewlwyd_plugin_callback_metrics_increment_counter = &glewlwyd_plugin_callback_metrics_increment_counter;

  // Init config structure with default values
  config->config_m->external_url = NULL;
  config->config_m->login_url = NULL;
  config->config_m->admin_scope = NULL;
  config->config_m->profile_scope = NULL;
  config->config_m->conn = NULL;
  config->config_m->glewlwyd_config = config;
  config->config_m->glewlwyd_module_callback_get_user = &glewlwyd_module_callback_get_user;
  config->config_m->glewlwyd_module_callback_set_user = &glewlwyd_module_callback_set_user;
  config->config_m->glewlwyd_module_callback_check_user_password = &glewlwyd_module_callback_check_user_password;
  config->config_m->glewlwyd_module_callback_check_user_session = &glewlwyd_module_callback_check_user_session;
  config->config_m->glewlwyd_module_callback_metrics_add_metric = &glewlwyd_module_callback_metrics_add_metric;
  config->config_m->glewlwyd_module_callback_metrics_increment_counter = &glewlwyd_module_callback_metrics_increment_counter;
  config->config_m->glewlwyd_module_callback_update_issued_for = &glewlwyd_module_callback_update_issued_for;
  config->config_file = NULL;
  config->port = 0;
  config->max_post_size = GLEWLWYD_DEFAULT_MAX_POST_SIZE;
  config->response_body_limit = GLEWLWYD_DEFAULT_RESPONSE_MAX_BODY_SIZE;
  config->max_header = GLEWLWYD_DEFAULT_RESPONSE_MAX_HEADER_COUNT;
  config->bind_address = NULL;
  config->bind_address_metrics = NULL;
  config->instance = NULL;
  config->instance_metrics = NULL;
  config->instance_initialized = 0;
  config->instance_metrics_initialized = 0;
  config->api_prefix = o_strdup(GLEWLWYD_DEFAULT_API_PREFIX);
  config->external_url = NULL;
  config->cookie_domain = NULL;
  config->cookie_secure = 0;
  config->cookie_same_site = U_COOKIE_SAME_SITE_EMPTY;
  config->add_x_frame_option_header_deny = 1;
  config->log_mode_args = 0;
  config->log_level_args = 0;
  config->log_mode = Y_LOG_MODE_NONE;
  config->log_level = Y_LOG_LEVEL_NONE;
  config->log_file = NULL;
  config->allow_origin = o_strdup(GLEWLWYD_DEFAULT_ALLOW_ORIGIN);
  config->allow_methods = o_strdup(GLEWLWYD_DEFAULT_ALLOW_METHODS);
  config->allow_headers = o_strdup(GLEWLWYD_DEFAULT_ALLOW_HEADERS);
  config->expose_headers = o_strdup(GLEWLWYD_DEFAULT_EXPOSE_HEADERS);
  config->originating_ip_header = o_strdup(GLEWLWYD_DEFAULT_ORIGINATING_IP_HEADER);
  config->use_secure_connection = 0;
  config->secure_connection_key_file = NULL;
  config->secure_connection_pem_file = NULL;
  config->secure_connection_ca_file = NULL;
  config->conn = NULL;
  config->session_key = o_strdup(GLEWLWYD_DEFAULT_SESSION_KEY);
  config->session_expiration = GLEWLWYD_DEFAULT_SESSION_EXPIRATION_PASSWORD;
  config->salt_length = GLEWLWYD_DEFAULT_SALT_LENGTH;
  config->hash_algorithm = digest_SHA256;
  config->login_url = o_strdup(GLEWLWYD_DEFAULT_LOGIN_URL);
  config->delete_profile = GLEWLWYD_PROFILE_DELETE_UNAUTHORIZED;
  config->user_module_path = NULL;
  config->user_module_list = NULL;
  config->user_module_instance_list = NULL;
  config->user_middleware_module_path = NULL;
  config->user_middleware_module_list = NULL;
  config->user_middleware_module_instance_list = NULL;
  config->client_module_path = NULL;
  config->client_module_list = NULL;
  config->client_module_instance_list = NULL;
  config->user_auth_scheme_module_path = NULL;
  config->user_auth_scheme_module_list = NULL;
  config->user_auth_scheme_module_instance_list = NULL;
  config->plugin_module_path = NULL;
  config->plugin_module_list = NULL;
  config->plugin_module_instance_list = NULL;
  config->admin_scope = o_strdup(GLEWLWYD_DEFAULT_ADMIN_SCOPE);
  config->profile_scope = o_strdup(GLEWLWYD_DEFAULT_PROFILE_SCOPE);
  config->admin_session_authentication = GLEWLWYD_SESSION_AUTH_COOKIE;
  config->profile_session_authentication = GLEWLWYD_SESSION_AUTH_COOKIE;
  config->login_api_enabled = 1;
  config->user_backend_api_run_enabled = NULL;
  config->user_middleware_backend_api_run_enabled = NULL;
  config->client_backend_api_run_enabled = NULL;
  config->scheme_api_run_enabled = NULL;
  config->plugin_api_run_enabled = NULL;
  config->allow_multiple_user_per_session = 1;
  config->metrics_endpoint = 0;
  config->metrics_endpoint_port = GLEWLWYD_DEFAULT_METRICS_PORT;
  config->metrics_endpoint_admin_session = 0;
  config->allow_gzip = 1;
  config->allow_deflate = 1;

  // Initialize module lock
  pthread_mutexattr_init ( &mutexattr );
  pthread_mutexattr_settype( &mutexattr, PTHREAD_MUTEX_RECURSIVE );
  if (pthread_mutex_init(&config->module_lock, &mutexattr) != 0) {
    fprintf(stderr, "Error initializing modules mutex\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  if (pthread_mutex_init(&config->insert_lock, &mutexattr) != 0) {
    fprintf(stderr, "Error initializing insert mutex\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  pthread_mutexattr_destroy(&mutexattr);

  config->static_file_config = o_malloc(sizeof(struct _u_compressed_inmemory_website_config));
  if (config->static_file_config == NULL) {
    fprintf(stderr, "Error allocating resources for config->static_file_config, aborting\n");
    return 2;
  } else if (u_init_compressed_inmemory_website_config(config->static_file_config) != U_OK) {
    fprintf(stderr, "Error u_init_compressed_inmemory_website_config for config->static_file_config, aborting\n");
    return 2;
  }
  u_map_put(&config->static_file_config->mime_types, "*", "application/octet-stream");
  config->instance = o_malloc(sizeof(struct _u_instance));
  if (config->instance == NULL) {
    fprintf(stderr, "Error allocating resources for config->instance, aborting\n");
    return 2;
  }

  if (pthread_mutex_init(&global_handler_close_lock, NULL) ||
      pthread_cond_init(&global_handler_close_cond, NULL)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "init - Error initializing global_handler_close_lock or global_handler_close_cond");
  }

  // Process end signals on dedicated thread
  if (sigemptyset(&close_signals) == -1 ||
      sigaddset(&close_signals, SIGQUIT) == -1 ||
      sigaddset(&close_signals, SIGINT) == -1 ||
      sigaddset(&close_signals, SIGTERM) == -1 ||
      sigaddset(&close_signals, SIGHUP) == -1 ||
      sigaddset(&close_signals, SIGBUS) == -1 ||
      sigaddset(&close_signals, SIGSEGV) == -1 ||
      sigaddset(&close_signals, SIGILL) == -1) {
    fprintf(stderr, "init - Error creating signal mask\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  if (pthread_sigmask(SIG_BLOCK, &close_signals, NULL)) {
    fprintf(stderr, "init - Error setting signal mask\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }

  if (pthread_create(&signal_thread_id, NULL, &signal_thread, &close_signals)) {
    fprintf(stderr, "init - Error creating signal thread\n");
    exit_server(&config, GLEWLWYD_ERROR);
    return 1;
  }

  // Parse command line arguments
  if (build_config_from_args(argc, argv, config, &use_config_file, &use_config_env) != G_OK) {
    fprintf(stderr, "Error parsing command-line parameters\n");
    print_help(stderr);
    exit_server(&config, GLEWLWYD_ERROR);
  }

  // Parse configuration file
  if (use_config_file && build_config_from_file(config) != G_OK) {
    fprintf(stderr, "Error parsing config file\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }

  // Parse environment variables
  if (use_config_env && build_config_from_env(config) != G_OK) {
    fprintf(stderr, "Error parsing environment variables\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }

  // Check if all mandatory configuration variables are present and correctly typed
  if (check_config(config) != G_OK) {
    fprintf(stderr, "Error - check the configuration\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }

  if (config->log_mode != Y_LOG_MODE_NONE && config->log_level != Y_LOG_LEVEL_NONE && !y_init_logs(GLEWLWYD_LOG_NAME, config->log_mode, config->log_level, config->log_file, "Starting Glewlwyd SSO authentication service")) {
    fprintf(stderr, "Error initializing logs\n");
    return 0;
  }
  
  if (config->log_level == Y_LOG_LEVEL_DEBUG) {
    y_set_split_message_newline(1, "Split logs with newlines");
  }

  if (o_strnullempty(config->cookie_domain)) {
    y_log_message(Y_LOG_LEVEL_WARNING, "Config property 'cookie_domain' is not set - cookie session may not be saved on the browser");
  } else if (o_strstr(config->external_url, config->cookie_domain) == NULL) {
    y_log_message(Y_LOG_LEVEL_WARNING, "Config property 'cookie_domain' seems different from 'external_url', cookie session may not be saved on the browser");
  }

  if (!config->cookie_secure) {
    y_log_message(Y_LOG_LEVEL_WARNING, "Config property 'cookie_secure' is set to false, recommended settings is true");
  }

  if (config->bind_address != NULL) {
    bind_address.sin_family = AF_INET;
    bind_address.sin_port = htons((uint16_t)config->port);
    inet_aton(config->bind_address, (struct in_addr *)&bind_address.sin_addr.s_addr);
    if (ulfius_init_instance(config->instance, config->port, &bind_address, NULL) != U_OK) {
      fprintf(stderr, "Error initializing webservice instance with bind address %s\n", config->bind_address);
      exit_server(&config, GLEWLWYD_ERROR);
    }
  } else {
    if (ulfius_init_instance(config->instance, config->port, NULL, NULL) != U_OK) {
      fprintf(stderr, "Error initializing webservice instance\n");
      exit_server(&config, GLEWLWYD_ERROR);
    }
  }
  config->instance->max_post_body_size = config->max_post_size;
  config->instance->max_post_param_size = config->max_post_size;
  config->instance_initialized = 1;

  http_comression_config.allow_gzip = config->allow_gzip;
  http_comression_config.allow_deflate = config->allow_deflate;
  config->static_file_config->allow_gzip = config->allow_gzip;
  config->static_file_config->allow_deflate = config->allow_deflate;

  if (config->metrics_endpoint) {
    config->instance_metrics = o_malloc(sizeof(struct _u_instance));
    if (config->instance_metrics == NULL) {
      fprintf(stderr, "Error allocating resources for config->instance_metrics, aborting\n");
      exit_server(&config, GLEWLWYD_ERROR);
    }
    if (config->bind_address_metrics != NULL) {
      bind_address_metrics.sin_family = AF_INET;
      bind_address_metrics.sin_port = htons((uint16_t)config->metrics_endpoint_port);
      inet_aton(config->bind_address_metrics, (struct in_addr *)&bind_address_metrics.sin_addr.s_addr);
      if (ulfius_init_instance(config->instance_metrics, config->metrics_endpoint_port, &bind_address_metrics, NULL) != U_OK) {
        fprintf(stderr, "Error initializing metrics instance_metrics with bind address %s\n", config->bind_address_metrics);
        exit_server(&config, GLEWLWYD_ERROR);
      }
    } else {
      if (ulfius_init_instance(config->instance_metrics, config->metrics_endpoint_port, NULL, NULL) != U_OK) {
        fprintf(stderr, "Error initializing metrics instance_metrics\n");
        exit_server(&config, GLEWLWYD_ERROR);
      }
    }
    if (glewlwyd_metrics_init(config) != 0) {
      fprintf(stderr, "Error initializing metrics\n");
      exit_server(&config, GLEWLWYD_ERROR);
    }
    config->instance_metrics_initialized = 1;
  }
  
  glewlwyd_metrics_add_metric(config, GLWD_METRICS_AUTH_USER_VALID, "Total number of successful authentication");
  glewlwyd_metrics_add_metric(config, GLWD_METRICS_AUTH_USER_VALID_SCHEME, "Total number of successful authentication by scheme");
  glewlwyd_metrics_add_metric(config, GLWD_METRICS_AUTH_USER_INVALID, "Total number of invalid authentication");
  glewlwyd_metrics_add_metric(config, GLWD_METRICS_AUTH_USER_INVALID_SCHEME, "Total number of invalid authentication by scheme");
  glewlwyd_metrics_add_metric(config, GLWD_METRICS_DATABSE_ERROR, "Total number of database errors");
  glewlwyd_metrics_increment_counter_va(config, GLWD_METRICS_AUTH_USER_VALID, 0, NULL);
  glewlwyd_metrics_increment_counter_va(config, GLWD_METRICS_AUTH_USER_INVALID, 0, NULL);
  glewlwyd_metrics_increment_counter_va(config, GLWD_METRICS_AUTH_USER_VALID_SCHEME, 0, "scheme_type", "password", NULL);
  glewlwyd_metrics_increment_counter_va(config, GLWD_METRICS_AUTH_USER_INVALID_SCHEME, 0, "scheme_type", "password", NULL);
  glewlwyd_metrics_increment_counter_va(config, GLWD_METRICS_DATABSE_ERROR, 0, NULL);

  config->config_m->external_url = config->external_url;
  config->config_m->login_url = config->login_url;
  config->config_m->admin_scope = config->admin_scope;
  config->config_m->profile_scope = config->profile_scope;
  config->config_m->conn = config->conn;
  config->config_m->hash_algorithm = config->hash_algorithm;

  // Initialize user modules
  if (init_user_module_list(config) != G_OK) {
    fprintf(stderr, "Error initializing user modules\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  if (load_user_module_instance_list(config) != G_OK) {
    fprintf(stderr, "Error loading user modules instances\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }

  // Initialize user middleware modules
  if (init_user_middleware_module_list(config) != G_OK) {
    fprintf(stderr, "Error initializing user middleware modules\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  if (load_user_middleware_module_instance_list(config) != G_OK) {
    fprintf(stderr, "Error loading user middleware modules instances\n");
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
  if (config->login_api_enabled) {
    ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_auth, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/auth/scheme/trigger/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_auth_trigger, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/auth/scheme/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_get_schemes_from_scopes, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_delete_session, (void*)config);
    // User profile
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/profile_list/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_get_profile, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/plugin", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_user_session, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/profile/plugin", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_get_plugin_list, (void*)config);
  } else {
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/auth/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/profile_list/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_403_whatever_the_means, NULL);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/plugin", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/profile/plugin", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_403_whatever_the_means, NULL);
  }

  if (config->profile_session_authentication & GLEWLWYD_SESSION_AUTH_COOKIE) {
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_user_profile_valid, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/password", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_user_profile_valid, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/grant", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_user_profile_valid, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/session/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_user_profile_valid, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/scheme/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_user_profile_valid, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_update_profile, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_delete_profile, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/profile/password", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_update_password, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/profile/grant", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_get_client_grant_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/profile/session", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_get_session_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/profile/session/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_session, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/profile/session/:session_hash", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_session, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/profile/scheme", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_get_scheme_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/scheme/register/*", GLEWLWYD_CALLBACK_PRIORITY_PRE_APPLICATION, &callback_glewlwyd_scheme_check_forbid_profile, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/profile/scheme/register/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_auth_register, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/profile/scheme/register/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_auth_register_get, (void*)config);
  } else {
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/password", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/grant", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/scheme/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/session/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
  }

  // Grant scopes endpoints
  ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/auth/grant/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_user_session, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/auth/grant/:client_id/:scope_list", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user_session_scope_grant, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/auth/grant/:client_id/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_user_session_scope_grant, (void*)config);

  if (config->admin_session_authentication & GLEWLWYD_SESSION_AUTH_COOKIE) {
    // User profile by delegation
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/delegate/:username/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_admin_session_delegate, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/delegate/:username/profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_update_profile, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/delegate/:username/profile/session", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_get_session_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/delegate/:username/profile/plugin", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_get_plugin_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/delegate/:username/profile/grant", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_get_client_grant_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/delegate/:username/auth/grant/:client_id", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_user_session_scope_grant, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/delegate/:username/profile/session/:session_hash", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_session, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/delegate/:username/profile/scheme", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_get_scheme_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/delegate/:username/profile/scheme/register/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_auth_register_delegate, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/delegate/:username/profile/scheme/register/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_auth_register_get_delegate, (void*)config);
  } else {
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/delegate/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
  }

  if (config->admin_session_authentication & (GLEWLWYD_SESSION_AUTH_COOKIE|GLEWLWYD_SESSION_AUTH_API_KEY)) {
    // Modules check session
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/mod/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_admin_session_or_api_key, (void*)config);

    // Get all module types available
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/type/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_module_type_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/mod/reload/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_reload_modules, (void*)config);

    // User modules management
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/user/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user_module_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/user/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user_module, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/mod/user/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_user_module, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/mod/user/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_user_module, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/mod/user/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_user_module, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/mod/user/:name/:action", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_manage_user_module, (void*)config);

    // User middleware modules management
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/user_middleware/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user_middleware_module_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/mod/user_middleware/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user_middleware_module, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/mod/user_middleware/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_user_middleware_module, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/mod/user_middleware/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_user_middleware_module, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/mod/user_middleware/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_user_middleware_module, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/mod/user_middleware/:name/:action", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_manage_user_middleware_module, (void*)config);

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

    // Users CRUD
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/user/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_admin_session_or_api_key, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/user/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/user/:username", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/user/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_user, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/user/:username", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_user, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/user/:username", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_user, (void*)config);

    // Clients CRUD
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/client/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_admin_session_or_api_key, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/client/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_client_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/client/:client_id", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_client, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/client/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_client, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/client/:client_id", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_client, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/client/:client_id", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_client, (void*)config);

    // Scopes CRUD
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/scope/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_admin_session_or_api_key, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/scope/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_scope_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/scope/:scope", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_scope, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/scope/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_scope, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/scope/:scope", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_scope, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/scope/:scope", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_scope, (void*)config);

    // API key CRD
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/key/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_admin_session, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/key/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_api_key_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/key/:key_hash", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_api_key, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/key/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_api_key, (void*)config);

    // Misc configuration CRUD
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/misc/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_admin_session_or_api_key, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/misc/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_misc_config_list, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/misc/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_misc_config, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/misc/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_misc_config, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/misc/:name", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_misc_config, (void*)config);
  } else {
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/mod/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/user/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/client/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/scope/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/key/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/misc/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_403_whatever_the_means, NULL);
  }

  // Other configuration
  ulfius_add_endpoint_by_val(config->instance, "GET", "/config", NULL, GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_server_configuration, (void*)config);

  if (http_comression_config.allow_deflate || http_comression_config.allow_gzip) {
    ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/profile_list/", GLEWLWYD_CALLBACK_PRIORITY_COMPRESSION, &callback_http_compression, &http_comression_config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/profile/*", GLEWLWYD_CALLBACK_PRIORITY_COMPRESSION, &callback_http_compression, &http_comression_config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/auth/grant/*", GLEWLWYD_CALLBACK_PRIORITY_COMPRESSION, &callback_http_compression, &http_comression_config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/delegate/:username/*", GLEWLWYD_CALLBACK_PRIORITY_COMPRESSION, &callback_http_compression, &http_comression_config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/mod/*", GLEWLWYD_CALLBACK_PRIORITY_COMPRESSION, &callback_http_compression, &http_comression_config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/user/*", GLEWLWYD_CALLBACK_PRIORITY_COMPRESSION, &callback_http_compression, &http_comression_config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/client/*", GLEWLWYD_CALLBACK_PRIORITY_COMPRESSION, &callback_http_compression, &http_comression_config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/scope/*", GLEWLWYD_CALLBACK_PRIORITY_COMPRESSION, &callback_http_compression, &http_comression_config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "/key/*", GLEWLWYD_CALLBACK_PRIORITY_COMPRESSION, &callback_http_compression, &http_comression_config);
    ulfius_add_endpoint_by_val(config->instance, "GET", "/config", NULL, GLEWLWYD_CALLBACK_PRIORITY_COMPRESSION, &callback_http_compression, &http_comression_config);
  }
  ulfius_add_endpoint_by_val(config->instance, "OPTIONS", NULL, "*", GLEWLWYD_CALLBACK_PRIORITY_ZERO, &callback_glewlwyd_options, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", NULL, "*", GLEWLWYD_CALLBACK_PRIORITY_POST_FILE, &callback_404_if_necessary, NULL);
  ulfius_set_default_endpoint(config->instance, &callback_default, (void*)config);

  // Static files server
  if (config->static_file_config->files_path != NULL) {
    ulfius_add_endpoint_by_val(config->instance, "GET", NULL, "*", GLEWLWYD_CALLBACK_PRIORITY_FILE, &callback_static_compressed_inmemory_website, (void*)config->static_file_config);
  }
  // Set default headers
  u_map_put(config->instance->default_headers, "Access-Control-Allow-Origin", config->allow_origin);
  u_map_put(config->instance->default_headers, "Access-Control-Allow-Credentials", "true");
  u_map_put(config->instance->default_headers, "Cache-Control", "no-store");
  u_map_put(config->instance->default_headers, "Pragma", "no-cache");
  if (config->add_x_frame_option_header_deny) {
    u_map_put(config->instance->default_headers, "X-Frame-Options", "deny");
  }
  config->instance->allowed_post_processor = U_POST_PROCESS_URL_ENCODED;

  // metrics endpoint configuration
  if (config->metrics_endpoint) {
    config->instance_metrics->allowed_post_processor = U_POST_PROCESS_NONE;
    if (config->metrics_endpoint_admin_session) {
      ulfius_add_endpoint_by_val(config->instance_metrics, "GET", NULL, "*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_admin_session, (void*)config);
    }
    ulfius_add_endpoint_by_val(config->instance_metrics, "GET", NULL, "*", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_metrics, (void*)config);
    ulfius_add_endpoint_by_val(config->instance_metrics, "GET", NULL, "*", GLEWLWYD_CALLBACK_PRIORITY_COMPRESSION, &callback_http_compression, &http_comression_config);
    ulfius_set_default_endpoint(config->instance_metrics, &callback_default, (void*)config);
    if (ulfius_start_framework(config->instance_metrics) != U_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error starting metrics webservice instance_metrics");
      exit_server(&config, GLEWLWYD_ERROR);
    }
  }

  // Check if cookie domain (if set) is the same domain as in external_url
  if (!o_strnullempty(config->cookie_domain)) {
    if (0 == o_strncmp("http://", config->external_url, o_strlen("http://"))) {
      tmp = o_strdup(config->external_url);
      tmp2 = o_strchr(tmp+o_strlen("http://"), '/');
      if (tmp2 != NULL) {
        *tmp2 = '\0';
      }
      tmp2 = o_strchr(tmp+o_strlen("http://"), ':');
      if (tmp2 != NULL) {
        *tmp2 = '\0';
      }
      if (0 != o_strcmp(tmp+o_strlen("http://"), config->cookie_domain)) {
        y_log_message(Y_LOG_LEVEL_WARNING, "Configuration parameter cookie_domain '%s' does not seem to match the domain in external_url '%s'", config->cookie_domain, tmp+o_strlen("http://"));
      }
      o_free(tmp);
    } else if (0 == o_strncmp("https://", config->external_url, o_strlen("https://"))) {
      tmp = o_strdup(config->external_url);
      tmp2 = o_strchr(tmp+o_strlen("https://"), '/');
      if (tmp2 != NULL) {
        *tmp2 = '\0';
      }
      tmp2 = o_strchr(tmp+o_strlen("https://"), ':');
      if (tmp2 != NULL) {
        *tmp2 = '\0';
      }
      if (0 != o_strcmp(tmp+o_strlen("https://"), config->cookie_domain)) {
        y_log_message(Y_LOG_LEVEL_WARNING, "Configuration parameter cookie_domain '%s' does not seem to match the domain in external_url '%s'", config->cookie_domain, tmp+o_strlen("https://"));
      }
      o_free(tmp);
    }
  }

  y_log_message(Y_LOG_LEVEL_INFO, "Glewlwyd started on port %d, prefix: %s, secure: %s, bind address: %s, external URL: %s", config->instance->port, config->api_prefix, config->use_secure_connection?"true":"false", config->bind_address!=NULL?config->bind_address:"no", config->external_url);

  if (config->use_secure_connection) {
    char * key_file = get_file_content(config->secure_connection_key_file);
    char * pem_file = get_file_content(config->secure_connection_pem_file);
    if (key_file != NULL && pem_file != NULL) {
      if (config->secure_connection_ca_file != NULL) {
        char * ca_file = get_file_content(config->secure_connection_ca_file);
        if (ca_file != NULL) {
          res = ulfius_start_secure_ca_trust_framework(config->instance, key_file, pem_file, ca_file);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "Error ca_file: %s", config->secure_connection_ca_file);
          res = G_ERROR_PARAM;
        }
        o_free(ca_file);
      } else {
        res = ulfius_start_secure_framework(config->instance, key_file, pem_file);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error server certificate: %s - %s", config->secure_connection_key_file, config->secure_connection_pem_file);
      res = G_ERROR_PARAM;
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
  exit_server(&config, 0);
  return 0;
}

/**
 * Exit properly the server by closing opened connections, databases and files
 */
void exit_server(struct config_elements ** config, int exit_value) {
  int close_logs = 0;

  if (config != NULL && *config != NULL) {
    close_logs = ((*config)->log_mode != Y_LOG_MODE_NONE && (*config)->log_level != Y_LOG_LEVEL_NONE);

    close_user_module_instance_list(*config);
    close_user_module_list(*config);

    close_user_middleware_module_instance_list(*config);
    close_user_middleware_module_list(*config);

    close_client_module_instance_list(*config);
    close_client_module_list(*config);

    close_user_auth_scheme_module_instance_list(*config);
    close_user_auth_scheme_module_list(*config);

    close_plugin_module_instance_list(*config);
    close_plugin_module_list(*config);

    pthread_mutex_destroy(&(*config)->module_lock);
    pthread_mutex_destroy(&(*config)->insert_lock);

    /* stop framework */
    if ((*config)->instance_initialized) {
      ulfius_stop_framework((*config)->instance);
      ulfius_clean_instance((*config)->instance);
    }

    if ((*config)->instance_metrics_initialized) {
      ulfius_stop_framework((*config)->instance_metrics);
      ulfius_clean_instance((*config)->instance_metrics);
    }

    h_close_db((*config)->conn);
    h_clean_connection((*config)->conn);
    ulfius_global_close();

    // Cleaning data
    o_free((*config)->instance);
    o_free((*config)->instance_metrics);

    y_log_message(Y_LOG_LEVEL_INFO, "Glewlwyd stopped");

    o_free((*config)->config_file);
    o_free((*config)->api_prefix);
    o_free((*config)->cookie_domain);
    o_free((*config)->admin_scope);
    o_free((*config)->profile_scope);
    o_free((*config)->external_url);
    o_free((*config)->log_file);
    o_free((*config)->allow_origin);
    o_free((*config)->allow_methods);
    o_free((*config)->allow_headers);
    o_free((*config)->expose_headers);
    o_free((*config)->originating_ip_header);
    o_free((*config)->secure_connection_key_file);
    o_free((*config)->secure_connection_pem_file);
    o_free((*config)->secure_connection_ca_file);
    o_free((*config)->session_key);
    o_free((*config)->login_url);
    o_free((*config)->user_module_path);
    o_free((*config)->user_middleware_module_path);
    o_free((*config)->client_module_path);
    o_free((*config)->user_auth_scheme_module_path);
    o_free((*config)->plugin_module_path);
    o_free((*config)->bind_address);
    o_free((*config)->user_backend_api_run_enabled);
    o_free((*config)->user_middleware_backend_api_run_enabled);
    o_free((*config)->client_backend_api_run_enabled);
    o_free((*config)->scheme_api_run_enabled);
    o_free((*config)->plugin_api_run_enabled);

    if ((*config)->static_file_config != NULL) {
      o_free((*config)->static_file_config->files_path);
      u_clean_compressed_inmemory_website_config((*config)->static_file_config);
      o_free((*config)->static_file_config);
    }
    glewlwyd_metrics_close((*config));

    o_free((*config)->config_p);
    o_free((*config)->config_m);
    o_free(*config);
    (*config) = NULL;

    if (close_logs) {
      y_close_logs();
    }
  }
  exit(exit_value);
}

/**
 * Initialize the application configuration based on the command line parameters
 */
int build_config_from_args(int argc, char ** argv, struct config_elements * config, int * use_config_file, int * use_config_env) {
  int next_option, ret = G_OK;
  const char * short_options = "c:e::p:m:l:f:h::v::";
  char * tmp = NULL, * to_free = NULL, * one_log_mode = NULL;
  static const struct option long_options[]= {
    {"config-file", required_argument, NULL, 'c'},
    {"env-variables", no_argument, NULL, 'e'},
    {"port", required_argument, NULL, 'p'},
    {"log-mode", required_argument, NULL, 'm'},
    {"log-level", required_argument, NULL, 'l'},
    {"log-file", required_argument, NULL, 'f'},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
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
              ret = G_ERROR_PARAM;
            } else {
              *use_config_file = 1;
            }
          } else {
            fprintf(stderr, "Error!\nNo config file specified\n");
            ret = G_ERROR_PARAM;
          }
          break;
        case 'e':
          *use_config_env = 1;
          break;
        case 'p':
          if (optarg != NULL) {
            config->port = (unsigned int)strtol(optarg, NULL, 10);
            if (config->port <= 0 || config->port > 65535) {
              fprintf(stderr, "Error!\nInvalid TCP Port number\n\tPlease specify an integer value between 1 and 65535");
              ret = G_ERROR_PARAM;
            }
          } else {
            fprintf(stderr, "Error!\nNo TCP Port number specified\n");
            ret = G_ERROR_PARAM;
          }
          break;
        case 'm':
          if (optarg != NULL) {
            config->log_mode_args = 1;
            tmp = o_strdup(optarg);
            if (tmp == NULL) {
              fprintf(stderr, "Error allocating log_mode, exiting\n");
              ret = G_ERROR_PARAM;
            }
            config->log_mode = Y_LOG_MODE_NONE;
            one_log_mode = strtok(tmp, ",");
            while (one_log_mode != NULL) {
              if (0 == o_strcmp("console", one_log_mode)) {
                config->log_mode += Y_LOG_MODE_CONSOLE;
              } else if (0 == o_strcmp("syslog", one_log_mode)) {
                config->log_mode += Y_LOG_MODE_SYSLOG;
              } else if (0 == o_strcmp("journald", one_log_mode)) {
                config->log_mode += Y_LOG_MODE_JOURNALD;
              } else if (0 == o_strcmp("file", one_log_mode)) {
                config->log_mode += Y_LOG_MODE_FILE;
              }
              one_log_mode = strtok(NULL, ",");
            }
            o_free(to_free);
          } else {
            fprintf(stderr, "Error!\nNo mode specified\n");
            ret = G_ERROR_PARAM;
          }
          break;
        case 'l':
          if (optarg != NULL) {
            config->log_level_args = 1;
            config->log_level = Y_LOG_LEVEL_NONE;
            if (0 == o_strcmp("NONE", optarg)) {
              config->log_level = Y_LOG_LEVEL_NONE;
            } else if (0 == o_strcmp("ERROR", optarg)) {
              config->log_level = Y_LOG_LEVEL_ERROR;
            } else if (0 == o_strcmp("WARNING", optarg)) {
              config->log_level = Y_LOG_LEVEL_WARNING;
            } else if (0 == o_strcmp("INFO", optarg)) {
              config->log_level = Y_LOG_LEVEL_INFO;
            } else if (0 == o_strcmp("DEBUG", optarg)) {
              config->log_level = Y_LOG_LEVEL_DEBUG;
            }
          } else {
            fprintf(stderr, "Error!\nNo log level specified\n");
            ret = G_ERROR_PARAM;
          }
          break;
        case 'f':
          if (optarg != NULL) {
            o_free(config->log_file);
            config->log_file = o_strdup(optarg);
            if (config->log_file == NULL) {
              fprintf(stderr, "Error allocating config->log_file, exiting\n");
              ret = G_ERROR_PARAM;
            }
          } else {
            fprintf(stderr, "Error!\nNo log file specified\n");
            ret = G_ERROR_PARAM;
          }
          break;
        case 'h':
          print_help(stdout);
          exit_server(&config, 0);
          break;
        case 'v':
          fprintf(stdout, "%s\n", _GLEWLWYD_VERSION_);
          exit_server(&config, 0);
          break;
      }

    } while (next_option != -1);
  } else {
    ret = G_ERROR;
  }
  return ret;
}

/**
 * Initialize the application configuration based on the config file content
 * Read the config file, get mandatory variables and devices
 */
int build_config_from_file(struct config_elements * config) {

  config_t cfg;
  config_setting_t * root = NULL,
                   * database = NULL,
                   * mime_type_list = NULL,
                   * mime_type = NULL;
  const char * str_value = NULL,
             * str_value_2 = NULL,
             * str_value_3 = NULL,
             * str_value_4 = NULL,
             * str_value_5 = NULL;
  int int_value = 0,
      int_value_2 = 0,
      int_value_3 = 0,
      ret = G_OK;
  unsigned int i;
  char * one_log_mode, * real_path, ** splitted = NULL;

  config_init(&cfg);

  do {
    if (!config_read_file(&cfg, config->config_file)) {
      fprintf(stderr, "Error parsing config file %s\nOn line %d error: %s, exiting\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
      ret = G_ERROR_PARAM;
      break;
    }

    // Get Port number to listen to
    if (!config->port && config_lookup_int(&cfg, "port", &int_value) == CONFIG_TRUE) {
      config->port = (uint)int_value;
    }

    if (config_lookup_int(&cfg, "max_post_size", &int_value) == CONFIG_TRUE) {
      config->max_post_size = (size_t)int_value;
    }

    if (config_lookup_int(&cfg, "response_body_limit", &int_value) == CONFIG_TRUE) {
      config->response_body_limit = (size_t)int_value;
    }

    if (config_lookup_int(&cfg, "max_header", &int_value) == CONFIG_TRUE) {
      config->max_header = (size_t)int_value;
    }

    if (config_lookup_string(&cfg, "bind_address", &str_value) == CONFIG_TRUE) {
      config->bind_address = o_strdup(str_value);
      if (config->bind_address == NULL) {
        fprintf(stderr, "Error allocating config->bind_address, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    if (config_lookup_string(&cfg, "api_prefix", &str_value) == CONFIG_TRUE) {
      o_free(config->api_prefix);
      config->api_prefix = o_strdup(str_value);
      if (config->api_prefix == NULL) {
        fprintf(stderr, "Error allocating config->api_prefix, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    if (config_lookup_string(&cfg, "cookie_domain", &str_value) == CONFIG_TRUE) {
      o_free(config->cookie_domain);
      config->cookie_domain = o_strdup(str_value);
      if (config->cookie_domain == NULL) {
        fprintf(stderr, "Error allocating config->cookie_domain, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    if (config_lookup_int(&cfg, "cookie_secure", &int_value) == CONFIG_TRUE) {
      config->cookie_secure = (uint)int_value;
    }

    if (config_lookup_string(&cfg, "cookie_same_site", &str_value) == CONFIG_TRUE) {
      if (0 == o_strcasecmp("empty", str_value)) {
        config->cookie_same_site = U_COOKIE_SAME_SITE_EMPTY;
      } else if (0 == o_strcasecmp("none", str_value)) {
        config->cookie_same_site = U_COOKIE_SAME_SITE_NONE;
      } else if (0 == o_strcasecmp("lax", str_value)) {
        config->cookie_same_site = U_COOKIE_SAME_SITE_LAX;
      } else if (0 == o_strcasecmp("strict", str_value)) {
        config->cookie_same_site = U_COOKIE_SAME_SITE_STRICT;
      } else {
        fprintf(stderr, "Error invalid cookie_same_site, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    if (config_lookup_bool(&cfg, "add_x_frame_option_header_deny", &int_value) == CONFIG_TRUE) {
      config->add_x_frame_option_header_deny = (uint)int_value;
    }

    // Get log mode
    if (!config->log_mode_args && config_lookup_string(&cfg, "log_mode", &str_value) == CONFIG_TRUE) {
      config->log_mode = Y_LOG_MODE_NONE;
      one_log_mode = strtok((char *)str_value, ",");
      while (one_log_mode != NULL) {
        if (0 == o_strcmp("console", one_log_mode)) {
          config->log_mode |= Y_LOG_MODE_CONSOLE;
        } else if (0 == o_strcmp("syslog", one_log_mode)) {
          config->log_mode |= Y_LOG_MODE_SYSLOG;
        } else if (0 == o_strcmp("journald", one_log_mode)) {
          config->log_mode |= Y_LOG_MODE_JOURNALD;
        } else if (0 == o_strcmp("file", one_log_mode)) {
          config->log_mode |= Y_LOG_MODE_FILE;
          // Get log file path
          if (config->log_file == NULL) {
            if (config_lookup_string(&cfg, "log_file", &str_value_2) == CONFIG_TRUE) {
              config->log_file = o_strdup(str_value_2);
              if (config->log_file == NULL) {
                fprintf(stderr, "Error allocating config->log_file, exiting\n");
                ret = G_ERROR_PARAM;
                break;
              }
            }
          }
        } else {
          fprintf(stderr, "Error - logging mode '%s' unknown, exiting\n", one_log_mode);
          ret = G_ERROR_PARAM;
          break;
        }
        one_log_mode = strtok(NULL, ",");
      }
      if (ret != G_OK) {
        break;
      }
    }

    // Get log level
    if (!config->log_level_args && config_lookup_string(&cfg, "log_level", &str_value) == CONFIG_TRUE) {
      config->log_level = Y_LOG_LEVEL_NONE;
      if (0 == o_strcmp("ERROR", str_value)) {
        config->log_level = Y_LOG_LEVEL_ERROR;
      } else if (0 == o_strcmp("WARNING", str_value)) {
        config->log_level = Y_LOG_LEVEL_WARNING;
      } else if (0 == o_strcmp("INFO", str_value)) {
        config->log_level = Y_LOG_LEVEL_INFO;
      } else if (0 == o_strcmp("DEBUG", str_value)) {
        config->log_level = Y_LOG_LEVEL_DEBUG;
      }
    }

    // Get allow-origin value for CORS
    if (config_lookup_string(&cfg, "allow_origin", &str_value) == CONFIG_TRUE) {
      o_free(config->allow_origin);
      config->allow_origin = o_strdup(str_value);
      if (config->allow_origin == NULL) {
        fprintf(stderr, "Error allocating config->allow_origin, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    // Get allow-methods value for CORS
    if (config_lookup_string(&cfg, "allow_methods", &str_value) == CONFIG_TRUE) {
      o_free(config->allow_methods);
      config->allow_methods = o_strdup(str_value);
      if (config->allow_methods == NULL) {
        fprintf(stderr, "Error allocating config->allow_methods, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    // Get allow-origin value for CORS
    if (config_lookup_string(&cfg, "allow_headers", &str_value) == CONFIG_TRUE) {
      o_free(config->allow_headers);
      config->allow_headers = o_strdup(str_value);
      if (config->allow_headers == NULL) {
        fprintf(stderr, "Error allocating config->allow_headers, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    // Get allow-origin value for CORS
    if (config_lookup_string(&cfg, "expose_headers", &str_value) == CONFIG_TRUE) {
      o_free(config->expose_headers);
      config->expose_headers = o_strdup(str_value);
      if (config->expose_headers == NULL) {
        fprintf(stderr, "Error allocating config->expose_headers, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    // Get originating_ip_header
    if (config_lookup_string(&cfg, "originating_ip_header", &str_value) == CONFIG_TRUE) {
      o_free(config->originating_ip_header);
      config->originating_ip_header = o_strdup(str_value);
      if (config->originating_ip_header == NULL) {
        fprintf(stderr, "Error allocating config->originating_ip_header, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    if (config_lookup_string(&cfg, "session_key", &str_value) == CONFIG_TRUE) {
      o_free(config->session_key);
      config->session_key = o_strdup(str_value);
    }

    if (config_lookup_int(&cfg, "session_expiration", &int_value) == CONFIG_TRUE) {
      config->session_expiration = (uint)int_value;
    }

    if (config_lookup_string(&cfg, "external_url", &str_value) == CONFIG_TRUE) {
      o_free(config->external_url);
      config->external_url = o_strdup(str_value);
      if (config->external_url == NULL) {
        fprintf(stderr, "Error allocating resources for config->external_url, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    if (config_lookup_string(&cfg, "login_url", &str_value) == CONFIG_TRUE) {
      o_free(config->login_url);
      config->login_url = o_strdup(str_value);
      if (config->login_url == NULL) {
        fprintf(stderr, "Error allocating resources for config->login_url, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    if (config_lookup_string(&cfg, "delete_profile", &str_value) == CONFIG_TRUE) {
      if (0 == o_strcmp("no", str_value)) {
        config->delete_profile = GLEWLWYD_PROFILE_DELETE_UNAUTHORIZED;
      } else if (0 == o_strcmp("delete", str_value)) {
        config->delete_profile = GLEWLWYD_PROFILE_DELETE_AUTHORIZED;
      } else if (0 == o_strcmp("disable", str_value)) {
        config->delete_profile = GLEWLWYD_PROFILE_DELETE_AUTHORIZED | GLEWLWYD_PROFILE_DELETE_DISABLE_PROFILE;
      } else {
        fprintf(stderr, "Invalid value for delete_profile, expected 'no', 'delete' or 'disable', exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    // Get path that serve static files
    if (config_lookup_string(&cfg, "static_files_path", &str_value) == CONFIG_TRUE) {
      o_free(config->static_file_config->files_path);
      real_path = realpath(str_value, NULL);
      if (real_path != NULL) {
        config->static_file_config->files_path = o_strdup(real_path);
        free(real_path);
        if (config->static_file_config->files_path == NULL) {
          fprintf(stderr, "Error allocating config->files_path, exiting\n");
          ret = G_ERROR_PARAM;
          break;
        }
      } else {
        fprintf(stderr, "Invalid static_files_path, exiting\n");
        ret = G_ERROR_PARAM;
      }
    }

    // Populate mime types u_map
    mime_type_list = config_lookup(&cfg, "static_files_mime_types");
    if (mime_type_list != NULL) {
      unsigned int len = (unsigned int)config_setting_length(mime_type_list);
      for (i=0; i<len; i++) {
        mime_type = config_setting_get_elem(mime_type_list, i);
        if (mime_type != NULL) {
          if (config_setting_lookup_string(mime_type, "extension", &str_value) == CONFIG_TRUE &&
              config_setting_lookup_string(mime_type, "mime_type", &str_value_2) == CONFIG_TRUE) {
            u_map_put(&config->static_file_config->mime_types, str_value, str_value_2);
            if (config_setting_lookup_int(mime_type, "compress", &int_value) == CONFIG_TRUE) {
              if (int_value && u_add_mime_types_compressed(config->static_file_config, str_value_2) != U_OK) {
                fprintf(stderr, "Error setting mime_type %s to compressed list, exiting\n", str_value_2);
                ret = G_ERROR_PARAM;
                break;
              }
            }
          }
        }
      }
    }

    if (config_lookup_bool(&cfg, "use_secure_connection", &int_value) == CONFIG_TRUE) {
      if (config_lookup_string(&cfg, "secure_connection_key_file", &str_value) == CONFIG_TRUE &&
          config_lookup_string(&cfg, "secure_connection_pem_file", &str_value_2) == CONFIG_TRUE) {
        config->use_secure_connection = (unsigned int)int_value;
        config->secure_connection_key_file = o_strdup(str_value);
        config->secure_connection_pem_file = o_strdup(str_value_2);
        if (config_lookup_string(&cfg, "secure_connection_ca_file", &str_value) == CONFIG_TRUE) {
          config->secure_connection_ca_file = o_strdup(str_value);
        }
      } else {
        fprintf(stderr, "Error secure connection is active but certificate is not valid, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    // Get token hash algorithm
    if (config_lookup_string(&cfg, "hash_algorithm", &str_value) == CONFIG_TRUE) {
      if (!o_strcmp("SHA1", str_value)) {
        config->hash_algorithm = digest_SHA1;
      } else if (!o_strcmp("SHA256", str_value)) {
        config->hash_algorithm = digest_SHA256;
      } else if (!o_strcmp("SHA512", str_value)) {
        config->hash_algorithm = digest_SHA512;
      } else {
        fprintf(stderr, "Error token hash algorithm: %s, exiting\n", str_value);
        ret = G_ERROR_PARAM;
        break;
      }
    }

    root = config_root_setting(&cfg);
    database = config_setting_get_member(root, "database");
    if (database != NULL) {
      if (config_setting_lookup_string(database, "type", &str_value) == CONFIG_TRUE) {
        if (0 == o_strcmp(str_value, "sqlite3")) {
          if (config_setting_lookup_string(database, "path", &str_value_2) == CONFIG_TRUE) {
            config->conn = h_connect_sqlite(str_value_2);
            if (config->conn == NULL) {
              fprintf(stderr, "Error opening sqlite database %s, exiting\n", str_value_2);
              ret = G_ERROR_PARAM;
              break;
            } else {
              if (h_execute_query_sqlite(config->conn, "PRAGMA foreign_keys = ON;") != H_OK) {
                fprintf(stderr, "Error executing sqlite3 query 'PRAGMA foreign_keys = ON;, exiting'\n");
                ret = G_ERROR_PARAM;
                break;
              }
            }
          } else {
            fprintf(stderr, "Error - no sqlite database specified\n");
            ret = G_ERROR_PARAM;
            break;
          }
        } else if (0 == o_strcmp(str_value, "mariadb")) {
          config_setting_lookup_string(database, "host", &str_value_2);
          config_setting_lookup_string(database, "user", &str_value_3);
          config_setting_lookup_string(database, "password", &str_value_4);
          config_setting_lookup_string(database, "dbname", &str_value_5);
          config_setting_lookup_int(database, "port", &int_value);
          config->conn = h_connect_mariadb(str_value_2, str_value_3, str_value_4, str_value_5, (unsigned int)int_value, NULL);
          if (config->conn == NULL) {
            fprintf(stderr, "Error opening mariadb database %s\n", str_value_5);
            ret = G_ERROR_PARAM;
            break;
          } else {
            if (h_execute_query_mariadb(config->conn, "SET sql_mode='PIPES_AS_CONCAT';", NULL) != H_OK) {
              fprintf(stderr, "Error executing mariadb query 'SET sql_mode='PIPES_AS_CONCAT';', exiting\n");
              ret = G_ERROR_PARAM;
              break;
            }
          }
        } else if (0 == o_strcmp(str_value, "postgre")) {
          config_setting_lookup_string(database, "conninfo", &str_value_2);
          config->conn = h_connect_pgsql(str_value_2);
          if (config->conn == NULL) {
            fprintf(stderr, "Error opening postgre database %s, exiting\n", str_value_2);
            ret = G_ERROR_PARAM;
            break;
          }
        } else {
          fprintf(stderr, "Error - database type unknown\n");
          ret = G_ERROR_PARAM;
          break;
        }
      } else {
        fprintf(stderr, "Error - no database type found\n");
        ret = G_ERROR_PARAM;
        break;
      }
    } else {
      fprintf(stderr, "Error - no database setting found\n");
      ret = G_ERROR_PARAM;
      break;
    }

    if (config_lookup_string(&cfg, "admin_scope", &str_value) == CONFIG_TRUE) {
      o_free(config->admin_scope);
      config->admin_scope = o_strdup(str_value);
    }

    if (config_lookup_string(&cfg, "profile_scope", &str_value) == CONFIG_TRUE) {
      o_free(config->profile_scope);
      config->profile_scope = o_strdup(str_value);
    }

    if (config_lookup_string(&cfg, "user_module_path", &str_value) == CONFIG_TRUE) {
      o_free(config->user_module_path);
      config->user_module_path = o_strdup(str_value);
    }

    if (config_lookup_string(&cfg, "user_middleware_module_path", &str_value) == CONFIG_TRUE) {
      o_free(config->user_middleware_module_path);
      config->user_middleware_module_path = o_strdup(str_value);
    }

    if (config_lookup_string(&cfg, "client_module_path", &str_value) == CONFIG_TRUE) {
      o_free(config->client_module_path);
      config->client_module_path = o_strdup(str_value);
    }

    if (config_lookup_string(&cfg, "user_auth_scheme_module_path", &str_value) == CONFIG_TRUE) {
      o_free(config->user_auth_scheme_module_path);
      config->user_auth_scheme_module_path = o_strdup(str_value);
    }

    if (config_lookup_string(&cfg, "plugin_module_path", &str_value) == CONFIG_TRUE) {
      o_free(config->plugin_module_path);
      config->plugin_module_path = o_strdup(str_value);
    }

    if (config_lookup_bool(&cfg, "metrics_endpoint", &int_value) == CONFIG_TRUE) {
      config->metrics_endpoint = (ushort)int_value;

      if (config_lookup_string(&cfg, "metrics_bind_address", &str_value) == CONFIG_TRUE) {
        config->bind_address_metrics = o_strdup(str_value);
        if (config->bind_address_metrics == NULL) {
          fprintf(stderr, "Error allocating config->bind_address_metrics, exiting\n");
          ret = G_ERROR_PARAM;
          break;
        }
      }

      if (config_lookup_int(&cfg, "metrics_endpoint_port", &int_value_2) == CONFIG_TRUE) {
        config->metrics_endpoint_port = (uint)int_value_2;
      }

      if (config_lookup_bool(&cfg, "metrics_endpoint_admin_session", &int_value_3) == CONFIG_TRUE) {
        config->metrics_endpoint_admin_session = (ushort)int_value_3;
      }
    }

    if (config_lookup_string(&cfg, "response_allowed_compression", &str_value) == CONFIG_TRUE && !o_strnullempty(str_value)) {
      if (split_string(str_value, ",", &splitted)) {
        if (!string_array_has_value((const char **)splitted, "deflate")) {
          config->allow_deflate = 0;
        }
        if (!string_array_has_value((const char **)splitted, "gzip")) {
          config->allow_gzip = 0;
        }
        free_string_array(splitted);
      } else {
        fprintf(stderr, "Error split_string, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    if (config_lookup_string(&cfg, "admin_session_authentication", &str_value) == CONFIG_TRUE && !o_strnullempty(str_value)) {
      config->admin_session_authentication = GLEWLWYD_SESSION_AUTH_NONE;
      if (split_string(str_value, ",", &splitted)) {
        if (string_array_has_value((const char **)splitted, "cookie")) {
          config->admin_session_authentication |= GLEWLWYD_SESSION_AUTH_COOKIE;
        }
        if (string_array_has_value((const char **)splitted, "api_key")) {
          config->admin_session_authentication |= GLEWLWYD_SESSION_AUTH_API_KEY;
        }
        free_string_array(splitted);
      } else {
        fprintf(stderr, "Error split_string, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    if (config_lookup_string(&cfg, "profile_session_authentication", &str_value) == CONFIG_TRUE && !o_strnullempty(str_value)) {
      config->profile_session_authentication = GLEWLWYD_SESSION_AUTH_NONE;
      if (split_string(str_value, ",", &splitted)) {
        if (string_array_has_value((const char **)splitted, "cookie")) {
          config->profile_session_authentication |= GLEWLWYD_SESSION_AUTH_COOKIE;
        }
        free_string_array(splitted);
      } else {
        fprintf(stderr, "Error split_string, exiting\n");
        ret = G_ERROR_PARAM;
        break;
      }
    }

    if (config_lookup_bool(&cfg, "login_api_enabled", &int_value) == CONFIG_TRUE) {
      config->login_api_enabled = (ushort)int_value;
    }

    if (config_lookup_bool(&cfg, "allow_multiple_user_per_session", &int_value) == CONFIG_TRUE) {
      config->allow_multiple_user_per_session = (uint)int_value;
    }

    if (config_lookup_string(&cfg, "user_backend_api_run_enabled", &str_value) == CONFIG_TRUE && !o_strnullempty(str_value)) {
      o_free(config->user_backend_api_run_enabled);
      config->user_backend_api_run_enabled = o_strdup(str_value);
    }

    if (config_lookup_string(&cfg, "user_middleware_backend_api_run_enabled", &str_value) == CONFIG_TRUE && !o_strnullempty(str_value)) {
      o_free(config->user_middleware_backend_api_run_enabled);
      config->user_middleware_backend_api_run_enabled = o_strdup(str_value);
    }

    if (config_lookup_string(&cfg, "client_backend_api_run_enabled", &str_value) == CONFIG_TRUE && !o_strnullempty(str_value)) {
      o_free(config->client_backend_api_run_enabled);
      config->client_backend_api_run_enabled = o_strdup(str_value);
    }

    if (config_lookup_string(&cfg, "scheme_api_run_enabled", &str_value) == CONFIG_TRUE && !o_strnullempty(str_value)) {
      o_free(config->scheme_api_run_enabled);
      config->scheme_api_run_enabled = o_strdup(str_value);
    }

    if (config_lookup_string(&cfg, "plugin_api_run_enabled", &str_value) == CONFIG_TRUE && !o_strnullempty(str_value)) {
      o_free(config->plugin_api_run_enabled);
      config->plugin_api_run_enabled = o_strdup(str_value);
    }

  } while (0);
  config_destroy(&cfg);
  return ret;
}

/**
 * Initialize the application configuration based on the environment variables
 */
int build_config_from_env(struct config_elements * config) {
  char * value = NULL, * value2 = NULL, * endptr = NULL, * one_log_mode = NULL, ** splitted = NULL;
  long int lvalue;
  int ret = G_OK;
  json_t * j_mime_types, * j_element;
  size_t index;

  if (!config->port && (value = getenv(GLEWLWYD_ENV_PORT)) != NULL && !o_strnullempty(value)) {
    endptr = NULL;
    lvalue = strtol(value, &endptr, 10);
    if (!(*endptr) && lvalue > 0 && lvalue < 65535) {
      config->port = (uint)lvalue;
    } else {
      fprintf(stderr, "Error invalid port number (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_MAX_POST_SIZE)) != NULL && !o_strnullempty(value)) {
    endptr = NULL;
    lvalue = strtol(value, &endptr, 10);
    if (!(*endptr) && lvalue > 0) {
      config->max_post_size = (size_t)lvalue;
    } else {
      fprintf(stderr, "Error invalid max_post_size number (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_RESPONSE_BODY_LIMIT)) != NULL && !o_strnullempty(value)) {
    endptr = NULL;
    lvalue = strtol(value, &endptr, 10);
    if (!(*endptr) && lvalue >= 0) {
      config->response_body_limit = (size_t)lvalue;
    } else {
      fprintf(stderr, "Error invalid response_body_limit number (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_MAX_HEADER)) != NULL && !o_strnullempty(value)) {
    endptr = NULL;
    lvalue = strtol(value, &endptr, 10);
    if (!(*endptr) && lvalue >= 0) {
      config->max_header = (size_t)lvalue;
    } else {
      fprintf(stderr, "Error invalid max_header number (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_BIND_ADDRESS)) != NULL && !o_strnullempty(value)) {
    o_free(config->bind_address);
    config->bind_address = o_strdup(value);
    if (config->bind_address == NULL) {
      fprintf(stderr, "Error allocating config->bind_address (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_API_PREFIX)) != NULL && !o_strnullempty(value)) {
    o_free(config->api_prefix);
    config->api_prefix = o_strdup(value);
    if (config->api_prefix == NULL) {
      fprintf(stderr, "Error allocating config->api_prefix (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_EXTERNAL_URL)) != NULL && !o_strnullempty(value)) {
    o_free(config->external_url);
    config->external_url = o_strdup(value);
    if (config->external_url == NULL) {
      fprintf(stderr, "Error allocating config->external_url (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_LOGIN_URL)) != NULL && !o_strnullempty(value)) {
    o_free(config->login_url);
    config->login_url = o_strdup(value);
    if (config->login_url == NULL) {
      fprintf(stderr, "Error allocating config->login_url (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_PROFILE_DELETE)) != NULL && !o_strnullempty(value)) {
    if (0 == o_strcmp("no", value)) {
      config->delete_profile = GLEWLWYD_PROFILE_DELETE_UNAUTHORIZED;
    } else if (0 == o_strcmp("delete", value)) {
      config->delete_profile = GLEWLWYD_PROFILE_DELETE_AUTHORIZED;
    } else if (0 == o_strcmp("disable", value)) {
      config->delete_profile = GLEWLWYD_PROFILE_DELETE_AUTHORIZED | GLEWLWYD_PROFILE_DELETE_DISABLE_PROFILE;
    } else {
      fprintf(stderr, "Invalid value for " GLEWLWYD_ENV_PROFILE_DELETE ", expected 'no', 'delete' or 'disable' (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_STATIC_FILES_PATH)) != NULL && !o_strnullempty(value)) {
    o_free(config->static_file_config->files_path);
    config->static_file_config->files_path = o_strdup(value);
    if (config->static_file_config->files_path == NULL) {
      fprintf(stderr, "Error allocating config->files_path (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_STATIC_FILES_MIME_TYPES)) != NULL && !o_strnullempty(value)) {
    j_mime_types = json_loads(value, JSON_DECODE_ANY, NULL);
    if (json_is_array(j_mime_types)) {
      json_array_foreach(j_mime_types, index, j_element) {
        if (!json_string_null_or_empty(json_object_get(j_element, "extension")) && json_string_length(json_object_get(j_element, "mime_type"))) {
          u_map_put(&config->static_file_config->mime_types, json_string_value(json_object_get(j_element, "extension")), json_string_value(json_object_get(j_element, "mime_type")));
          if (json_object_get(j_element, "compress") == json_true()) {
            if (u_add_mime_types_compressed(config->static_file_config, json_string_value(json_object_get(j_element, "mime_type"))) != U_OK) {
              fprintf(stderr, "Error setting mime_type %s to compressed list (env), exiting\n", json_string_value(json_object_get(j_element, "mime_type")));
              ret = G_ERROR_PARAM;
              break;
            }
          }
        } else {
          fprintf(stderr, "Error - variable "GLEWLWYD_ENV_STATIC_FILES_MIME_TYPES" must be a JSON array, example [{\"extension\":\".html\",\"mime_type\":\"text/html\"}] (env), exiting\n");
          ret = G_ERROR_PARAM;
          break;
        }
      }
    } else {
      fprintf(stderr, "Error - variable "GLEWLWYD_ENV_STATIC_FILES_MIME_TYPES" must be a JSON array, example [{\"extension\":\".html\",\"mime_type\":\"text/html\"}] (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
    json_decref(j_mime_types);
  }

  if ((value = getenv(GLEWLWYD_ENV_ALLOW_ORIGIN)) != NULL && !o_strnullempty(value)) {
    o_free(config->allow_origin);
    config->allow_origin = o_strdup(value);
    if (config->allow_origin == NULL) {
      fprintf(stderr, "Error allocating config->allow_origin (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_ALLOW_METHODS)) != NULL && !o_strnullempty(value)) {
    o_free(config->allow_methods);
    config->allow_methods = o_strdup(value);
    if (config->allow_methods == NULL) {
      fprintf(stderr, "Error allocating config->allow_methods (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_ALLOW_HEADERS)) != NULL && !o_strnullempty(value)) {
    o_free(config->allow_headers);
    config->allow_headers = o_strdup(value);
    if (config->allow_headers == NULL) {
      fprintf(stderr, "Error allocating config->allow_headers (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_EXPOSE_HEADERS)) != NULL && !o_strnullempty(value)) {
    o_free(config->expose_headers);
    config->expose_headers = o_strdup(value);
    if (config->expose_headers == NULL) {
      fprintf(stderr, "Error allocating config->expose_headers (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_ORIGINATING_IP_HEADER)) != NULL && !o_strnullempty(value)) {
    o_free(config->originating_ip_header);
    config->originating_ip_header = o_strdup(value);
    if (config->originating_ip_header == NULL) {
      fprintf(stderr, "Error allocating config->originating_ip_header (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if (!config->log_mode_args && (value = getenv(GLEWLWYD_ENV_LOG_MODE)) != NULL && !o_strnullempty(value)) {
    config->log_mode = Y_LOG_MODE_NONE;
    one_log_mode = strtok((char *)value, ",");
    while (one_log_mode != NULL && ret == G_OK) {
      if (0 == o_strcmp("console", one_log_mode)) {
        config->log_mode |= Y_LOG_MODE_CONSOLE;
      } else if (0 == o_strcmp("syslog", one_log_mode)) {
        config->log_mode |= Y_LOG_MODE_SYSLOG;
      } else if (0 == o_strcmp("journald", one_log_mode)) {
        config->log_mode |= Y_LOG_MODE_JOURNALD;
      } else if (0 == o_strcmp("file", one_log_mode)) {
        config->log_mode |= Y_LOG_MODE_FILE;
        // Get log file path
        if ((value2 = getenv(GLEWLWYD_ENV_LOG_FILE)) != NULL && !o_strnullempty(value2)) {
          o_free(config->log_file);
          config->log_file = o_strdup(value2);
          if (config->log_file == NULL) {
            fprintf(stderr, "Error allocating config->log_file (env), exiting\n");
            ret = G_ERROR_PARAM;
          }
        }
      } else {
        fprintf(stderr, "Error - logging mode '%s' unknown (env), exiting\n", one_log_mode);
        ret = G_ERROR_PARAM;
      }
      one_log_mode = strtok(NULL, ",");
    }
  }

  if (!config->log_level_args && (value = getenv(GLEWLWYD_ENV_LOG_LEVEL)) != NULL && !o_strnullempty(value)) {
    if (0 == o_strcmp("NONE", value)) {
      config->log_level = Y_LOG_LEVEL_NONE;
    } else if (0 == o_strcmp("ERROR", value)) {
      config->log_level = Y_LOG_LEVEL_ERROR;
    } else if (0 == o_strcmp("WARNING", value)) {
      config->log_level = Y_LOG_LEVEL_WARNING;
    } else if (0 == o_strcmp("INFO", value)) {
      config->log_level = Y_LOG_LEVEL_INFO;
    } else if (0 == o_strcmp("DEBUG", value)) {
      config->log_level = Y_LOG_LEVEL_DEBUG;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_COOKIE_DOMAIN)) != NULL && !o_strnullempty(value)) {
    config->cookie_domain = o_strdup(value);
    if (config->cookie_domain == NULL) {
      fprintf(stderr, "Error allocating config->cookie_domain (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_COOKIE_SAME_SITE)) != NULL && !o_strnullempty(value)) {
    if (0 == o_strcasecmp("empty", value)) {
      config->cookie_same_site = U_COOKIE_SAME_SITE_EMPTY;
    } else if (0 == o_strcasecmp("none", value)) {
      config->cookie_same_site = U_COOKIE_SAME_SITE_NONE;
    } else if (0 == o_strcasecmp("lax", value)) {
      config->cookie_same_site = U_COOKIE_SAME_SITE_LAX;
    } else if (0 == o_strcasecmp("strict", value)) {
      config->cookie_same_site = U_COOKIE_SAME_SITE_STRICT;
    } else {
      fprintf(stderr, "Error invalid cookie_same_site, exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_COOKIE_SECURE)) != NULL) {
    config->cookie_secure = (uint)(o_strcmp(value, "1")==0);
  }

  if ((value = getenv(GLEWLWYD_ENV_MULTIPLE_USER_SESSION)) != NULL) {
    config->allow_multiple_user_per_session = (uint)(o_strcmp(value, "1")==0);
  }

  if ((value = getenv(GLEWLWYD_ENV_ADD_X_FRAME_DENY)) != NULL) {
    config->add_x_frame_option_header_deny = (uint)(o_strcmp(value, "1")==0);
  }

  if ((value = getenv(GLEWLWYD_ENV_SESSION_EXPIRATION)) != NULL && !o_strnullempty(value)) {
    endptr = NULL;
    lvalue = strtol(value, &endptr, 10);
    if (!(*endptr) && lvalue > 0) {
      config->session_expiration = (uint)lvalue;
    } else {
      fprintf(stderr, "Error invalid session_expiration number (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_SESSION_KEY)) != NULL && !o_strnullempty(value)) {
    o_free(config->session_key);
    config->session_key = o_strdup(value);
    if (config->session_key == NULL) {
      fprintf(stderr, "Error allocating config->session_key (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_ADMIN_SCOPE)) != NULL && !o_strnullempty(value)) {
    o_free(config->admin_scope);
    config->admin_scope = o_strdup(value);
    if (config->admin_scope == NULL) {
      fprintf(stderr, "Error allocating config->admin_scope (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_PROFILE_SCOPE)) != NULL && !o_strnullempty(value)) {
    o_free(config->profile_scope);
    config->profile_scope = o_strdup(value);
    if (config->profile_scope == NULL) {
      fprintf(stderr, "Error allocating config->profile_scope (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_USER_MODULE_PATH)) != NULL && !o_strnullempty(value)) {
    o_free(config->user_module_path);
    config->user_module_path = o_strdup(value);
    if (config->user_module_path == NULL) {
      fprintf(stderr, "Error allocating config->user_module_path (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_USER_MIDDLEWARE_MODULE_PATH)) != NULL && !o_strnullempty(value)) {
    o_free(config->user_middleware_module_path);
    config->user_middleware_module_path = o_strdup(value);
    if (config->user_middleware_module_path == NULL) {
      fprintf(stderr, "Error allocating config->user_middleware_module_path (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_CLIENT_MODULE_PATH)) != NULL && !o_strnullempty(value)) {
    o_free(config->client_module_path);
    config->client_module_path = o_strdup(value);
    if (config->client_module_path == NULL) {
      fprintf(stderr, "Error allocating config->client_module_path (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_AUTH_SCHEME_MODULE_PATH)) != NULL && !o_strnullempty(value)) {
    o_free(config->user_auth_scheme_module_path);
    config->user_auth_scheme_module_path = o_strdup(value);
    if (config->user_auth_scheme_module_path == NULL) {
      fprintf(stderr, "Error allocating config->user_auth_scheme_module_path (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_PLUGIN_MODULE_PATH)) != NULL && !o_strnullempty(value)) {
    o_free(config->plugin_module_path);
    config->plugin_module_path = o_strdup(value);
    if (config->plugin_module_path == NULL) {
      fprintf(stderr, "Error allocating config->plugin_module_path (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_USE_SECURE_CONNECTION)) != NULL) {
    config->use_secure_connection = (uint)(o_strcmp(value, "1")==0);
  }

  if ((value = getenv(GLEWLWYD_ENV_SECURE_CONNECTION_KEY_FILE)) != NULL && !o_strnullempty(value)) {
    o_free(config->secure_connection_key_file);
    config->secure_connection_key_file = o_strdup(value);
    if (config->secure_connection_key_file == NULL) {
      fprintf(stderr, "Error allocating config->secure_connection_key_file (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_SECURE_CONNECTION_PEM_FILE)) != NULL && !o_strnullempty(value)) {
    o_free(config->secure_connection_pem_file);
    config->secure_connection_pem_file = o_strdup(value);
    if (config->secure_connection_pem_file == NULL) {
      fprintf(stderr, "Error allocating config->secure_connection_pem_file (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_SECURE_CONNECTION_CA_FILE)) != NULL && !o_strnullempty(value)) {
    o_free(config->secure_connection_ca_file);
    config->secure_connection_ca_file = o_strdup(value);
    if (config->secure_connection_ca_file == NULL) {
      fprintf(stderr, "Error allocating config->secure_connection_ca_file (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_HASH_ALGORITHM)) != NULL && !o_strnullempty(value)) {
    if (!o_strcmp("SHA1", value)) {
      config->hash_algorithm = digest_SHA1;
    } else if (!o_strcmp("SHA256", value)) {
      config->hash_algorithm = digest_SHA256;
    } else if (!o_strcmp("SHA512", value)) {
      config->hash_algorithm = digest_SHA512;
    } else {
      fprintf(stderr, "Error token hash algorithm: %s (env), exiting\n", value);
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_DATABASE_TYPE)) != NULL && !o_strnullempty(value)) {
    if (config->conn != NULL) {
      h_close_db(config->conn);
      h_clean_connection(config->conn);
    }
    if (0 == o_strcmp(value, "sqlite3")) {
      if ((config->conn = h_connect_sqlite(getenv(GLEWLWYD_ENV_DATABASE_SQLITE3_PATH))) == NULL) {
        fprintf(stderr, "Error opening sqlite database '%s' (env), exiting\n", getenv(GLEWLWYD_ENV_DATABASE_SQLITE3_PATH));
        ret = G_ERROR_PARAM;
      } else {
        if (h_execute_query_sqlite(config->conn, "PRAGMA foreign_keys = ON;") != H_OK) {
          fprintf(stderr, "Error executing sqlite3 query 'PRAGMA foreign_keys = ON; (env), exiting'\n");
          ret = G_ERROR_PARAM;
        }
      }
    } else if (0 == o_strcmp(value, "mariadb")) {
      lvalue = strtol(getenv(GLEWLWYD_ENV_DATABASE_MARIADB_PORT), &endptr, 10);
      if (!(*endptr) && lvalue > 0 && lvalue < 65535) {
        if ((config->conn = h_connect_mariadb(getenv(GLEWLWYD_ENV_DATABASE_MARIADB_HOST), getenv(GLEWLWYD_ENV_DATABASE_MARIADB_USER), getenv(GLEWLWYD_ENV_DATABASE_MARIADB_PASSWORD), getenv(GLEWLWYD_ENV_DATABASE_MARIADB_DBNAME), (unsigned int)lvalue, NULL)) == NULL) {
          fprintf(stderr, "Error opening mariadb database '%s'\n", getenv(GLEWLWYD_ENV_DATABASE_MARIADB_DBNAME));
          ret = G_ERROR_PARAM;
        } else {
          if (h_execute_query_mariadb(config->conn, "SET sql_mode='PIPES_AS_CONCAT';", NULL) != H_OK) {
            fprintf(stderr, "Error executing mariadb query 'SET sql_mode='PIPES_AS_CONCAT'; (env), exiting'\n");
            ret = G_ERROR_PARAM;
          }
        }
      }
    } else if (0 == o_strcmp(value, "postgre")) {
      if ((config->conn = h_connect_pgsql(getenv(GLEWLWYD_ENV_DATABASE_POSTGRE_CONNINFO))) == NULL) {
        fprintf(stderr, "Error opening postgre database %s (env), exiting\n", getenv(GLEWLWYD_ENV_DATABASE_POSTGRE_CONNINFO));
        ret = G_ERROR_PARAM;
      }
    } else {
      fprintf(stderr, "Error - database type unknown (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_METRICS)) != NULL) {
    config->metrics_endpoint = (ushort)(o_strcmp(value, "1")==0);
  }

  if ((value = getenv(GLEWLWYD_ENV_METRICS_PORT)) != NULL) {
    config->metrics_endpoint_port = (uint)(o_strcmp(value, "1")==0);
  }

  if ((value = getenv(GLEWLWYD_ENV_METRICS_ADMIN)) != NULL) {
    config->metrics_endpoint_admin_session = (ushort)(o_strcmp(value, "1")==0);
  }

  if ((value = getenv(GLEWLWYD_ENV_METRICS_BIND_ADDRESS)) != NULL && !o_strnullempty(value)) {
    o_free(config->bind_address_metrics);
    config->bind_address_metrics = o_strdup(value);
    if (config->bind_address_metrics == NULL) {
      fprintf(stderr, "Error allocating config->bind_address_metrics (env), exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_RESPONSE_ALLOWED_COMPRESSION)) != NULL && !o_strnullempty(value)) {
    if (split_string(value, ",", &splitted)) {
      if (!string_array_has_value((const char **)splitted, "deflate")) {
        config->allow_deflate = 0;
      }
      if (!string_array_has_value((const char **)splitted, "gzip")) {
        config->allow_gzip = 0;
      }
      free_string_array(splitted);
    } else {
      fprintf(stderr, "Error split_string, exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_ADMIN_SESSION_AUTH)) != NULL && !o_strnullempty(value)) {
    config->admin_session_authentication = GLEWLWYD_SESSION_AUTH_NONE;
    if (split_string(value, ",", &splitted)) {
      if (string_array_has_value((const char **)splitted, "cookie")) {
        config->admin_session_authentication |= GLEWLWYD_SESSION_AUTH_COOKIE;
      }
      if (string_array_has_value((const char **)splitted, "api_key")) {
        config->admin_session_authentication |= GLEWLWYD_SESSION_AUTH_API_KEY;
      }
      free_string_array(splitted);
    } else {
      fprintf(stderr, "Error split_string, exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_PROFILE_SESSION_AUTH)) != NULL && !o_strnullempty(value)) {
    config->profile_session_authentication = GLEWLWYD_SESSION_AUTH_NONE;
    if (split_string(value, ",", &splitted)) {
      if (string_array_has_value((const char **)splitted, "cookie")) {
        config->profile_session_authentication |= GLEWLWYD_SESSION_AUTH_COOKIE;
      }
      free_string_array(splitted);
    } else {
      fprintf(stderr, "Error split_string, exiting\n");
      ret = G_ERROR_PARAM;
    }
  }

  if ((value = getenv(GLEWLWYD_ENV_LOGIN_API_ENABLED)) != NULL) {
    config->login_api_enabled = (uint)(o_strcmp(value, "1")==0);
  }

  if ((value = getenv(GLEWLWYD_ENV_USER_BACKEND_API_RUN_ENABLED)) != NULL && !o_strnullempty(value)) {
    o_free(config->user_backend_api_run_enabled);
    config->user_backend_api_run_enabled = o_strdup(value);
  }

  if ((value = getenv(GLEWLWYD_ENV_USER_MIDDLEWARE_BACKEND_API_RUN_ENABLED)) != NULL && !o_strnullempty(value)) {
    o_free(config->user_middleware_backend_api_run_enabled);
    config->user_middleware_backend_api_run_enabled = o_strdup(value);
  }

  if ((value = getenv(GLEWLWYD_ENV_CLIENT_BACKEND_API_RUN_ENABLED)) != NULL && !o_strnullempty(value)) {
    o_free(config->client_backend_api_run_enabled);
    config->client_backend_api_run_enabled = o_strdup(value);
  }

  if ((value = getenv(GLEWLWYD_ENV_SCHEME_API_RUN_ENABLED)) != NULL && !o_strnullempty(value)) {
    o_free(config->scheme_api_run_enabled);
    config->scheme_api_run_enabled = o_strdup(value);
  }

  if ((value = getenv(GLEWLWYD_ENV_PLUGIN_API_RUN_ENABLED)) != NULL && !o_strnullempty(value)) {
    o_free(config->plugin_api_run_enabled);
    config->plugin_api_run_enabled = o_strdup(value);
  }

  return ret;
}

/**
 * Check if all mandatory configuration parameters are present and correct
 * Initialize some parameters with default value if not set
 */
int check_config(struct config_elements * config) {
  int ret = G_OK;

  if (o_strnullempty(config->external_url)) {
    fprintf(stderr, "Error - configuration external_url mandatory\n");
    ret = G_ERROR_PARAM;
  }

  if (o_strnullempty(config->user_module_path)) {
    fprintf(stderr, "Error - configuration user_module_path mandatory\n");
    ret = G_ERROR_PARAM;
  }

  if (o_strnullempty(config->client_module_path)) {
    fprintf(stderr, "Error - configuration client_module_path mandatory\n");
    ret = G_ERROR_PARAM;
  }

  if (o_strnullempty(config->user_auth_scheme_module_path)) {
    fprintf(stderr, "Error - configuration user_auth_scheme_module_path mandatory\n");
    ret = G_ERROR_PARAM;
  }

  if (o_strnullempty(config->plugin_module_path)) {
    fprintf(stderr, "Error - configuration plugin_module_path mandatory\n");
    ret = G_ERROR_PARAM;
  }

  if (config->conn == NULL) {
    fprintf(stderr, "Error - no database configuration specified\n");
    ret = G_ERROR_PARAM;
  }

  if (!config->port) {
    config->port = GLEWLWYD_DEFAULT_PORT;
  }

  return ret;
}

/**
 * Print help message to output file specified
 */
void print_help(FILE * output) {
  fprintf(output, "\nGlewlwyd Single-Sign-On (SSO) server with multiple factor authentication\n");
  fprintf(output, "\n");
  fprintf(output, "Version %s\n", _GLEWLWYD_VERSION_);
  fprintf(output, "\n");
  fprintf(output, "Copyright 2016-2021 Nicolas Mora <mail@babelouest.org>\n");
  fprintf(output, "\n");
  fprintf(output, "This program is free software; you can redistribute it and/or\n");
  fprintf(output, "modify it under the terms of the GNU GENERAL PUBLIC LICENSE\n");
  fprintf(output, "License as published by the Free Software Foundation;\n");
  fprintf(output, "version 3 of the License.\n");
  fprintf(output, "\n");
  fprintf(output, "Command-line options:\n");
  fprintf(output, "\n");
  fprintf(output, "-c --config-file PATH\n");
  fprintf(output, "\tPath to configuration file\n");
  fprintf(output, "-e --env-variables\n");
  fprintf(output, "\tUse environment variables to configure Glewlwyd\n");
  fprintf(output, "-p --port PORT\n");
  fprintf(output, "\tPort to listen to\n");
  fprintf(output, "-u --url-prefix PREFIX\n");
  fprintf(output, "\tAPI URL prefix\n");
  fprintf(output, "-m --log-mode MODE\n");
  fprintf(output, "\tLog modes available:\n");
  fprintf(output, "\tconsole, syslog or file\n");
  fprintf(output, "\tIf you want multiple modes, separate them with a comma \",\"\n");
  fprintf(output, "\tdefault: console\n");
  fprintf(output, "-l --log-level LEVEL\n");
  fprintf(output, "\tLog levels available:\n");
  fprintf(output, "\tNONE, ERROR, WARNING, INFO, DEBUG\n");
  fprintf(output, "\tdefault: INFO\n");
  fprintf(output, "-f --log-file PATH\n");
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
void * signal_thread(void *arg) {
  sigset_t *sigs = arg;
  int res, signum;

  res = sigwait(sigs, &signum);
  if (res) {
    fprintf(stderr, "Glewlwyd - Waiting for signals failed\n");
    exit(1);
  }
  if (signum == SIGQUIT || signum == SIGINT || signum == SIGTERM || signum == SIGHUP) {
    y_log_message(Y_LOG_LEVEL_INFO, "Glewlwyd - Received close signal: %s", strsignal(signum));
    pthread_mutex_lock(&global_handler_close_lock);
    pthread_cond_signal(&global_handler_close_cond);
    pthread_mutex_unlock(&global_handler_close_lock);
    return NULL;
  } else if (signum == SIGBUS) {
    fprintf(stderr, "Glewlwyd - Received bus error signal\n");
    exit(256-signum);
  } else if (signum == SIGSEGV) {
    fprintf(stderr, "Glewlwyd - Received segmentation fault signal\n");
    exit(256-signum);
  } else if (signum == SIGILL) {
    fprintf(stderr, "Glewlwyd - Received illegal instruction signal\n");
    exit(256-signum);
  } else {
    y_log_message(Y_LOG_LEVEL_WARNING, "Glewlwyd - Received unexpected signal: %s", strsignal(signum));
  }

  return NULL;
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

static int load_user_module_file(struct config_elements * config, const char * file_path) {
  void * file_handle;
  struct _user_module * cur_user_module = NULL;
  int ret;
  json_t * j_parameters;

  file_handle = dlopen(file_path, RTLD_LAZY);

  if (file_handle != NULL) {
    cur_user_module = o_malloc(sizeof(struct _user_module));
    if (cur_user_module != NULL) {
      cur_user_module->name = NULL;
      cur_user_module->file_handle = file_handle;
      cur_user_module->api_version = 0.0;
      *(void **) (&cur_user_module->user_module_load) = dlsym(file_handle, "user_module_load");
      *(void **) (&cur_user_module->user_module_unload) = dlsym(file_handle, "user_module_unload");
      *(void **) (&cur_user_module->user_module_init) = dlsym(file_handle, "user_module_init");
      *(void **) (&cur_user_module->user_module_close) = dlsym(file_handle, "user_module_close");
      *(void **) (&cur_user_module->user_module_count_total) = dlsym(file_handle, "user_module_count_total");
      *(void **) (&cur_user_module->user_module_get_list) = dlsym(file_handle, "user_module_get_list");
      *(void **) (&cur_user_module->user_module_get) = dlsym(file_handle, "user_module_get");
      *(void **) (&cur_user_module->user_module_get_profile) = dlsym(file_handle, "user_module_get_profile");
      *(void **) (&cur_user_module->user_module_is_valid) = dlsym(file_handle, "user_module_is_valid");
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
          cur_user_module->user_module_count_total != NULL &&
          cur_user_module->user_module_get_list != NULL &&
          cur_user_module->user_module_get != NULL &&
          cur_user_module->user_module_get_profile != NULL &&
          cur_user_module->user_module_is_valid != NULL &&
          cur_user_module->user_module_add != NULL &&
          cur_user_module->user_module_update != NULL &&
          cur_user_module->user_module_update_profile != NULL &&
          cur_user_module->user_module_delete != NULL &&
          cur_user_module->user_module_check_password != NULL &&
          cur_user_module->user_module_update_password != NULL) {
        j_parameters = cur_user_module->user_module_load(config->config_m);
        if (check_result_value(j_parameters, G_OK)) {
          cur_user_module->name = o_strdup(json_string_value(json_object_get(j_parameters, "name")));
          cur_user_module->display_name = o_strdup(json_string_value(json_object_get(j_parameters, "display_name")));
          cur_user_module->description = o_strdup(json_string_value(json_object_get(j_parameters, "description")));
          cur_user_module->api_version = json_real_value(json_object_get(j_parameters, "api_version"));
          if (!o_strnullempty(cur_user_module->name) && get_user_module_lib(config, cur_user_module->name) == NULL) {
            if (cur_user_module->api_version >= _GLEWLWYD_USER_MODULE_VERSION) {
              if (!pthread_mutex_lock(&config->module_lock)) {
                if (pointer_list_append(config->user_module_list, (void*)cur_user_module)) {
                  y_log_message(Y_LOG_LEVEL_INFO, "Loading user module %s - %s", file_path, cur_user_module->name);
                  ret = G_OK;
                } else {
                  cur_user_module->user_module_unload(config->config_m);
                  dlclose(file_handle);
                  o_free(cur_user_module->name);
                  o_free(cur_user_module->display_name);
                  o_free(cur_user_module->description);
                  o_free(cur_user_module);
                  y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_file - Error pointer_list_append");
                  ret = G_ERROR;
                }
                pthread_mutex_unlock(&config->module_lock);
              } else {
                cur_user_module->user_module_unload(config->config_m);
                dlclose(file_handle);
                o_free(cur_user_module->name);
                o_free(cur_user_module->display_name);
                o_free(cur_user_module->description);
                o_free(cur_user_module);
                y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_file - Error pthread_mutex_lock");
                ret = G_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_file - User module with name '%s' has invalid api_version: %.2f, minimum required: %.2f", cur_user_module->name, cur_user_module->api_version, _GLEWLWYD_USER_MODULE_VERSION);
              cur_user_module->user_module_unload(config->config_m);
              dlclose(file_handle);
              o_free(cur_user_module->name);
              o_free(cur_user_module->display_name);
              o_free(cur_user_module->description);
              o_free(cur_user_module);
              ret = G_ERROR_PARAM;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_file - User module with name '%s' already present or name empty", cur_user_module->name);
            cur_user_module->user_module_unload(config->config_m);
            dlclose(file_handle);
            o_free(cur_user_module->name);
            o_free(cur_user_module->display_name);
            o_free(cur_user_module->description);
            o_free(cur_user_module);
            ret = G_ERROR_PARAM;
          }
        } else {
          dlclose(file_handle);
          o_free(cur_user_module);
          y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_file - Error user_module_load for module %s", file_path);
          ret = G_ERROR_MEMORY;
        }
        json_decref(j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_file - Error module %s has not all required functions", file_path);
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_load: %s", (cur_user_module->user_module_load != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_unload: %s", (cur_user_module->user_module_unload != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_init: %s", (cur_user_module->user_module_init != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_close: %s", (cur_user_module->user_module_close != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_count_total: %s", (cur_user_module->user_module_count_total != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_get_list: %s", (cur_user_module->user_module_get_list != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_get: %s", (cur_user_module->user_module_get != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_get_profile: %s", (cur_user_module->user_module_get_profile != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_is_valid: %s", (cur_user_module->user_module_is_valid != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_add: %s", (cur_user_module->user_module_add != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_update: %s", (cur_user_module->user_module_update != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_update_profile: %s", (cur_user_module->user_module_update_profile != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_delete: %s", (cur_user_module->user_module_delete != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_check_password: %s", (cur_user_module->user_module_check_password != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_module_update_password: %s", (cur_user_module->user_module_update_password != NULL?"found":"not found"));
        dlclose(file_handle);
        o_free(cur_user_module);
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_file - Error allocating resources for cur_user_module");
      dlclose(file_handle);
      ret = G_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_file - Error opening module file %s, reason: %s", file_path, dlerror());
    ret = G_ERROR;
  }

  return ret;
}

int init_user_module_list(struct config_elements * config) {
  int ret = G_OK, is_reg;
  DIR * modules_directory;
  struct dirent * in_file;
  char * file_path;
  struct stat u_stat;
  memset(&u_stat, 0, sizeof(struct stat));

  config->user_module_list = o_malloc(sizeof(struct _pointer_list));
  if (config->user_module_list != NULL) {
    pointer_list_init(config->user_module_list);
    // read module_path and load modules
    if (NULL == (modules_directory = opendir(config->user_module_path))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "init_user_module_list - Error reading libraries folder %s", config->user_module_path);
      ret = G_ERROR;
    } else {
      while ((in_file = readdir(modules_directory))) {
        is_reg = 0;
        file_path = NULL;
        if (in_file->d_type == DT_REG) {
          is_reg = 1;
          file_path = msprintf("%s/%s", config->user_module_path, in_file->d_name);
        } else if (in_file->d_type == DT_UNKNOWN) {
          file_path = msprintf("%s/%s", config->user_module_path, in_file->d_name);
          if (!stat(file_path, &u_stat)) {
            if (S_ISREG(u_stat.st_mode)) {
              is_reg = 1;
            }
          }
        }
        if (is_reg) {
          if (load_user_module_file(config, file_path) != G_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "init_user_module_list - Error opening module file %s", file_path);
          }
        }
        o_free(file_path);
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
  json_t * j_query, * j_result, * j_instance, * j_parameters, * j_init;
  int res, ret;
  size_t index, i;
  struct _user_module_instance * cur_instance;
  struct _user_module * module = NULL;
  char * message;

  config->user_module_instance_list = o_malloc(sizeof(struct _pointer_list));
  if (config->user_module_instance_list != NULL) {
    pointer_list_init(config->user_module_instance_list);
    j_query = json_pack("{sss[sssssss]ss}",
                        "table",
                        GLEWLWYD_TABLE_USER_MODULE_INSTANCE,
                        "columns",
                          "gumi_module AS module",
                          "gumi_name AS name",
                          "gumi_order AS order_by",
                          "gumi_parameters AS parameters",
                          "gumi_readonly AS readonly",
                          "gumi_multiple_passwords AS multiple_passwords",
                          "gumi_enabled AS enabled",
                        "order_by",
                        "gumi_order");
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (!pthread_mutex_lock(&config->module_lock)) {
        ret = G_OK;
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
              cur_instance->readonly = (short int)json_integer_value(json_object_get(j_instance, "readonly"));
              cur_instance->multiple_passwords = (short int)json_integer_value(json_object_get(j_instance, "multiple_passwords"));
              cur_instance->enabled = 0;
              if (pointer_list_append(config->user_module_instance_list, cur_instance)) {
                if ((res = is_user_backend_api_run_enabled(config, cur_instance->name)) == G_OK) {
                  if (json_integer_value(json_object_get(j_instance, "enabled"))) {
                    j_parameters = json_loads(json_string_value(json_object_get(j_instance, "parameters")), JSON_DECODE_ANY, NULL);
                    if (j_parameters != NULL) {
                      j_init = module->user_module_init(config->config_m, cur_instance->readonly, cur_instance->multiple_passwords, j_parameters, &cur_instance->cls);
                      if (check_result_value(j_init, G_OK)) {
                        cur_instance->enabled = 1;
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error init module %s/%s", module->name, json_string_value(json_object_get(j_instance, "name")));
                        message = json_dumps(j_init, JSON_INDENT(2));
                        y_log_message(Y_LOG_LEVEL_DEBUG, message);
                        o_free(message);
                      }
                      json_decref(j_init);
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error parsing module parameters %s/%s: %s", module->name, json_string_value(json_object_get(j_instance, "name")), json_string_value(json_object_get(j_instance, "parameters")));
                    }
                    json_decref(j_parameters);
                  } else {
                  }
                } else if (res != G_ERROR_NOT_FOUND) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error is_user_backend_api_run_enabled");
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error reallocating resources for user_module_instance_list");
                o_free(cur_instance->name);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error allocating resources for cur_instance");
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error module %s not found", json_string_value(json_object_get(j_instance, "module")));
          }
        }
        json_decref(j_result);
        pthread_mutex_unlock(&config->module_lock);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error pthread_mutex_lock");
        ret = G_ERROR;
      }
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
  size_t i;
  struct _user_module_instance * cur_instance;

  for (i=0; i<pointer_list_size(config->user_module_instance_list); i++) {
    cur_instance = (struct _user_module_instance *)pointer_list_get_at(config->user_module_instance_list, i);
    if (cur_instance != NULL && 0 == o_strcmp(cur_instance->name, name)) {
      return cur_instance;
    }
  }
  return NULL;
}

struct _user_module * get_user_module_lib(struct config_elements * config, const char * name) {
  size_t i;
  struct _user_module * module;

  for (i=0; i<pointer_list_size(config->user_module_list); i++) {
    module = (struct _user_module *)pointer_list_get_at(config->user_module_list, i);
    if (module != NULL && 0 == o_strcmp(module->name, name)) {
      return module;
    }
  }
  return NULL;
}

void close_user_module_instance_list(struct config_elements * config) {
  size_t i;
  int res;

  if (!pthread_mutex_lock(&config->module_lock)) {
    for (i=0; i<pointer_list_size(config->user_module_instance_list); i++) {
      struct _user_module_instance * instance = (struct _user_module_instance *)pointer_list_get_at(config->user_module_instance_list, i);
      if (instance != NULL) {
        if ((res = is_user_backend_api_run_enabled(config, instance->name)) == G_OK) {
          if (instance->enabled && instance->module->user_module_close(config->config_m, instance->cls) != G_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "close_user_module_instance_list - Error user_module_close for instance '%s'/'%s'", instance->module->name, instance->name);
          }
        } else if (res != G_ERROR_NOT_FOUND) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_user_module_instance_list - Error is_user_backend_api_run_enabled");
        }
        o_free(instance->name);
        o_free(instance);
      }
    }
    pointer_list_clean(config->user_module_instance_list);
    o_free(config->user_module_instance_list);
    pthread_mutex_unlock(&config->module_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "close_user_module_instance_list - Error pthread_mutex_lock");
  }
}

void close_user_module_list(struct config_elements * config) {
  size_t i;

  if (!pthread_mutex_lock(&config->module_lock)) {
    for (i=0; i<pointer_list_size(config->user_module_list); i++) {
      struct _user_module * module = (struct _user_module *)pointer_list_get_at(config->user_module_list, i);
      if (module != NULL) {
        if (module->user_module_unload(config->config_m) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_user_module_list - Error user_module_unload for module '%s'", module->name);
        }
  /*
  * dlclose() makes valgrind not useful when it comes to libraries
  * they say it's not relevant to use it anyway
  * I'll let it here until I'm sure
  */
  #ifndef DEBUG
        if (dlclose(module->file_handle)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_user_module_list - Error dlclose for module '%s'", module->name);
        }
  #endif
        o_free(module->name);
        o_free(module->display_name);
        o_free(module->description);
        o_free(module);
      }
    }
    pointer_list_clean(config->user_module_list);
    o_free(config->user_module_list);
    pthread_mutex_unlock(&config->module_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "close_user_module_list - Error pthread_mutex_lock");
  }
}

static int load_user_middleware_module_file(struct config_elements * config, const char * file_path) {
  void * file_handle;
  struct _user_middleware_module * cur_user_middleware_module = NULL;
  int ret;
  json_t * j_parameters;

  file_handle = dlopen(file_path, RTLD_LAZY);

  if (file_handle != NULL) {
    cur_user_middleware_module = o_malloc(sizeof(struct _user_middleware_module));
    if (cur_user_middleware_module != NULL) {
      cur_user_middleware_module->name = NULL;
      cur_user_middleware_module->file_handle = file_handle;
      cur_user_middleware_module->api_version = 0.0;
      *(void **) (&cur_user_middleware_module->user_middleware_module_load) = dlsym(file_handle, "user_middleware_module_load");
      *(void **) (&cur_user_middleware_module->user_middleware_module_unload) = dlsym(file_handle, "user_middleware_module_unload");
      *(void **) (&cur_user_middleware_module->user_middleware_module_init) = dlsym(file_handle, "user_middleware_module_init");
      *(void **) (&cur_user_middleware_module->user_middleware_module_close) = dlsym(file_handle, "user_middleware_module_close");
      *(void **) (&cur_user_middleware_module->user_middleware_module_get_list) = dlsym(file_handle, "user_middleware_module_get_list");
      *(void **) (&cur_user_middleware_module->user_middleware_module_get) = dlsym(file_handle, "user_middleware_module_get");
      *(void **) (&cur_user_middleware_module->user_middleware_module_get_profile) = dlsym(file_handle, "user_middleware_module_get_profile");
      *(void **) (&cur_user_middleware_module->user_middleware_module_update) = dlsym(file_handle, "user_middleware_module_update");
      *(void **) (&cur_user_middleware_module->user_middleware_module_delete) = dlsym(file_handle, "user_middleware_module_delete");

      if (cur_user_middleware_module->user_middleware_module_load != NULL &&
          cur_user_middleware_module->user_middleware_module_unload != NULL &&
          cur_user_middleware_module->user_middleware_module_init != NULL &&
          cur_user_middleware_module->user_middleware_module_close != NULL &&
          cur_user_middleware_module->user_middleware_module_get_list != NULL &&
          cur_user_middleware_module->user_middleware_module_get != NULL &&
          cur_user_middleware_module->user_middleware_module_get_profile != NULL &&
          cur_user_middleware_module->user_middleware_module_update != NULL &&
          cur_user_middleware_module->user_middleware_module_delete != NULL) {
        j_parameters = cur_user_middleware_module->user_middleware_module_load(config->config_m);
        if (check_result_value(j_parameters, G_OK)) {
          cur_user_middleware_module->name = o_strdup(json_string_value(json_object_get(j_parameters, "name")));
          cur_user_middleware_module->display_name = o_strdup(json_string_value(json_object_get(j_parameters, "display_name")));
          cur_user_middleware_module->description = o_strdup(json_string_value(json_object_get(j_parameters, "description")));
          cur_user_middleware_module->api_version = json_real_value(json_object_get(j_parameters, "api_version"));
          if (!o_strnullempty(cur_user_middleware_module->name) && get_user_middleware_module_lib(config, cur_user_middleware_module->name) == NULL) {
            if (cur_user_middleware_module->api_version >= _GLEWLWYD_USER_MODULE_VERSION) {
              if (!pthread_mutex_lock(&config->module_lock)) {
                if (pointer_list_append(config->user_middleware_module_list, (void*)cur_user_middleware_module)) {
                  y_log_message(Y_LOG_LEVEL_INFO, "Loading user middleware module %s - %s", file_path, cur_user_middleware_module->name);
                  ret = G_OK;
                } else {
                  cur_user_middleware_module->user_middleware_module_unload(config->config_m);
                  dlclose(file_handle);
                  o_free(cur_user_middleware_module->name);
                  o_free(cur_user_middleware_module->display_name);
                  o_free(cur_user_middleware_module->description);
                  o_free(cur_user_middleware_module);
                  y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_file - Error pointer_list_append");
                  ret = G_ERROR;
                }
                pthread_mutex_unlock(&config->module_lock);
              } else {
                cur_user_middleware_module->user_middleware_module_unload(config->config_m);
                dlclose(file_handle);
                o_free(cur_user_middleware_module->name);
                o_free(cur_user_middleware_module->display_name);
                o_free(cur_user_middleware_module->description);
                o_free(cur_user_middleware_module);
                y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_file - Error pthread_mutex_lock");
                ret = G_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_file - User module with name '%s' has invalid api_version: %.2f, minimum required: %.2f", cur_user_middleware_module->name, cur_user_middleware_module->api_version, _GLEWLWYD_USER_MODULE_VERSION);
              cur_user_middleware_module->user_middleware_module_unload(config->config_m);
              dlclose(file_handle);
              o_free(cur_user_middleware_module->name);
              o_free(cur_user_middleware_module->display_name);
              o_free(cur_user_middleware_module->description);
              o_free(cur_user_middleware_module);
              ret = G_ERROR_PARAM;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_file - User module with name '%s' already present or name empty", cur_user_middleware_module->name);
            cur_user_middleware_module->user_middleware_module_unload(config->config_m);
            dlclose(file_handle);
            o_free(cur_user_middleware_module->name);
            o_free(cur_user_middleware_module->display_name);
            o_free(cur_user_middleware_module->description);
            o_free(cur_user_middleware_module);
            ret = G_ERROR_PARAM;
          }
        } else {
          dlclose(file_handle);
          o_free(cur_user_middleware_module);
          y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_file - Error user_middleware_module_load for module %s", file_path);
          ret = G_ERROR_MEMORY;
        }
        json_decref(j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_file - Error module %s has not all required functions", file_path);
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_middleware_module_load: %s", (cur_user_middleware_module->user_middleware_module_load != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_middleware_module_unload: %s", (cur_user_middleware_module->user_middleware_module_unload != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_middleware_module_init: %s", (cur_user_middleware_module->user_middleware_module_init != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_middleware_module_close: %s", (cur_user_middleware_module->user_middleware_module_close != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_middleware_module_get_list: %s", (cur_user_middleware_module->user_middleware_module_get_list != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_middleware_module_get: %s", (cur_user_middleware_module->user_middleware_module_get != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_middleware_module_get_profile: %s", (cur_user_middleware_module->user_middleware_module_get_profile != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_middleware_module_update: %s", (cur_user_middleware_module->user_middleware_module_update != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_middleware_module_delete: %s", (cur_user_middleware_module->user_middleware_module_delete != NULL?"found":"not found"));
        dlclose(file_handle);
        o_free(cur_user_middleware_module);
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_file - Error allocating resources for cur_user_middleware_module");
      dlclose(file_handle);
      ret = G_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_file - Error opening module file %s, reason: %s", file_path, dlerror());
    ret = G_ERROR;
  }

  return ret;
}

int init_user_middleware_module_list(struct config_elements * config) {
  int ret = G_OK, is_reg;
  DIR * modules_directory;
  struct dirent * in_file;
  char * file_path;
  struct stat u_stat;
  memset(&u_stat, 0, sizeof(struct stat));

  config->user_middleware_module_list = o_malloc(sizeof(struct _pointer_list));
  if (config->user_middleware_module_list != NULL) {
    pointer_list_init(config->user_middleware_module_list);
    if (!o_strnullempty(config->user_middleware_module_path)) {
      // read module_path and load modules
      if (NULL == (modules_directory = opendir(config->user_middleware_module_path))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "init_user_middleware_module_list - Error reading libraries folder %s", config->user_middleware_module_path);
      } else {
        while ((in_file = readdir(modules_directory))) {
          is_reg = 0;
          file_path = NULL;
          if (in_file->d_type == DT_REG) {
            is_reg = 1;
            file_path = msprintf("%s/%s", config->user_middleware_module_path, in_file->d_name);
          } else if (in_file->d_type == DT_UNKNOWN) {
            file_path = msprintf("%s/%s", config->user_middleware_module_path, in_file->d_name);
            if (!stat(file_path, &u_stat)) {
              if (S_ISREG(u_stat.st_mode)) {
                is_reg = 1;
              }
            }
          }
          if (is_reg) {
            if (load_user_middleware_module_file(config, file_path) != G_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "init_user_middleware_module_list - Error opening module file %s", file_path);
            }
          }
          o_free(file_path);
        }
        closedir(modules_directory);
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "init_user_middleware_module_list - Error allocating resources for config->user_middleware_module_list");
    ret = G_ERROR_MEMORY;
  }

  return ret;
}

int load_user_middleware_module_instance_list(struct config_elements * config) {
  json_t * j_query, * j_result, * j_instance, * j_parameters, * j_init;
  int res, ret;
  size_t index, i;
  struct _user_middleware_module_instance * cur_instance;
  struct _user_middleware_module * module = NULL;
  char * message;

  config->user_middleware_module_instance_list = o_malloc(sizeof(struct _pointer_list));
  if (config->user_middleware_module_instance_list != NULL) {
    pointer_list_init(config->user_middleware_module_instance_list);
    if (!o_strnullempty(config->user_middleware_module_path)) {
      j_query = json_pack("{sss[sssss]ss}",
                          "table",
                          GLEWLWYD_TABLE_USER_MIDDLEWARE_MODULE_INSTANCE,
                          "columns",
                            "gummi_module AS module",
                            "gummi_name AS name",
                            "gummi_order AS order_by",
                            "gummi_parameters AS parameters",
                            "gummi_enabled AS enabled",
                          "order_by",
                          "gummi_order");
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        ret = G_OK;
        if (!pthread_mutex_lock(&config->module_lock)) {
          json_array_foreach(j_result, index, j_instance) {
            module = NULL;
            for (i=0; i<pointer_list_size(config->user_middleware_module_list); i++) {
              module = (struct _user_middleware_module *)pointer_list_get_at(config->user_middleware_module_list, i);
              if (0 == o_strcmp(module->name, json_string_value(json_object_get(j_instance, "module")))) {
                break;
              } else {
                module = NULL;
              }
            }
            if (module != NULL) {
              cur_instance = o_malloc(sizeof(struct _user_middleware_module_instance));
              if (cur_instance != NULL) {
                cur_instance->cls = NULL;
                cur_instance->name = o_strdup(json_string_value(json_object_get(j_instance, "name")));
                cur_instance->module = module;
                cur_instance->enabled = 0;
                if (pointer_list_append(config->user_middleware_module_instance_list, cur_instance)) {
                  if ((res = is_user_middleware_backend_api_run_enabled(config, cur_instance->name)) == G_OK) {
                    if (json_integer_value(json_object_get(j_instance, "enabled"))) {
                      j_parameters = json_loads(json_string_value(json_object_get(j_instance, "parameters")), JSON_DECODE_ANY, NULL);
                      if (j_parameters != NULL) {
                        j_init = module->user_middleware_module_init(config->config_m, j_parameters, &cur_instance->cls);
                        if (check_result_value(j_init, G_OK)) {
                          cur_instance->enabled = 1;
                        } else {
                          y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_instance_list - Error init module %s/%s", module->name, json_string_value(json_object_get(j_instance, "name")));
                          message = json_dumps(j_init, JSON_INDENT(2));
                          y_log_message(Y_LOG_LEVEL_DEBUG, message);
                          o_free(message);
                          cur_instance->enabled = 0;
                          ret = G_ERROR_PARAM;
                        }
                        json_decref(j_init);
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_instance_list - Error parsing module parameters %s/%s: %s", module->name, json_string_value(json_object_get(j_instance, "name")), json_string_value(json_object_get(j_instance, "parameters")));
                        cur_instance->enabled = 0;
                      }
                      json_decref(j_parameters);
                    }
                  } else if (res != G_ERROR_NOT_FOUND) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error is_user_middleware_backend_api_run_enabled");
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_instance_list - Error reallocating resources for user_middleware_module_instance_list");
                  o_free(cur_instance->name);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_instance_list - Error allocating resources for cur_instance");
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_instance_list - Error module %s not found", json_string_value(json_object_get(j_instance, "module")));
            }
          }
          json_decref(j_result);
          pthread_mutex_unlock(&config->module_lock);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_instance_list - Error pthread_mutex_lock");
          ret = G_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_instance_list - Error executing j_query");
        ret = G_ERROR_DB;
      }
    } else {
      // Do not return an error for backwards compatibility
      y_log_message(Y_LOG_LEVEL_WARNING, "Warning - user_middleware_module_path missing in config file");
      ret = G_OK;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "load_user_middleware_module_instance_list - Error allocating resource for config->user_middleware_module_instance_list");
    ret = G_ERROR_MEMORY;
  }
  return ret;
}

struct _user_middleware_module_instance * get_user_middleware_module_instance(struct config_elements * config, const char * name) {
  size_t i;
  struct _user_middleware_module_instance * cur_instance;

  for (i=0; i<pointer_list_size(config->user_middleware_module_instance_list); i++) {
    cur_instance = (struct _user_middleware_module_instance *)pointer_list_get_at(config->user_middleware_module_instance_list, i);
    if (cur_instance != NULL && 0 == o_strcmp(cur_instance->name, name)) {
      return cur_instance;
    }
  }
  return NULL;
}

struct _user_middleware_module * get_user_middleware_module_lib(struct config_elements * config, const char * name) {
  size_t i;
  struct _user_middleware_module * module;

  for (i=0; i<pointer_list_size(config->user_middleware_module_list); i++) {
    module = (struct _user_middleware_module *)pointer_list_get_at(config->user_middleware_module_list, i);
    if (module != NULL && 0 == o_strcmp(module->name, name)) {
      return module;
    }
  }
  return NULL;
}

void close_user_middleware_module_instance_list(struct config_elements * config) {
  size_t i;
  int res;

  if (!pthread_mutex_lock(&config->module_lock)) {
    for (i=0; i<pointer_list_size(config->user_middleware_module_instance_list); i++) {
      struct _user_middleware_module_instance * instance = (struct _user_middleware_module_instance *)pointer_list_get_at(config->user_middleware_module_instance_list, i);
      if (instance != NULL) {
        if ((res = is_user_middleware_backend_api_run_enabled(config, instance->name)) == G_OK) {
          if (instance->enabled && instance->module->user_middleware_module_close(config->config_m, instance->cls) != G_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "close_user_middleware_module_instance_list - Error user_middleware_module_close for instance '%s'/'%s'", instance->module->name, instance->name);
          }
        } else if (res != G_ERROR_NOT_FOUND) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_user_middleware_module_instance_list - Error is_user_middleware_backend_api_run_enabled");
        }
        o_free(instance->name);
        o_free(instance);
      }
    }
    pointer_list_clean(config->user_middleware_module_instance_list);
    o_free(config->user_middleware_module_instance_list);
    pthread_mutex_unlock(&config->module_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "close_user_middleware_module_instance_list - Error pthread_mutex_lock");
  }
}

void close_user_middleware_module_list(struct config_elements * config) {
  size_t i;

  if (!pthread_mutex_lock(&config->module_lock)) {
    for (i=0; i<pointer_list_size(config->user_middleware_module_list); i++) {
      struct _user_middleware_module * module = (struct _user_middleware_module *)pointer_list_get_at(config->user_middleware_module_list, i);
      if (module != NULL) {
        if (module->user_middleware_module_unload(config->config_m) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_user_middleware_module_list - Error user_middleware_module_unload for module '%s'", module->name);
        }
  /*
  * dlclose() makes valgrind not useful when it comes to libraries
  * they say it's not relevant to use it anyway
  * I'll let it here until I'm sure
  */
  #ifndef DEBUG
        if (dlclose(module->file_handle)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_user_middleware_module_list - Error dlclose for module '%s'", module->name);
        }
  #endif
        o_free(module->name);
        o_free(module->display_name);
        o_free(module->description);
        o_free(module);
      }
    }
    pointer_list_clean(config->user_middleware_module_list);
    o_free(config->user_middleware_module_list);
    pthread_mutex_unlock(&config->module_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "close_user_middleware_module_list - Error pthread_mutex_lock");
  }
}

static int load_user_auth_scheme_module_file(struct config_elements * config, const char * file_path) {
  void * file_handle;
  struct _user_auth_scheme_module * cur_user_auth_scheme_module = NULL;
  int ret;
  json_t * j_module;

  file_handle = dlopen(file_path, RTLD_LAZY);

  if (file_handle != NULL) {
    cur_user_auth_scheme_module = o_malloc(sizeof(struct _user_auth_scheme_module));
    if (cur_user_auth_scheme_module != NULL) {
      cur_user_auth_scheme_module->name = NULL;
      cur_user_auth_scheme_module->file_handle = file_handle;
      cur_user_auth_scheme_module->api_version = 0.0;
      *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_load) = dlsym(file_handle, "user_auth_scheme_module_load");
      *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_unload) = dlsym(file_handle, "user_auth_scheme_module_unload");
      *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_init) = dlsym(file_handle, "user_auth_scheme_module_init");
      *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_close) = dlsym(file_handle, "user_auth_scheme_module_close");
      *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_register) = dlsym(file_handle, "user_auth_scheme_module_register");
      *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_register_get) = dlsym(file_handle, "user_auth_scheme_module_register_get");
      *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_deregister) = dlsym(file_handle, "user_auth_scheme_module_deregister");
      *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_validate) = dlsym(file_handle, "user_auth_scheme_module_validate");
      *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_trigger) = dlsym(file_handle, "user_auth_scheme_module_trigger");
      *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_can_use) = dlsym(file_handle, "user_auth_scheme_module_can_use");
      *(void **) (&cur_user_auth_scheme_module->user_auth_scheme_module_identify) = dlsym(file_handle, "user_auth_scheme_module_identify");

      if (cur_user_auth_scheme_module->user_auth_scheme_module_load != NULL &&
          cur_user_auth_scheme_module->user_auth_scheme_module_unload != NULL &&
          cur_user_auth_scheme_module->user_auth_scheme_module_init != NULL &&
          cur_user_auth_scheme_module->user_auth_scheme_module_close != NULL &&
          cur_user_auth_scheme_module->user_auth_scheme_module_register != NULL &&
          cur_user_auth_scheme_module->user_auth_scheme_module_register_get != NULL &&
          cur_user_auth_scheme_module->user_auth_scheme_module_deregister != NULL &&
          cur_user_auth_scheme_module->user_auth_scheme_module_validate != NULL &&
          cur_user_auth_scheme_module->user_auth_scheme_module_trigger != NULL &&
          cur_user_auth_scheme_module->user_auth_scheme_module_can_use != NULL &&
          cur_user_auth_scheme_module->user_auth_scheme_module_identify != NULL) {
        j_module = cur_user_auth_scheme_module->user_auth_scheme_module_load(config->config_m);
        if (check_result_value(j_module, G_OK)) {
          cur_user_auth_scheme_module->name = o_strdup(json_string_value(json_object_get(j_module, "name")));
          cur_user_auth_scheme_module->display_name = o_strdup(json_string_value(json_object_get(j_module, "display_name")));
          cur_user_auth_scheme_module->description = o_strdup(json_string_value(json_object_get(j_module, "description")));
          cur_user_auth_scheme_module->api_version = json_real_value(json_object_get(j_module, "api_version"));
          if (!o_strnullempty(cur_user_auth_scheme_module->name) && get_user_auth_scheme_module_lib(config, cur_user_auth_scheme_module->name) == NULL) {
            if (!pthread_mutex_lock(&config->module_lock)) {
              if (pointer_list_append(config->user_auth_scheme_module_list, cur_user_auth_scheme_module)) {
                y_log_message(Y_LOG_LEVEL_INFO, "Loading user auth scheme module %s - %s", file_path, cur_user_auth_scheme_module->name);
                ret = G_OK;
              } else {
                cur_user_auth_scheme_module->user_auth_scheme_module_unload(config->config_m);
                dlclose(file_handle);
                o_free(cur_user_auth_scheme_module->name);
                o_free(cur_user_auth_scheme_module->display_name);
                o_free(cur_user_auth_scheme_module->description);
                o_free(cur_user_auth_scheme_module);
                y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_file - Error reallocating resources for user_auth_scheme_module_list");
                ret = G_ERROR_MEMORY;
              }
              pthread_mutex_unlock(&config->module_lock);
            } else {
              cur_user_auth_scheme_module->user_auth_scheme_module_unload(config->config_m);
              dlclose(file_handle);
              o_free(cur_user_auth_scheme_module->name);
              o_free(cur_user_auth_scheme_module->display_name);
              o_free(cur_user_auth_scheme_module->description);
              o_free(cur_user_auth_scheme_module);
              y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_file - Error pthread_mutex_lock");
              ret = G_ERROR_MEMORY;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_file - User auth scheme module with name '%s' already present or name empty", cur_user_auth_scheme_module->name);
            cur_user_auth_scheme_module->user_auth_scheme_module_unload(config->config_m);
            dlclose(file_handle);
            o_free(cur_user_auth_scheme_module->name);
            o_free(cur_user_auth_scheme_module->display_name);
            o_free(cur_user_auth_scheme_module->description);
            o_free(cur_user_auth_scheme_module);
            ret = G_ERROR;
          }
        } else {
          dlclose(file_handle);
          o_free(cur_user_auth_scheme_module);
          y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_file - Error user_auth_scheme_module_load for module %s", file_path);
          ret = G_ERROR_MEMORY;
        }
        json_decref(j_module);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_file - Error module %s has not all required functions", file_path);
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_load: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_load != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_unload: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_unload != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_init: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_init != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_close: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_close != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_register: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_register != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_register_get: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_register_get != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_deregister: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_deregister != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_validate: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_validate != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_trigger: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_trigger != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_can_use: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_can_use != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - user_auth_scheme_module_identify: %s", (cur_user_auth_scheme_module->user_auth_scheme_module_identify != NULL?"found":"not found"));
        dlclose(file_handle);
        o_free(cur_user_auth_scheme_module);
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_file - Error allocating resources for cur_user_auth_scheme_module");
      dlclose(file_handle);
      ret = G_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_file - Error opening module file %s, reason: %s", file_path, dlerror());
    ret = G_ERROR;
  }

  return ret;
}

int init_user_auth_scheme_module_list(struct config_elements * config) {
  int ret = G_OK, is_reg;
  DIR * modules_directory;
  struct dirent * in_file;
  char * file_path;
  struct stat u_stat;
  memset(&u_stat, 0, sizeof(struct stat));

  config->user_auth_scheme_module_list = o_malloc(sizeof(struct _pointer_list));
  if (config->user_auth_scheme_module_list != NULL) {
    pointer_list_init(config->user_auth_scheme_module_list);
    // read module_path and load modules
    if (NULL == (modules_directory = opendir(config->user_auth_scheme_module_path))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "init_user_auth_scheme_module_list - Error reading libraries folder %s", config->user_auth_scheme_module_path);
      ret = G_ERROR;
    } else {
      while ((in_file = readdir(modules_directory))) {
        is_reg = 0;
        file_path = NULL;
        if (in_file->d_type == DT_REG) {
          file_path = msprintf("%s/%s", config->user_auth_scheme_module_path, in_file->d_name);
          is_reg = 1;
        } else if (in_file->d_type == DT_UNKNOWN) {
          file_path = msprintf("%s/%s", config->user_auth_scheme_module_path, in_file->d_name);
          if (!stat(file_path, &u_stat)) {
            if (S_ISREG(u_stat.st_mode)) {
              is_reg = 1;
            }
          }
        }
        if (is_reg) {
          if (load_user_auth_scheme_module_file(config, file_path) != G_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "init_user_auth_scheme_module_list - Error opening module file %s", file_path);
          }
        }
        o_free(file_path);
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
  json_t * j_query, * j_result, * j_instance, * j_parameters, * j_init;
  int res, ret;
  size_t index, i;
  struct _user_auth_scheme_module_instance * cur_instance;
  struct _user_auth_scheme_module * module = NULL;
  char * message;

  config->user_auth_scheme_module_instance_list = o_malloc(sizeof(struct _pointer_list));
  if (config->user_auth_scheme_module_instance_list != NULL) {
    pointer_list_init(config->user_auth_scheme_module_instance_list);
    j_query = json_pack("{sss[ssssssss]}",
                        "table",
                        GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE,
                        "columns",
                          "guasmi_id",
                          "guasmi_module AS module",
                          "guasmi_name AS name",
                          "guasmi_expiration",
                          "guasmi_max_use",
                          "guasmi_allow_user_register",
                          "guasmi_parameters AS parameters",
                          "guasmi_enabled AS enabled");
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (!pthread_mutex_lock(&config->module_lock)) {
        ret = G_OK;
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
              cur_instance->guasmi_max_use = json_integer_value(json_object_get(j_instance, "guasmi_max_use"));
              cur_instance->guasmi_allow_user_register = (short int)json_integer_value(json_object_get(j_instance, "guasmi_allow_user_register"));
              cur_instance->enabled = 0;
              if (pointer_list_append(config->user_auth_scheme_module_instance_list, cur_instance)) {
                if ((res = is_scheme_backend_api_run_enabled(config, cur_instance->name)) == G_OK) {
                  if (json_integer_value(json_object_get(j_instance, "enabled"))) {
                    j_parameters = json_loads(json_string_value(json_object_get(j_instance, "parameters")), JSON_DECODE_ANY, NULL);
                    if (j_parameters != NULL) {
                      j_init = module->user_auth_scheme_module_init(config->config_m, j_parameters, cur_instance->name, &cur_instance->cls);
                      if (check_result_value(j_init, G_OK)) {
                        glewlwyd_metrics_increment_counter_va(config, GLWD_METRICS_AUTH_USER_VALID_SCHEME, 0, "scheme_type", module->name, "scheme_name", cur_instance->name, NULL);
                        glewlwyd_metrics_increment_counter_va(config, GLWD_METRICS_AUTH_USER_INVALID_SCHEME, 0, "scheme_type", module->name, "scheme_name", cur_instance->name, NULL);
                        cur_instance->enabled = 1;
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error init module %s/%s", module->name, json_string_value(json_object_get(j_instance, "name")));
                        if (check_result_value(j_init, G_ERROR_PARAM)) {
                          message = json_dumps(json_object_get(j_init, "error"), JSON_INDENT(2));
                          y_log_message(Y_LOG_LEVEL_DEBUG, message);
                          o_free(message);
                        }
                      }
                      json_decref(j_init);
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error parsing parameters for module %s: '%s'", cur_instance->name, json_string_value(json_object_get(j_instance, "parameters")));
                      o_free(cur_instance->name);
                    }
                    json_decref(j_parameters);
                  }
                } else if (res != G_ERROR_NOT_FOUND) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error is_scheme_backend_api_run_enabled");
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error reallocating resources for user_auth_scheme_module_instance_list");
                o_free(cur_instance->name);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error allocating resources for cur_instance");
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error module %s not found", json_string_value(json_object_get(j_instance, "module")));
          }
        }
        json_decref(j_result);
        pthread_mutex_unlock(&config->module_lock);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error pthread_mutex_lock");
        ret = G_ERROR;
      }
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
  size_t i;
  struct _user_auth_scheme_module_instance * cur_instance;
  int res;

  for (i=0; i<pointer_list_size(config->user_auth_scheme_module_instance_list); i++) {
    cur_instance = pointer_list_get_at(config->user_auth_scheme_module_instance_list, i);
    if ((res = is_scheme_backend_api_run_enabled(config, cur_instance->name)) == G_OK) {
      if (0 == o_strcmp(cur_instance->name, name)) {
        return cur_instance;
      }
    } else if (res != G_ERROR_NOT_FOUND) {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_user_auth_scheme_module_instance - Error is_scheme_backend_api_run_enabled");
    }
  }
  return NULL;
}

struct _user_auth_scheme_module * get_user_auth_scheme_module_lib(struct config_elements * config, const char * name) {
  size_t i;
  struct _user_auth_scheme_module * module;

  for (i=0; i<pointer_list_size(config->user_auth_scheme_module_list); i++) {
    module = (struct _user_auth_scheme_module *)pointer_list_get_at(config->user_auth_scheme_module_list, i);
    if (module != NULL && 0 == o_strcmp(module->name, name)) {
      return module;
    }
  }
  return NULL;
}

void close_user_auth_scheme_module_instance_list(struct config_elements * config) {
  size_t i;
  int res;

  if (!pthread_mutex_lock(&config->module_lock)) {
    for (i=0; i<pointer_list_size(config->user_auth_scheme_module_instance_list); i++) {
      struct _user_auth_scheme_module_instance * instance = (struct _user_auth_scheme_module_instance *)pointer_list_get_at(config->user_auth_scheme_module_instance_list, i);
      if (instance != NULL) {
        if ((res = is_scheme_backend_api_run_enabled(config, instance->name)) == G_OK) {
          if (instance->enabled && instance->module->user_auth_scheme_module_close(config->config_m, instance->cls) != G_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "close_user_auth_scheme_module_instance_list - Error user_auth_scheme_module_close for instance '%s'/'%s'", instance->module->name, instance->name);
          }
        } else if (res != G_ERROR_NOT_FOUND) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_user_auth_scheme_module_instance_list - Error is_scheme_backend_api_run_enabled");
        }
        o_free(instance->name);
        o_free(instance);
      }
    }
    pointer_list_clean(config->user_auth_scheme_module_instance_list);
    o_free(config->user_auth_scheme_module_instance_list);
    pthread_mutex_unlock(&config->module_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "close_user_auth_scheme_module_instance_list - Error pthread_mutex_lock");
  }
}

void close_user_auth_scheme_module_list(struct config_elements * config) {
  size_t i;

  if (!pthread_mutex_lock(&config->module_lock)) {
    for (i=0; i<pointer_list_size(config->user_auth_scheme_module_list); i++) {
      struct _user_auth_scheme_module * module = (struct _user_auth_scheme_module *)pointer_list_get_at(config->user_auth_scheme_module_list, i);
      if (module != NULL) {
        if (module->user_auth_scheme_module_unload(config->config_m) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_user_auth_scheme_module_list - Error user_auth_scheme_module_unload for module '%s'", module->name);
        }
  #ifndef DEBUG
        if (dlclose(module->file_handle)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_user_auth_scheme_module_list - Error dlclose for module '%s'", module->name);
        }
  #endif
        o_free(module->name);
        o_free(module->display_name);
        o_free(module->description);
        o_free(module);
      }
    }
    pointer_list_clean(config->user_auth_scheme_module_list);
    o_free(config->user_auth_scheme_module_list);
    pthread_mutex_unlock(&config->module_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "close_user_auth_scheme_module_list - Error pthread_mutex_lock");
  }
}

static int load_client_module_file(struct config_elements * config, const char * file_path) {
  void * file_handle;
  struct _client_module * cur_client_module = NULL;
  int ret;
  json_t * j_parameters;

  file_handle = dlopen(file_path, RTLD_LAZY);

  if (file_handle != NULL) {
    cur_client_module = o_malloc(sizeof(struct _client_module));
    if (cur_client_module != NULL) {
      cur_client_module->name = NULL;
      cur_client_module->file_handle = file_handle;
      cur_client_module->api_version = 0.0;
      *(void **) (&cur_client_module->client_module_load) = dlsym(file_handle, "client_module_load");
      *(void **) (&cur_client_module->client_module_unload) = dlsym(file_handle, "client_module_unload");
      *(void **) (&cur_client_module->client_module_init) = dlsym(file_handle, "client_module_init");
      *(void **) (&cur_client_module->client_module_close) = dlsym(file_handle, "client_module_close");
      *(void **) (&cur_client_module->client_module_count_total) = dlsym(file_handle, "client_module_count_total");
      *(void **) (&cur_client_module->client_module_get_list) = dlsym(file_handle, "client_module_get_list");
      *(void **) (&cur_client_module->client_module_get) = dlsym(file_handle, "client_module_get");
      *(void **) (&cur_client_module->client_module_is_valid) = dlsym(file_handle, "client_module_is_valid");
      *(void **) (&cur_client_module->client_module_add) = dlsym(file_handle, "client_module_add");
      *(void **) (&cur_client_module->client_module_update) = dlsym(file_handle, "client_module_update");
      *(void **) (&cur_client_module->client_module_delete) = dlsym(file_handle, "client_module_delete");
      *(void **) (&cur_client_module->client_module_check_password) = dlsym(file_handle, "client_module_check_password");

      if (cur_client_module->client_module_load != NULL &&
          cur_client_module->client_module_unload != NULL &&
          cur_client_module->client_module_init != NULL &&
          cur_client_module->client_module_close != NULL &&
          cur_client_module->client_module_count_total != NULL &&
          cur_client_module->client_module_get_list != NULL &&
          cur_client_module->client_module_get != NULL &&
          cur_client_module->client_module_is_valid != NULL &&
          cur_client_module->client_module_add != NULL &&
          cur_client_module->client_module_update != NULL &&
          cur_client_module->client_module_delete != NULL &&
          cur_client_module->client_module_check_password != NULL) {
        j_parameters = cur_client_module->client_module_load(config->config_m);
        if (check_result_value(j_parameters, G_OK)) {
          cur_client_module->name = o_strdup(json_string_value(json_object_get(j_parameters, "name")));
          cur_client_module->display_name = o_strdup(json_string_value(json_object_get(j_parameters, "display_name")));
          cur_client_module->description = o_strdup(json_string_value(json_object_get(j_parameters, "description")));
          cur_client_module->api_version = json_real_value(json_object_get(j_parameters, "api_version"));
          if (!o_strnullempty(cur_client_module->name) && get_client_module_lib(config, cur_client_module->name) == NULL) {
            if (!pthread_mutex_lock(&config->module_lock)) {
              if (pointer_list_append(config->client_module_list, cur_client_module)) {
                y_log_message(Y_LOG_LEVEL_INFO, "Loading client module %s - %s", file_path, cur_client_module->name);
                ret = G_OK;
              } else {
                cur_client_module->client_module_unload(config->config_m);
                dlclose(file_handle);
                o_free(cur_client_module->name);
                o_free(cur_client_module->display_name);
                o_free(cur_client_module->description);
                o_free(cur_client_module);
                y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_file - Error reallocating resources for client_module_list");
                ret = G_ERROR_MEMORY;
              }
              pthread_mutex_unlock(&config->module_lock);
            } else {
              cur_client_module->client_module_unload(config->config_m);
              dlclose(file_handle);
              o_free(cur_client_module->name);
              o_free(cur_client_module->display_name);
              o_free(cur_client_module->description);
              o_free(cur_client_module);
              y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_file - Error pthread_mutex_lock");
              ret = G_ERROR_MEMORY;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_file - Client module with name '%s' already present or name empty", cur_client_module->name);
            cur_client_module->client_module_unload(config->config_m);
            dlclose(file_handle);
            o_free(cur_client_module->name);
            o_free(cur_client_module->display_name);
            o_free(cur_client_module->description);
            o_free(cur_client_module);
            ret = G_ERROR;
          }
        } else {
          dlclose(file_handle);
          o_free(cur_client_module);
          y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_file - Error client_module_load for module %s", file_path);
          ret = G_ERROR_MEMORY;
        }
        json_decref(j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_file - Error module %s has not all required functions", file_path);
        y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_load: %s", (cur_client_module->client_module_load != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_unload: %s", (cur_client_module->client_module_unload != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_init: %s", (cur_client_module->client_module_init != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_close: %s", (cur_client_module->client_module_close != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_count_total: %s", (cur_client_module->client_module_count_total != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_get_list: %s", (cur_client_module->client_module_get_list != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_get: %s", (cur_client_module->client_module_get != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_is_valid: %s", (cur_client_module->client_module_is_valid != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_add: %s", (cur_client_module->client_module_add != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_update: %s", (cur_client_module->client_module_update != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_delete: %s", (cur_client_module->client_module_delete != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - client_module_check_password: %s", (cur_client_module->client_module_check_password != NULL?"found":"not found"));
        dlclose(file_handle);
        o_free(cur_client_module);
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_file - Error allocating resources for cur_client_module");
      dlclose(file_handle);
      ret = G_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_file - Error opening module file %s, reason: %s", file_path, dlerror());
    ret = G_ERROR;
  }
  return ret;
}

int init_client_module_list(struct config_elements * config) {
  int ret = G_OK, is_reg;
  DIR * modules_directory;
  struct dirent * in_file;
  char * file_path;
  struct stat u_stat;
  memset(&u_stat, 0, sizeof(struct stat));

  config->client_module_list = o_malloc(sizeof(struct _pointer_list));
  if (config->client_module_list != NULL) {
    pointer_list_init(config->client_module_list);
    // read module_path and load modules
    if (NULL == (modules_directory = opendir(config->client_module_path))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "init_client_module_list - Error reading libraries folder %s", config->client_module_path);
      ret = G_ERROR;
    } else {
      while ((in_file = readdir(modules_directory))) {
        is_reg = 0;
        file_path = NULL;
        if (in_file->d_type == DT_REG) {
          file_path = msprintf("%s/%s", config->client_module_path, in_file->d_name);
          is_reg = 1;
        } else if (in_file->d_type == DT_UNKNOWN) {
          file_path = msprintf("%s/%s", config->client_module_path, in_file->d_name);
          if (!stat(file_path, &u_stat)) {
            if (S_ISREG(u_stat.st_mode)) {
              is_reg = 1;
            }
          }
        }
        if (is_reg) {
          if (load_client_module_file(config, file_path) != G_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "init_client_module_list - Error opening module file %s", file_path);
          }
        }
        o_free(file_path);
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
  json_t * j_query, * j_result, * j_instance, * j_parameters, * j_init;
  int res, ret;
  size_t index, i;
  struct _client_module_instance * cur_instance;
  struct _client_module * module = NULL;

  config->client_module_instance_list = o_malloc(sizeof(struct _pointer_list));
  if (config->client_module_instance_list != NULL) {
    pointer_list_init(config->client_module_instance_list);
    j_query = json_pack("{sss[ssssss]ss}",
                        "table",
                        GLEWLWYD_TABLE_CLIENT_MODULE_INSTANCE,
                        "columns",
                          "gcmi_module AS module",
                          "gcmi_name AS name",
                          "gcmi_order AS order_by",
                          "gcmi_parameters AS parameters",
                          "gcmi_readonly AS readonly",
                          "gcmi_enabled AS enabled",
                        "order_by",
                        "gcmi_order");
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (!pthread_mutex_lock(&config->module_lock)) {
        ret = G_OK;
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
              cur_instance->readonly = (short int)json_integer_value(json_object_get(j_instance, "readonly"));
              cur_instance->module = module;
              cur_instance->enabled = 0;
              if (pointer_list_append(config->client_module_instance_list, cur_instance)) {
                if ((res = is_client_backend_api_run_enabled(config, cur_instance->name)) == G_OK) {
                  if (json_integer_value(json_object_get(j_instance, "enabled"))) {
                    j_parameters = json_loads(json_string_value(json_object_get(j_instance, "parameters")), JSON_DECODE_ANY, NULL);
                    if (j_parameters != NULL) {
                      j_init = module->client_module_init(config->config_m, cur_instance->readonly, j_parameters, &cur_instance->cls);
                      if (check_result_value(j_init, G_OK)) {
                        cur_instance->enabled = 1;
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_instance_list - Error init module %s/%s", module->name, json_string_value(json_object_get(j_instance, "name")));
                      }
                      json_decref(j_init);
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_instance_list - Error parsing module parameters %s/%s: '%s'", module->name, json_string_value(json_object_get(j_instance, "name")), json_string_value(json_object_get(j_instance, "parameters")));
                    }
                    json_decref(j_parameters);
                  }
                } else if (res != G_ERROR_NOT_FOUND) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_instance_list - Error is_client_backend_api_run_enabled");
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_instance_list - Error reallocating resources for client_module_instance_list");
                o_free(cur_instance->name);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_instance_list - Error allocating resources for cur_instance");
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_instance_list - Error module %s not found", json_string_value(json_object_get(j_instance, "module")));
          }
        }
        json_decref(j_result);
        pthread_mutex_unlock(&config->module_lock);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_client_module_instance_list - Error pthread_mutex_lock");
        ret = G_ERROR;
      }
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
  size_t i;
  struct _client_module_instance * cur_instance;

  for (i=0; i<pointer_list_size(config->client_module_instance_list); i++) {
    cur_instance = pointer_list_get_at(config->client_module_instance_list, i);
    if (0 == o_strcmp(cur_instance->name, name)) {
      return cur_instance;
    }
  }
  return NULL;
}

struct _client_module * get_client_module_lib(struct config_elements * config, const char * name) {
  size_t i;
  struct _client_module * module;

  for (i=0; i<pointer_list_size(config->client_module_list); i++) {
    module = (struct _client_module *)pointer_list_get_at(config->client_module_list, i);
    if (module != NULL && 0 == o_strcmp(module->name, name)) {
      return module;
    }
  }
  return NULL;
}

void close_client_module_instance_list(struct config_elements * config) {
  size_t i;
  int res;

  if (!pthread_mutex_lock(&config->module_lock)) {
    for (i=0; i<pointer_list_size(config->client_module_instance_list); i++) {
      struct _client_module_instance * instance = (struct _client_module_instance *)pointer_list_get_at(config->client_module_instance_list, i);
      if (instance != NULL) {
        if ((res = is_client_backend_api_run_enabled(config, instance->name)) == G_OK) {
          if (instance->enabled && instance->module->client_module_close(config->config_m, instance->cls) != G_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "close_client_module_instance_list - Error client_module_close for instance '%s'/'%s'", instance->module->name, instance->name);
          }
        } else if (res != G_ERROR_NOT_FOUND) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_client_module_instance_list - Error is_client_backend_api_run_enabled");
        }
        o_free(instance->name);
        o_free(instance);
      }
    }
    pointer_list_clean(config->client_module_instance_list);
    o_free(config->client_module_instance_list);
    pthread_mutex_unlock(&config->module_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "close_client_module_instance_list - Error pthread_mutex_lock");
  }
}

void close_client_module_list(struct config_elements * config) {
  size_t i;

  if (!pthread_mutex_lock(&config->module_lock)) {
    for (i=0; i<pointer_list_size(config->client_module_list); i++) {
      struct _client_module * module = (struct _client_module *)pointer_list_get_at(config->client_module_list, i);
      if (module != NULL) {
        if (module->client_module_unload(config->config_m) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_client_module_list - Error client_module_unload for module '%s'", module->name);
        }
  /*
  * dlclose() makes valgrind not useful when it comes to libraries
  * they say it's not relevant to use it anyway
  * I'll let it here until I'm sure
  */
  #ifndef DEBUG
        if (dlclose(module->file_handle)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_client_module_list - Error dlclose for module '%s'", module->name);
        }
  #endif
        o_free(module->name);
        o_free(module->display_name);
        o_free(module->description);
        o_free(module);
      }
    }
    pointer_list_clean(config->client_module_list);
    o_free(config->client_module_list);
    pthread_mutex_unlock(&config->module_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "close_client_module_list - Error close_client_module_list");
  }
}

static int load_plugin_module_file(struct config_elements * config, const char * file_path) {
  void * file_handle;
  struct _plugin_module * cur_plugin_module = NULL;
  int ret;
  json_t * j_result;

  file_handle = dlopen(file_path, RTLD_LAZY);

  if (file_handle != NULL) {
    cur_plugin_module = o_malloc(sizeof(struct _plugin_module));
    if (cur_plugin_module != NULL) {
      cur_plugin_module->name = NULL;
      cur_plugin_module->file_handle = file_handle;
      cur_plugin_module->api_version = 0.0;
      *(void **) (&cur_plugin_module->plugin_module_load) = dlsym(file_handle, "plugin_module_load");
      *(void **) (&cur_plugin_module->plugin_module_unload) = dlsym(file_handle, "plugin_module_unload");
      *(void **) (&cur_plugin_module->plugin_module_init) = dlsym(file_handle, "plugin_module_init");
      *(void **) (&cur_plugin_module->plugin_module_close) = dlsym(file_handle, "plugin_module_close");
      *(void **) (&cur_plugin_module->plugin_user_revoke) = dlsym(file_handle, "plugin_user_revoke");

      if (cur_plugin_module->plugin_module_load != NULL &&
          cur_plugin_module->plugin_module_unload != NULL &&
          cur_plugin_module->plugin_module_init != NULL &&
          cur_plugin_module->plugin_module_close != NULL &&
          cur_plugin_module->plugin_user_revoke != NULL) {
        j_result = cur_plugin_module->plugin_module_load(config->config_p);
        if (check_result_value(j_result, G_OK)) {
          cur_plugin_module->name = o_strdup(json_string_value(json_object_get(j_result, "name")));
          cur_plugin_module->display_name = o_strdup(json_string_value(json_object_get(j_result, "display_name")));
          cur_plugin_module->description = o_strdup(json_string_value(json_object_get(j_result, "description")));
          cur_plugin_module->api_version = json_real_value(json_object_get(j_result, "api_version"));
          if (!o_strnullempty(cur_plugin_module->name) && get_plugin_module_lib(config, cur_plugin_module->name) == NULL) {
            if (!pthread_mutex_lock(&config->module_lock)) {
              if (pointer_list_append(config->plugin_module_list, cur_plugin_module)) {
                y_log_message(Y_LOG_LEVEL_INFO, "Loading plugin module %s - %s", file_path, cur_plugin_module->name);
                ret = G_OK;
              } else {
                cur_plugin_module->plugin_module_unload(config->config_p);
                dlclose(file_handle);
                o_free(cur_plugin_module->name);
                o_free(cur_plugin_module->display_name);
                o_free(cur_plugin_module->description);
                o_free(cur_plugin_module);
                y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_file - Error reallocating resources for client_module_list");
                ret = G_ERROR_MEMORY;
              }
              pthread_mutex_unlock(&config->module_lock);
            } else {
              cur_plugin_module->plugin_module_unload(config->config_p);
              dlclose(file_handle);
              o_free(cur_plugin_module->name);
              o_free(cur_plugin_module->display_name);
              o_free(cur_plugin_module->description);
              o_free(cur_plugin_module);
              y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_file - Error pthread_mutex_lock");
              ret = G_ERROR_MEMORY;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_file - Plugin module with name '%s' already present or name empty", cur_plugin_module->name);
            cur_plugin_module->plugin_module_unload(config->config_p);
            dlclose(file_handle);
            o_free(cur_plugin_module->name);
            o_free(cur_plugin_module->display_name);
            o_free(cur_plugin_module->description);
            o_free(cur_plugin_module);
            ret = G_ERROR;
          }
        } else {
          dlclose(file_handle);
          o_free(cur_plugin_module->name);
          o_free(cur_plugin_module->display_name);
          o_free(cur_plugin_module->description);
          o_free(cur_plugin_module);
          y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_file - Error client_module_init for module %s", file_path);
          ret = G_ERROR_MEMORY;
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_file - Error module %s has not all required functions", file_path);
        y_log_message(Y_LOG_LEVEL_ERROR, " - plugin_module_load: %s", (cur_plugin_module->plugin_module_load != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - plugin_module_unload: %s", (cur_plugin_module->plugin_module_unload != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - plugin_module_init: %s", (cur_plugin_module->plugin_module_init != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - plugin_module_close: %s", (cur_plugin_module->plugin_module_close != NULL?"found":"not found"));
        y_log_message(Y_LOG_LEVEL_ERROR, " - plugin_user_revoke: %s", (cur_plugin_module->plugin_user_revoke != NULL?"found":"not found"));
        dlclose(file_handle);
        o_free(cur_plugin_module);
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_file - Error allocating resources for cur_client_module");
      dlclose(file_handle);
      ret = G_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_file - Error opening module file %s, reason: %s", file_path, dlerror());
    ret = G_ERROR;
  }
  return ret;
}

int init_plugin_module_list(struct config_elements * config) {
  int ret = G_OK, is_reg;
  DIR * modules_directory;
  struct dirent * in_file;
  char * file_path;
  struct stat u_stat;
  memset(&u_stat, 0, sizeof(struct stat));

  config->plugin_module_list = o_malloc(sizeof(struct _pointer_list));
  if (config->plugin_module_list != NULL) {
    pointer_list_init(config->plugin_module_list);
    // read module_path and load modules
    if (NULL == (modules_directory = opendir(config->plugin_module_path))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "init_plugin_module_list - Error reading libraries folder %s", config->plugin_module_path);
      ret = G_ERROR;
    } else {
      while ((in_file = readdir(modules_directory))) {
        is_reg = 0;
        file_path = NULL;
        if (in_file->d_type == DT_REG) {
          file_path = msprintf("%s/%s", config->plugin_module_path, in_file->d_name);
          is_reg = 1;
        } else if (in_file->d_type == DT_UNKNOWN) {
          file_path = msprintf("%s/%s", config->plugin_module_path, in_file->d_name);
          if (!stat(file_path, &u_stat)) {
            if (S_ISREG(u_stat.st_mode)) {
              is_reg = 1;
            }
          }
        }
        if (is_reg) {
          if (load_plugin_module_file(config, file_path) != G_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "init_client_module_list - Error opening module file %s", file_path);
          }
        }
        o_free(file_path);
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
  json_t * j_query, * j_result, * j_instance, * j_parameters, * j_init;
  int res, ret;
  size_t index, i;
  struct _plugin_module_instance * cur_instance;
  struct _plugin_module * module = NULL;
  char * message;

  config->plugin_module_instance_list = o_malloc(sizeof(struct _pointer_list));
  if (config->plugin_module_instance_list != NULL) {
    pointer_list_init(config->plugin_module_instance_list);
    j_query = json_pack("{sss[ssss]}",
                        "table",
                        GLEWLWYD_TABLE_PLUGIN_MODULE_INSTANCE,
                        "columns",
                          "gpmi_module AS module",
                          "gpmi_name AS name",
                          "gpmi_parameters AS parameters",
                          "gpmi_enabled AS enabled");
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (!pthread_mutex_lock(&config->module_lock)) {
        ret = G_OK;
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
              cur_instance->enabled = 0;
              if (pointer_list_append(config->plugin_module_instance_list, cur_instance)) {
                if ((res = is_plugin_api_run_enabled(config, cur_instance->name)) == G_OK) {
                  if (json_integer_value(json_object_get(j_instance, "enabled"))) {
                    j_parameters = json_loads(json_string_value(json_object_get(j_instance, "parameters")), JSON_DECODE_ANY, NULL);
                    if (j_parameters != NULL) {
                      j_init = module->plugin_module_init(config->config_p, cur_instance->name, j_parameters, &cur_instance->cls);
                      if (check_result_value(j_init, G_OK)) {
                        cur_instance->enabled = 1;
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error init module %s/%s", module->name, json_string_value(json_object_get(j_instance, "name")));
                        if (check_result_value(j_init, G_ERROR_PARAM)) {
                          message = json_dumps(json_object_get(j_init, "error"), JSON_INDENT(2));
                          y_log_message(Y_LOG_LEVEL_DEBUG, message);
                          o_free(message);
                        }
                      }
                      json_decref(j_init);
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error parsing parameters for module %s/%s: '%s'", module->name, json_string_value(json_object_get(j_instance, "name")), json_string_value(json_object_get(j_instance, "parameters")));
                    }
                    json_decref(j_parameters);
                  }
                } else if (res != G_ERROR_NOT_FOUND) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error is_plugin_api_run_enabled");
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error reallocating resources for client_module_instance_list");
                o_free(cur_instance->name);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error allocating resources for cur_instance");
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error module %s not found", json_string_value(json_object_get(j_instance, "module")));
          }
        }
        json_decref(j_result);
        pthread_mutex_unlock(&config->module_lock);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error pthread_mutex_lock");
        ret = G_ERROR;
      }
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
  size_t i;
  struct _plugin_module_instance * cur_instance;

  for (i=0; i<pointer_list_size(config->plugin_module_instance_list); i++) {
    cur_instance = (struct _plugin_module_instance *)pointer_list_get_at(config->plugin_module_instance_list, i);
    if (cur_instance != NULL && 0 == o_strcmp(cur_instance->name, name)) {
      return cur_instance;
    }
  }
  return NULL;
}

struct _plugin_module * get_plugin_module_lib(struct config_elements * config, const char * name) {
  size_t i;
  struct _plugin_module * module;

  for (i=0; i<pointer_list_size(config->plugin_module_list); i++) {
    module = (struct _plugin_module *)pointer_list_get_at(config->plugin_module_list, i);
    if (module != NULL && 0 == o_strcmp(module->name, name)) {
      return module;
    }
  }
  return NULL;
}

void close_plugin_module_instance_list(struct config_elements * config) {
  size_t i;
  int res;

  if (!pthread_mutex_lock(&config->module_lock)) {
    for (i=0; i<pointer_list_size(config->plugin_module_instance_list); i++) {
      struct _plugin_module_instance * instance = (struct _plugin_module_instance *)pointer_list_get_at(config->plugin_module_instance_list, i);
      if (instance != NULL) {
        if ((res = is_plugin_api_run_enabled(config, instance->name)) == G_OK) {
          if (instance->enabled && instance->module->plugin_module_close(config->config_p, instance->name, instance->cls) != G_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "close_plugin_module_instance_list - Error plugin_module_close for instance '%s'/'%s'", instance->module->name, instance->name);
          }
        } else if (res != G_ERROR_NOT_FOUND) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_plugin_module_instance_list - Error is_plugin_api_run_enabled");
        }
        o_free(instance->name);
        o_free(instance);
      }
    }
    pointer_list_clean(config->plugin_module_instance_list);
    o_free(config->plugin_module_instance_list);
    pthread_mutex_unlock(&config->module_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "close_plugin_module_instance_list - Error pthread_mutex_lock");
  }
}

void close_plugin_module_list(struct config_elements * config) {
  size_t i;

  if (!pthread_mutex_lock(&config->module_lock)) {
    for (i=0; i<pointer_list_size(config->plugin_module_list); i++) {
      struct _plugin_module * module = (struct _plugin_module *)pointer_list_get_at(config->plugin_module_list, i);
      if (module != NULL) {
        if (module->plugin_module_unload(config->config_p) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_plugin_module_list - Error plugin_module_unload for module '%s'", module->name);
        }
  #ifndef DEBUG
        if (dlclose(module->file_handle)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "close_plugin_module_list - Error dlclose for module '%s'", module->name);
        }
  #endif
        o_free(module->name);
        o_free(module->display_name);
        o_free(module->description);
        o_free(module);
      }
    }
    pointer_list_clean(config->plugin_module_list);
    o_free(config->plugin_module_list);
    pthread_mutex_unlock(&config->module_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "close_plugin_module_list - Error pthread_mutex_lock");
  }
}

char * get_ip_data(struct config_elements * config, const char * ip_address) {
  char * data = NULL, * url, ** properties = NULL;
  json_t * j_misc_config = get_misc_config(config, GLEWLWYD_IP_GEOLOCATION_API_TYPE, NULL), * j_response;
  struct _u_request req;
  struct _u_response resp;
  size_t i;

  if (check_result_value(j_misc_config, G_OK) && json_object_get(json_object_get(json_object_get(j_misc_config, "misc_config"), "value"), "enabled") == json_true()) {
    if (split_string(json_string_value(json_object_get(json_object_get(json_object_get(j_misc_config, "misc_config"), "value"), "output-properties")), ",", &properties)) {
      url = str_replace(json_string_value(json_object_get(json_object_get(json_object_get(j_misc_config, "misc_config"), "value"), "url")), "{IP}", ip_address);
      ulfius_init_request(&req);
      ulfius_init_response(&resp);
      ulfius_set_request_properties(&req, U_OPT_HTTP_URL, url, U_OPT_NONE);
      if (ulfius_send_http_request_with_limit(&req, &resp, config->response_body_limit, config->max_header) == U_OK && resp.status >= 200 && resp.status < 300) {
        if ((j_response = ulfius_get_json_body_response(&resp, NULL)) != NULL) {
          for (i=0; properties[i]!=NULL; i++) {
            if (data == NULL) {
              data = o_strdup(json_string_value(json_object_get(j_response, trimwhitespace(properties[i]))));
            } else {
              data = mstrcatf(data, " - %s", json_string_value(json_object_get(j_response, trimwhitespace(properties[i]))));
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_ip_data - No JSON response - url", url);
        }
        json_decref(j_response);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_ip_data - Error ulfius_send_http_request_with_limit - url %s", url);
      }
      ulfius_clean_request(&req);
      ulfius_clean_response(&resp);
      o_free(url);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_ip_data - Error split_string for %s", json_string_value(json_object_get(json_object_get(json_object_get(j_misc_config, "misc_config"), "value"), "output-properties")));
    }
    free_string_array(properties);
  }
  json_decref(j_misc_config);
  return data;
}

const char * get_template_property(json_t * j_params, const char * template_property, const char * user_lang, const char * property_field) {
  json_t * j_template = NULL;
  const char * property = NULL, * property_default = NULL, * lang = NULL;
  
  if (json_object_get(j_params, template_property) == NULL) {
    property = json_string_value(json_object_get(j_params, property_field));
  } else {
    json_object_foreach(json_object_get(j_params, template_property), lang, j_template) {
      if (0 == o_strcmp(user_lang, lang)) {
        property = json_string_value(json_object_get(j_template, property_field));
      }
      if (json_object_get(j_template, "defaultLang") == json_true()) {
        property_default = json_string_value(json_object_get(j_template, property_field));
      }
    }
    if (property == NULL) {
      property = property_default;
    }
  }
  return property;
}

char * complete_template(const char * template, ...) {
  va_list vl;
  const char * variable, * value;
  char * to_return = NULL, * tmp;
  
  va_start(vl, template);
  variable = va_arg(vl, const char *);
  to_return = o_strdup(template);
  for (; variable != NULL; variable = va_arg(vl, const char *)) {
    value = va_arg(vl, const char *);
    tmp = str_replace(to_return, variable, value);
    o_free(to_return);
    to_return = tmp;
    tmp = NULL;
  }
  return to_return;
}

void * thread_send_mail(void * args) {
  struct send_mail_content_struct * send_mail = (struct send_mail_content_struct *)args;
  if (send_mail != NULL) {
    if (ulfius_send_smtp_rich_email(send_mail->host,
                                   send_mail->port,
                                   send_mail->use_tls,
                                   send_mail->verify_certificate,
                                   send_mail->user,
                                   send_mail->password,
                                   send_mail->from,
                                   send_mail->email,
                                   NULL,
                                   NULL,
                                   send_mail->content_type,
                                   send_mail->subject,
                                   send_mail->body) != U_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "thread_send_mail - Error ulfius_send_smtp_rich_email");
    }
    o_free(send_mail->host);
    o_free(send_mail->user);
    o_free(send_mail->password);
    o_free(send_mail->from);
    o_free(send_mail->content_type);
    o_free(send_mail->email);
    o_free(send_mail->subject);
    o_free(send_mail->body);
    o_free(send_mail);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "thread_send_mail - Error send_mail ivalid");
  }
  
  return NULL;
}

int is_user_backend_api_run_enabled (struct config_elements * config, const char * name) {
  char ** plugin_list = NULL;
  int ret;

  if (!o_strnullempty(config->user_backend_api_run_enabled)) {
    if (!o_strnullempty(name)) {
      if (!split_string(config->user_backend_api_run_enabled, ",", &plugin_list)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error split_string for config->user_backend_api_run_enabled");
        ret = G_ERROR;
      } else {
        if (string_array_has_value_case((const char **)plugin_list, name)) {
          ret = G_OK;
        } else {
          ret = G_ERROR_NOT_FOUND;
        }
        free_string_array(plugin_list);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error name parameter empty");
      ret = G_ERROR_PARAM;
    }
  } else {
    ret = G_OK;
  }
  return ret;
}

int is_user_middleware_backend_api_run_enabled (struct config_elements * config, const char * name) {
  char ** plugin_list = NULL;
  int ret;

  if (!o_strnullempty(config->user_middleware_backend_api_run_enabled)) {
    if (!o_strnullempty(name)) {
      if (!split_string(config->user_middleware_backend_api_run_enabled, ",", &plugin_list)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error split_string for config->user_middleware_backend_api_run_enabled");
        ret = G_ERROR;
      } else {
        if (string_array_has_value_case((const char **)plugin_list, name)) {
          ret = G_OK;
        } else {
          ret = G_ERROR_NOT_FOUND;
        }
        free_string_array(plugin_list);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error name parameter empty");
      ret = G_ERROR_PARAM;
    }
  } else {
    ret = G_OK;
  }
  return ret;
}

int is_client_backend_api_run_enabled (struct config_elements * config, const char * name) {
  char ** plugin_list = NULL;
  int ret;

  if (!o_strnullempty(config->client_backend_api_run_enabled)) {
    if (!o_strnullempty(name)) {
      if (!split_string(config->client_backend_api_run_enabled, ",", &plugin_list)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error split_string for config->client_backend_api_run_enabled");
        ret = G_ERROR;
      } else {
        if (string_array_has_value_case((const char **)plugin_list, name)) {
          ret = G_OK;
        } else {
          ret = G_ERROR_NOT_FOUND;
        }
        free_string_array(plugin_list);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error name parameter empty");
      ret = G_ERROR_PARAM;
    }
  } else {
    ret = G_OK;
  }
  return ret;
}

int is_scheme_backend_api_run_enabled (struct config_elements * config, const char * name) {
  char ** plugin_list = NULL;
  int ret;

  if (!o_strnullempty(config->scheme_api_run_enabled)) {
    if (!o_strnullempty(name)) {
      if (!split_string(config->scheme_api_run_enabled, ",", &plugin_list)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error split_string for config->scheme_api_run_enabled");
        ret = G_ERROR;
      } else {
        if (string_array_has_value_case((const char **)plugin_list, name)) {
          ret = G_OK;
        } else {
          ret = G_ERROR_NOT_FOUND;
        }
        free_string_array(plugin_list);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error name parameter empty");
      ret = G_ERROR_PARAM;
    }
  } else {
    ret = G_OK;
  }
  return ret;
}

int is_plugin_api_run_enabled (struct config_elements * config, const char * name) {
  char ** plugin_api_run_enabled_list = NULL;
  int ret;

  if (!o_strnullempty(config->plugin_api_run_enabled)) {
    if (!o_strnullempty(name)) {
      if (!split_string(config->plugin_api_run_enabled, ",", &plugin_api_run_enabled_list)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error split_string for config->plugin_api_run_enabled");
        ret = G_ERROR;
      } else {
        if (string_array_has_value_case((const char **)plugin_api_run_enabled_list, name)) {
          ret = G_OK;
        } else {
          ret = G_ERROR_NOT_FOUND;
        }
        free_string_array(plugin_api_run_enabled_list);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "load_plugin_module_instance_list - Error name parameter empty");
      ret = G_ERROR_PARAM;
    }
  } else {
    ret = G_OK;
  }
  return ret;
}

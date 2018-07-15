/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * main functions definitions
 * and main process start
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
#include <getopt.h>
#include <libconfig.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
  }
  
  // Init config structure with default values
  config->config_file = NULL;
  config->port = GLEWLWYD_DEFAULT_PORT;
  config->api_prefix = NULL;
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
  config->grant_url = NULL;
  config->user_module_path = NULL;
  config->user_module_list_size = 0;
  config->user_module_list = NULL;
  config->user_module_instance_list_size = 0;
  config->user_module_instance_list = NULL;
  config->client_module_path = NULL;
  config->client_module_list_size = 0;
  config->client_module_list = NULL;
  config->client_module_instance_list_size = 0;
  config->client_module_instance_list = NULL;
  config->user_auth_scheme_module_path = NULL;
  config->user_auth_scheme_module_list_size = 0;
  config->user_auth_scheme_module_list = NULL;
  config->user_auth_scheme_module_instance_list_size = 0;
  config->user_auth_scheme_module_instance_list = NULL;
  
  config->glewlwyd_resource_config_admin = o_malloc(sizeof(struct _glewlwyd_resource_config));
  if (config->glewlwyd_resource_config_admin == NULL) {
    fprintf(stderr, "Error allocating resources for config->glewlwyd_resource_config_admin, aborting\n");
    return 2;
  }
  config->glewlwyd_resource_config_admin->jwt_alg = JWT_ALG_NONE;
  config->glewlwyd_resource_config_admin->jwt_decode_key = NULL;
  config->glewlwyd_resource_config_admin->method = G_METHOD_HEADER;
  config->glewlwyd_resource_config_admin->oauth_scope = NULL;
  config->glewlwyd_resource_config_admin->realm = NULL;
  
  config->glewlwyd_resource_config_profile = o_malloc(sizeof(struct _glewlwyd_resource_config));
  if (config->glewlwyd_resource_config_profile == NULL) {
    fprintf(stderr, "Error allocating resources for config->glewlwyd_resource_config_profile, aborting\n");
    return 2;
  }
  config->glewlwyd_resource_config_profile->jwt_alg = JWT_ALG_NONE;
  config->glewlwyd_resource_config_profile->jwt_decode_key = NULL;
  config->glewlwyd_resource_config_profile->method = G_METHOD_HEADER;
  config->glewlwyd_resource_config_profile->oauth_scope = NULL;
  config->glewlwyd_resource_config_profile->realm = NULL;
  
  config->static_file_config = o_malloc(sizeof(struct _static_file_config));
  if (config->static_file_config == NULL) {
    fprintf(stderr, "Error allocating resources for config->static_file_config, aborting\n");
    return 2;
  }
  config->static_file_config->files_path = NULL;
  config->static_file_config->url_prefix = NULL;
  config->static_file_config->redirect_on_404 = "/";
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
  
  // Initialize user auth scheme modules
  if (init_user_auth_scheme_module_list(config) != G_OK) {
    fprintf(stderr, "Error initializing user auth scheme modules\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  if (load_user_auth_scheme_module_instance_list(config) != G_OK) {
    fprintf(stderr, "Error loading user auth scheme modules instances\n");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  
  // At this point, we declare all API endpoints and configure 
  
  // Authentication
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/auth/user/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_validate_user, (void*)config);
#ifdef DEBUG
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/auth/user/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_check_user, (void*)config); // TODO: Remove on release
#endif

  // Other configuration
  ulfius_add_endpoint_by_val(config->instance, "GET", "/config/", NULL, GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_server_configuration, (void*)config);
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
  uint i;
  
  if (config != NULL && *config != NULL) {
    /* stop framework */
    ulfius_stop_framework((*config)->instance);
    ulfius_clean_instance((*config)->instance);
    h_close_db((*config)->conn);
    h_clean_connection((*config)->conn);
    y_close_logs();
    
    // Cleaning data
    o_free((*config)->instance);
    for (i=0; i<(*config)->user_module_instance_list_size; i++) {
      if ((*config)->user_module_instance_list[i]->module->user_module_close((*config), (*config)->user_module_instance_list[i]->cls) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error closing module %s", (*config)->user_module_instance_list[i]->name);
      }
      o_free((*config)->user_module_instance_list[i]->name);
      o_free((*config)->user_module_instance_list[i]);
    }
    o_free((*config)->user_module_instance_list);
    for (i=0; i<(*config)->user_module_list_size; i++) {
      (*config)->user_module_list[i]->user_module_unload(*config);
      o_free((*config)->user_module_list[i]->name);
      dlclose((*config)->user_module_list[i]->file_handle);
      o_free((*config)->user_module_list[i]);
    }
    o_free((*config)->user_module_list);
    
    for (i=0; i<(*config)->client_module_list_size; i++) {
      dlclose((*config)->client_module_list[i]->file_handle);
      o_free((*config)->client_module_list[i]);
    }
    o_free((*config)->client_module_list);
    
    for (i=0; i<(*config)->user_auth_scheme_module_instance_list_size; i++) {
      if ((*config)->user_auth_scheme_module_instance_list[i]->module->user_auth_scheme_module_close((*config), (*config)->user_auth_scheme_module_instance_list[i]->cls) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "exit_server - Error closing module %s", (*config)->user_auth_scheme_module_instance_list[i]->name);
      }
      o_free((*config)->user_auth_scheme_module_instance_list[i]->name);
      o_free((*config)->user_auth_scheme_module_instance_list[i]);
    }
    o_free((*config)->user_auth_scheme_module_instance_list);
    for (i=0; i<(*config)->user_auth_scheme_module_list_size; i++) {
      (*config)->user_auth_scheme_module_list[i]->user_auth_scheme_module_unload(*config);
      o_free((*config)->user_auth_scheme_module_list[i]->name);
      dlclose((*config)->user_auth_scheme_module_list[i]->file_handle);
      o_free((*config)->user_auth_scheme_module_list[i]);
    }
    o_free((*config)->user_auth_scheme_module_list);
    
    o_free((*config)->config_file);
    o_free((*config)->api_prefix);
    o_free((*config)->log_file);
    o_free((*config)->allow_origin);
    o_free((*config)->secure_connection_key_file);
    o_free((*config)->secure_connection_pem_file);
    o_free((*config)->session_key);
    o_free((*config)->hash_algorithm);
    o_free((*config)->login_url);
    o_free((*config)->grant_url);
    o_free((*config)->user_module_path);
    o_free((*config)->client_module_path);
    o_free((*config)->user_auth_scheme_module_path);
    
    if ((*config)->static_file_config != NULL) {
      u_map_clean_full((*config)->static_file_config->mime_types);
      o_free((*config)->static_file_config->files_path);
      o_free((*config)->static_file_config->url_prefix);
      o_free((*config)->static_file_config);
    }
    
    if ((*config)->glewlwyd_resource_config_admin != NULL) {
      o_free((*config)->glewlwyd_resource_config_admin->oauth_scope);
      o_free((*config)->glewlwyd_resource_config_admin->jwt_decode_key);
      o_free((*config)->glewlwyd_resource_config_admin->realm);
      o_free((*config)->glewlwyd_resource_config_admin);
    }
    
    if ((*config)->glewlwyd_resource_config_profile != NULL) {
      o_free((*config)->glewlwyd_resource_config_profile->oauth_scope);
      o_free((*config)->glewlwyd_resource_config_profile->jwt_decode_key);
      o_free((*config)->glewlwyd_resource_config_profile->realm);
      o_free((*config)->glewlwyd_resource_config_profile);
    }
    
    o_free(*config);
    (*config) = NULL;
  }
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
              exit_server(&config, GLEWLWYD_STOP);
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
              exit_server(&config, GLEWLWYD_STOP);
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
              exit_server(&config, GLEWLWYD_STOP);
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
              exit_server(&config, GLEWLWYD_STOP);
            }
          } else {
            fprintf(stderr, "Error!\nNo log file specified\n");
            return 0;
          }
          break;
        case 'h':
          print_help(stdout);
          exit_server(&config, GLEWLWYD_STOP);
          break;
        case 'v':
          fprintf(stdout, "%s\n", _GLEWLWYD_VERSION_);
          exit_server(&config, GLEWLWYD_STOP);
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
  config_setting_t * root = NULL, * database = NULL, * jwt = NULL, * mime_type_list = NULL, * mime_type = NULL;
  const char * str_value = NULL, * str_value_2 = NULL, * str_value_3 = NULL, * str_value_4 = NULL, * str_value_5 = NULL;
  int int_value = 0, int_value_2 = 0, int_value_3 = 0, int_value_4 = 0, i;
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

  if (!y_init_logs(GLEWLWYD_LOG_NAME, config->log_mode, config->log_level, config->log_file, "Starting Glewlwyd Oauth2 authentication service")) {
    fprintf(stderr, "Error initializing logs\n");
    exit_server(&config, GLEWLWYD_ERROR);
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
  
  if (config_lookup_string(&cfg, "grant_url", &str_value) != CONFIG_TRUE) {
    fprintf(stderr, "grant_url is mandatory, exiting\n");
    config_destroy(&cfg);
    return 0;
  } else {
    config->grant_url = strdup(str_value);
    if (config->grant_url == NULL) {
      fprintf(stderr, "Error allocating resources for config->grant_url, exiting\n");
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
  
  jwt = config_setting_get_member(root, "jwt");
  if (jwt != NULL) {
    config_setting_lookup_bool(jwt, "use_rsa", &int_value);
    config_setting_lookup_bool(jwt, "use_ecdsa", &int_value_2);
    config_setting_lookup_bool(jwt, "use_sha", &int_value_3);
    config_setting_lookup_int(jwt, "key_size", &int_value_4);

    if (config_lookup_string(&cfg, "admin_scope", &str_value) == CONFIG_TRUE) {
      config->glewlwyd_resource_config_admin->oauth_scope = strdup(str_value);
    }
    
    if (config_lookup_string(&cfg, "profile_scope", &str_value) == CONFIG_TRUE) {
      config->glewlwyd_resource_config_profile->oauth_scope = strdup(str_value);
    }
    
    if (int_value_4 == 256 || int_value_4 == 384 || int_value_4 == 512) {
      if (int_value) {
        config_setting_lookup_string(jwt, "rsa_pub_file", &str_value);
        if (str_value != NULL) {
          config->glewlwyd_resource_config_admin->jwt_decode_key = get_file_content(str_value);
          config->glewlwyd_resource_config_profile->jwt_decode_key = get_file_content(str_value);
          if (int_value_4 == 256) {
            config->glewlwyd_resource_config_admin->jwt_alg = JWT_ALG_RS256;
            config->glewlwyd_resource_config_profile->jwt_alg = JWT_ALG_RS256;
          } else if (int_value_4 == 384) {
            config->glewlwyd_resource_config_admin->jwt_alg = JWT_ALG_RS384;
            config->glewlwyd_resource_config_profile->jwt_alg = JWT_ALG_RS384;
          } else if (int_value_4 == 512) {
            config->glewlwyd_resource_config_admin->jwt_alg = JWT_ALG_RS512;
            config->glewlwyd_resource_config_profile->jwt_alg = JWT_ALG_RS512;
          }
          if (config->glewlwyd_resource_config_profile->jwt_decode_key == NULL || config->glewlwyd_resource_config_admin->jwt_decode_key == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error, rsa_pub_file content incorrect\n");
            return 0;
          }
        } else {
          config_destroy(&cfg);
          fprintf(stderr, "Error, rsa_pub_file incorrect\n");
          return 0;
        }
      } else if (int_value_2) {
        config_setting_lookup_string(jwt, "ecdsa_pub_file", &str_value);
        if (str_value != NULL) {
          config->glewlwyd_resource_config_admin->jwt_decode_key = get_file_content(str_value);
          config->glewlwyd_resource_config_profile->jwt_decode_key = get_file_content(str_value);
          if (int_value_4 == 256) {
            config->glewlwyd_resource_config_admin->jwt_alg = JWT_ALG_ES256;
            config->glewlwyd_resource_config_profile->jwt_alg = JWT_ALG_ES256;
          } else if (int_value_4 == 384) {
            config->glewlwyd_resource_config_admin->jwt_alg = JWT_ALG_ES384;
            config->glewlwyd_resource_config_profile->jwt_alg = JWT_ALG_ES384;
          } else if (int_value_4 == 512) {
            config->glewlwyd_resource_config_admin->jwt_alg = JWT_ALG_ES512;
            config->glewlwyd_resource_config_profile->jwt_alg = JWT_ALG_ES512;
          }
          if (config->glewlwyd_resource_config_profile->jwt_decode_key == NULL || config->glewlwyd_resource_config_admin->jwt_decode_key == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error, ecdsa_pub_file content incorrect\n");
            return 0;
          }
        } else {
          config_destroy(&cfg);
          fprintf(stderr, "Error, ecdsa_pub_file incorrect\n");
          return 0;
        }
      } else if (int_value_3) {
        config_setting_lookup_string(jwt, "sha_secret", &str_value);
        if (str_value != NULL) {
          config->glewlwyd_resource_config_admin->jwt_decode_key = o_strdup(str_value);
          config->glewlwyd_resource_config_profile->jwt_decode_key = o_strdup(str_value);
          if (int_value_4 == 256) {
            config->glewlwyd_resource_config_admin->jwt_alg = JWT_ALG_HS256;
            config->glewlwyd_resource_config_profile->jwt_alg = JWT_ALG_HS256;
          } else if (int_value_4 == 384) {
            config->glewlwyd_resource_config_admin->jwt_alg = JWT_ALG_HS384;
            config->glewlwyd_resource_config_profile->jwt_alg = JWT_ALG_HS384;
          } else if (int_value_4 == 512) {
            config->glewlwyd_resource_config_admin->jwt_alg = JWT_ALG_HS512;
            config->glewlwyd_resource_config_profile->jwt_alg = JWT_ALG_HS512;
          }
        } else {
          config_destroy(&cfg);
          fprintf(stderr, "Error, sha_secret incorrect\n");
          return 0;
        }
      } else {
        config_destroy(&cfg);
        fprintf(stderr, "Error, no jwt algorithm selected\n");
        return 0;
      }
    } else {
      config_destroy(&cfg);
      fprintf(stderr, "Error, key_size incorrect, values available are 256, 384 or 512\n");
      return 0;
    }
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

/**
 *
 * Read the content of a file and return it as a char *
 * returned value must be o_free'd after use
 *
 */
char * get_file_content(const char * file_path) {
  char * buffer = NULL;
  size_t length, res;
  FILE * f;

  f = fopen (file_path, "rb");
  if (f) {
    fseek (f, 0, SEEK_END);
    length = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = o_malloc((length+1)*sizeof(char));
    if (buffer) {
      res = fread (buffer, 1, length, f);
      if (res != length) {
        fprintf(stderr, "fread warning, reading %zu while expecting %zu", res, length);
      }
      // Add null character at the end of buffer, just in case
      buffer[length] = '\0';
    }
    fclose (f);
  }
  
  return buffer;
}

/**
 * Return the source ip address of the request
 * Based on the header value "X-Forwarded-For" if set, which means the request is forwarded by a proxy
 * otherwise the call is direct, return the client_address
 */
const char * get_ip_source(const struct _u_request * request) {
  const char * ip_source = u_map_get(request->map_header, "X-Forwarded-For");
  
  if (ip_source == NULL) {
    struct sockaddr_in * in_source = (struct sockaddr_in *)request->client_address;
    if (in_source != NULL) {
      ip_source = inet_ntoa(in_source->sin_addr);
    } else {
      ip_source = "NOT_FOUND";
    }
  }
  
  return ip_source;
};

/**
 * Converts a hex character to its integer value
 */
char from_hex(char ch) {
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/**
 * Converts an integer value to its hex character
 */
char to_hex(char code) {
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

/**
 * Returns a url-encoded version of str
 * IMPORTANT: be sure to o_free() the returned string after use 
 * Thanks Geek Hideout!
 * http://www.geekhideout.com/urlcode.shtml
 */
char * url_encode(char * str) {
  char * pstr = str, * buf = o_malloc(strlen(str) * 3 + 1), * pbuf = buf;
  while (* pstr) {
    if (isalnum(* pstr) || * pstr == '-' || * pstr == '_' || * pstr == '.' || * pstr == '~') 
      * pbuf++ = * pstr;
    else if (* pstr == ' ') 
      * pbuf++ = '+';
    else 
      * pbuf++ = '%', * pbuf++ = to_hex(* pstr >> 4), * pbuf++ = to_hex(* pstr & 15);
    pstr++;
  }
  * pbuf = '\0';
  return buf;
}

/**
 * Returns a url-decoded version of str
 * IMPORTANT: be sure to o_free() the returned string after use
 * Thanks Geek Hideout!
 * http://www.geekhideout.com/urlcode.shtml
 */
char * url_decode(char * str) {
  char * pstr = str, * buf = o_malloc(strlen(str) + 1), * pbuf = buf;
  while (* pstr) {
    if (* pstr == '%') {
      if (pstr[1] && pstr[2]) {
        * pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
        pstr += 2;
      }
    } else if (* pstr == '+') { 
      * pbuf++ = ' ';
    } else {
      * pbuf++ = * pstr;
    }
    pstr++;
  }
  * pbuf = '\0';
  return buf;
}

/**
 *
 * Generates a query string based on url and post parameters of a request
 * Returned value must be o_free'd after use
 *
 */
char * generate_query_parameters(const struct _u_request * request) {
  char * query = NULL, * param, * tmp, * value;
  const char ** keys;
  struct _u_map params;
  int i;
  
  u_map_init(&params);
  
  keys = u_map_enum_keys(request->map_url);
  for (i=0; keys[i] != NULL; i++) {
    u_map_put(&params, keys[i], u_map_get(request->map_url, keys[i]));
  }
  
  keys = u_map_enum_keys(request->map_post_body);
  for (i=0; keys[i] != NULL; i++) {
    u_map_put(&params, keys[i], u_map_get(request->map_post_body, keys[i]));
  }
  
  keys = u_map_enum_keys(&params);
  for (i=0; keys[i] != NULL; i++) {
    value = url_encode((char *)u_map_get(request->map_url, keys[i]));
    param = msprintf("%s=%s", keys[i], value);
    o_free(value);
    if (query == NULL) {
      query = o_strdup(param);
    } else {
      tmp = msprintf("%s&%s", query, param);
      o_free(query);
      query = tmp;
    }
    o_free(param);
  }
  
  u_map_clean(&params);
  
  return query;
}

long random_at_most(long max) {
  unsigned long
  // max <= RAND_MAX < ULONG_MAX, so this is okay.
  num_bins = (unsigned long) max + 1,
  num_rand = (unsigned long) RAND_MAX + 1,
  bin_size = num_rand / num_bins,
  defect   = num_rand % num_bins;

  long x;
  do {
   x = random();
  }
  // This is carefully written not to overflow
  while (num_rand - defect <= (unsigned long)x);

  // Truncated division is intentional
  return x/bin_size;
}

/**
 * Generates a random string and store it in str
 */
char * rand_string(char * str, size_t str_size) {
  const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  size_t n;
  
  if (str_size > 0 && str != NULL) {
    for (n = 0; n < str_size; n++) {
      long key = random_at_most((sizeof(charset)) - 2);
      str[n] = charset[key];
    }
    str[str_size] = '\0';
    return str;
  } else {
    return NULL;
  }
}

int init_user_module_list(struct config_elements * config) {
  int ret = G_OK;
  struct _user_module * cur_user_module = NULL;
  DIR * modules_directory;
  struct dirent * in_file;
  char * file_path;
  void * file_handle;
  
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
        }
        
        file_handle = dlopen(file_path, RTLD_LAZY);
        
        if (file_handle != NULL) {
          cur_user_module = o_malloc(sizeof(struct _user_module));
          if (cur_user_module != NULL) {
            cur_user_module->name = NULL;
            cur_user_module->file_handle = file_handle;
            *(void **) (&cur_user_module->user_module_load) = dlsym(file_handle, "user_module_load");
            *(void **) (&cur_user_module->user_module_unload) = dlsym(file_handle, "user_module_unload");
            *(void **) (&cur_user_module->user_module_init) = dlsym(file_handle, "user_module_init");
            *(void **) (&cur_user_module->user_module_close) = dlsym(file_handle, "user_module_close");
            *(void **) (&cur_user_module->user_module_get_list) = dlsym(file_handle, "user_module_get_list");
            *(void **) (&cur_user_module->user_module_get) = dlsym(file_handle, "user_module_get");
            *(void **) (&cur_user_module->user_module_add) = dlsym(file_handle, "user_module_add");
            *(void **) (&cur_user_module->user_module_update) = dlsym(file_handle, "user_module_update");
            *(void **) (&cur_user_module->user_module_delete) = dlsym(file_handle, "user_module_delete");
            *(void **) (&cur_user_module->user_module_check_password) = dlsym(file_handle, "user_module_check_password");
            
            if (cur_user_module->user_module_load != NULL &&
                cur_user_module->user_module_unload != NULL &&
                cur_user_module->user_module_init != NULL &&
                cur_user_module->user_module_close != NULL &&
                cur_user_module->user_module_get_list != NULL &&
                cur_user_module->user_module_get != NULL &&
                cur_user_module->user_module_add != NULL &&
                cur_user_module->user_module_update != NULL &&
                cur_user_module->user_module_delete != NULL &&
                cur_user_module->user_module_check_password != NULL) {
              if (cur_user_module->user_module_load(config, &cur_user_module->name) == G_OK) {
                config->user_module_list = realloc(config->user_module_list, (config->user_module_list_size + 1) * sizeof(struct _user_module *));
                if (config->user_module_list != NULL) {
                  y_log_message(Y_LOG_LEVEL_INFO, "Loading user module %s - %s", file_path, cur_user_module->name);
                  config->user_module_list[config->user_module_list_size] = cur_user_module;
                  config->user_module_list_size++;
                } else {
                  cur_user_module->user_module_unload(config);
                  dlclose(file_handle);
                  o_free(cur_user_module);
                  y_log_message(Y_LOG_LEVEL_ERROR, "init_user_module_list - Error reallocating resources for user_module_list");
                  ret = G_ERROR_MEMORY;
                }
              } else {
                dlclose(file_handle);
                o_free(cur_user_module);
                y_log_message(Y_LOG_LEVEL_ERROR, "init_user_module_list - Error user_module_init for module %s", file_path);
                ret = G_ERROR_MEMORY;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "init_user_module_list - Error module %s has not all required functions", file_path);
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
        o_free(file_path);
      }
    }
    closedir(modules_directory);
  }
  
  return ret;
}

int load_user_module_instance_list(struct config_elements * config) {
  json_t * j_query, * j_result, * j_instance;
  int res, ret, i;
  size_t index;
  struct _user_module_instance * cur_instance;
  struct _user_module * module;
  
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
      for (i=0; i<config->user_module_list_size && module == NULL; i++) {
        if (0 == o_strcmp(config->user_module_list[i]->name, json_string_value(json_object_get(j_instance, "module")))) {
          module = config->user_module_list[i];
        }
      }
      if (module != NULL) {
        cur_instance = o_malloc(sizeof(struct _user_module_instance));
        if (cur_instance != NULL) {
          cur_instance->cls = NULL;
          cur_instance->name = o_strdup(json_string_value(json_object_get(j_instance, "name")));
          cur_instance->module = module;
          config->user_module_instance_list = o_realloc(config->user_module_instance_list, (config->user_module_instance_list_size + 1) * sizeof(struct _user_module_instance *));
          if (config->user_module_instance_list != NULL) {
            if (module->user_module_init(config, json_string_value(json_object_get(j_instance, "parameters")), &cur_instance->cls) == G_OK) {
              cur_instance->enabled = 1;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "load_user_module_instance_list - Error init module %s/%s", module->name, json_string_value(json_object_get(j_instance, "name")));
              cur_instance->enabled = 0;
            }
            config->user_module_instance_list[config->user_module_instance_list_size] = cur_instance;
            config->user_module_instance_list_size++;
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
  return ret;
}

struct _user_module_instance * get_user_module_instance(struct config_elements * config, const char * name) {
  int i;

  for (i=0; i<config->user_module_instance_list_size; i++) {
    if (0 == o_strcmp(config->user_module_instance_list[i]->name, name)) {
      return config->user_module_instance_list[i];
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
        }
        
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
            
            if (cur_user_auth_scheme_module->user_auth_scheme_module_load != NULL &&
                cur_user_auth_scheme_module->user_auth_scheme_module_unload != NULL &&
                cur_user_auth_scheme_module->user_auth_scheme_module_init != NULL &&
                cur_user_auth_scheme_module->user_auth_scheme_module_close != NULL &&
                cur_user_auth_scheme_module->user_auth_scheme_module_validate != NULL) {
              if (cur_user_auth_scheme_module->user_auth_scheme_module_load(config, &cur_user_auth_scheme_module->name) == G_OK) {
                config->user_auth_scheme_module_list = realloc(config->user_auth_scheme_module_list, (config->user_auth_scheme_module_list_size + 1) * sizeof(struct _user_auth_scheme_module *));
                if (config->user_auth_scheme_module_list != NULL) {
                  y_log_message(Y_LOG_LEVEL_INFO, "Loading user auth scheme module %s - %s", file_path, cur_user_auth_scheme_module->name);
                  config->user_auth_scheme_module_list[config->user_auth_scheme_module_list_size] = cur_user_auth_scheme_module;
                  config->user_auth_scheme_module_list_size++;
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
        o_free(file_path);
      }
    }
    closedir(modules_directory);
  }
  
  return ret;
}

int load_user_auth_scheme_module_instance_list(struct config_elements * config) {
  json_t * j_query, * j_result, * j_instance;
  int res, ret, i;
  size_t index;
  struct _user_auth_scheme_module_instance * cur_instance;
  struct _user_auth_scheme_module * module;
  
  j_query = json_pack("{sss[ssss]ss}",
                      "table",
                      GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE,
                      "columns",
                        "guasmi_module AS module",
                        "guasmi_name AS name",
                        "guasmi_order AS order_by",
                        "guasmi_parameters AS parameters",
                      "order_by",
                      "guasmi_order");
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_instance) {
      module = NULL;
      for (i=0; i<config->user_auth_scheme_module_list_size && NULL == module; i++) {
        if (0 == o_strcmp(config->user_auth_scheme_module_list[i]->name, json_string_value(json_object_get(j_instance, "module")))) {
          module = config->user_auth_scheme_module_list[i];
        }
      }
      if (module != NULL) {
        cur_instance = o_malloc(sizeof(struct _user_auth_scheme_module_instance));
        if (cur_instance != NULL) {
          cur_instance->cls = NULL;
          cur_instance->name = o_strdup(json_string_value(json_object_get(j_instance, "name")));
          cur_instance->module = module;
          config->user_auth_scheme_module_instance_list = o_realloc(config->user_auth_scheme_module_instance_list, (config->user_auth_scheme_module_instance_list_size + 1) * sizeof(struct _user_module_instance *));
          if (config->user_auth_scheme_module_instance_list != NULL) {
            if (module->user_auth_scheme_module_init(config, json_string_value(json_object_get(j_instance, "parameters")), &cur_instance->cls) == G_OK) {
              cur_instance->enabled = 1;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "load_user_auth_scheme_module_instance_list - Error init module %s/%s", module->name, json_string_value(json_object_get(j_instance, "name")));
              cur_instance->enabled = 0;
            }
            config->user_auth_scheme_module_instance_list[config->user_auth_scheme_module_instance_list_size] = cur_instance;
            config->user_auth_scheme_module_instance_list_size++;
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
  return ret;
}

struct _user_auth_scheme_module_instance * get_user_auth_scheme_module_instance(struct config_elements * config, const char * name) {
  int i;

  for (i=0; i<config->user_auth_scheme_module_instance_list_size; i++) {
    if (0 == o_strcmp(config->user_auth_scheme_module_instance_list[i]->name, name)) {
      return config->user_auth_scheme_module_instance_list[i];
    }
  }
  return NULL;
}

int init_client_module_list(struct config_elements * config) {
  return G_ERROR;
}

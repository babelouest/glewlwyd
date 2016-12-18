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
 * and main process start
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

#include <ldap.h>
#include <getopt.h>
#include <signal.h>
#include <ctype.h>
#include <libconfig.h>
#include <openssl/md5.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
  struct config_elements * config = malloc(sizeof(struct config_elements));
  int res;
  
  srand(time(NULL));
  if (config == NULL) {
    fprintf(stderr, "Memory error - config\n");
    return 1;
  }
  
  // Init config structure with default values
  config->config_file = NULL;
  config->url_prefix = NULL;
  config->log_mode = Y_LOG_MODE_NONE;
  config->log_level = Y_LOG_LEVEL_NONE;
  config->log_file = NULL;
  config->use_scope = 0;
  config->conn = NULL;
  config->instance = malloc(sizeof(struct _u_instance));
  config->allow_origin = NULL;
  config->static_files_path = NULL;
  config->static_files_prefix = NULL;
  config->auth_ldap = NULL;
  config->refresh_token_expiration = GLEWLWYD_REFRESH_TOKEN_EXP_DEFAULT;
  config->access_token_expiration = GLEWLWYD_ACCESS_TOKEN_EXP_DEFAULT;
  config->jwt_decode_key = NULL;
  config->session_key = nstrdup(GLEWLWYD_SESSION_KEY_DEFAULT);
  config->session_expiration = GLEWLWYD_SESSION_EXPIRATION_DEFAULT;
  config->admin_scope = nstrdup(GLEWLWYD_ADMIN_SCOPE);
  config->use_secure_connection = 0;
  config->secure_connection_key_file = NULL;
  config->secure_connection_pem_file = NULL;
  if (config->instance == NULL) {
    fprintf(stderr, "Memory error - config->instance\n");
    return 1;
  }
  ulfius_init_instance(config->instance, -1, NULL);

  config->mime_types = malloc(sizeof(struct _u_map));
  if (config->mime_types == NULL) {
    y_log_message(Y_LOG_LEVEL_ERROR, "init - Error allocating resources for config->mime_types, aborting");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  u_map_init(config->mime_types);
  u_map_put(config->mime_types, "*", "application/octet-stream");
  
  global_handler_variable = GLEWLWYD_RUNNING;
  // Catch end signals to make a clean exit
  signal (SIGQUIT, exit_handler);
  signal (SIGINT, exit_handler);
  signal (SIGTERM, exit_handler);
  signal (SIGHUP, exit_handler);

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
  
  // At this point, we declare all API endpoints and configure 
  
  // Authorization endpoint
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/auth/", NULL, NULL, NULL, &callback_glewlwyd_authorization, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/auth/", NULL, NULL, NULL, &callback_glewlwyd_authorization, (void*)config);

  // Token endpoint
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/token/", NULL, NULL, NULL, &callback_glewlwyd_token, (void*)config);

  // Authentication
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/user/auth/", &callback_glewlwyd_check_user_session, (void*)config, NULL, &callback_glewlwyd_get_user_session, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/user/auth/", NULL, NULL, NULL, &callback_glewlwyd_validate_user_session, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/user/auth/", &callback_glewlwyd_check_user_session, (void*)config, NULL, &callback_glewlwyd_delete_user_session, (void*)config);

  // Current user scope grant endpoints
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/user/grant/", &callback_glewlwyd_check_user, (void*)config, NULL, &callback_glewlwyd_get_user_session_scope_grant, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/user/grant/", &callback_glewlwyd_check_user, (void*)config, NULL, &callback_glewlwyd_set_user_scope_grant, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/user/grant/", &callback_glewlwyd_check_user, (void*)config, NULL, &callback_glewlwyd_user_scope_delete, (void*)config);

  // Current user endpoints
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/user/profile/", &callback_glewlwyd_check_user, (void*)config, NULL, &callback_glewlwyd_get_user_session_profile, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->url_prefix, "/user/profile/", &callback_glewlwyd_check_user, (void*)config, NULL, &callback_glewlwyd_set_user_profile, (void*)config);

  // Authorization type callbacks
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/response_type/", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_get_response_type, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->url_prefix, "/response_type/:authorization_type", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_set_response_type, (void*)config);

  // Scope endpoints
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/scope/", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_get_list_scope, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/scope/:scope", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_get_scope, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/scope/", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_add_scope, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->url_prefix, "/scope/:scope", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_set_scope, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/scope/:scope", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_delete_scope, (void*)config);

  // User endpoints
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/user/", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_get_list_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/user/:username", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_get_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/user/", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_add_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->url_prefix, "/user/:username", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_set_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/user/:username", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_delete_user, (void*)config);

  // Client endpoints
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/client/", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_get_list_client, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/client/:client_id", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_get_client, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/client/", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_add_client, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->url_prefix, "/client/:client_id", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_set_client, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/client/:client_id", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_delete_client, (void*)config);

  // Resource endpoints
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/resource/", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_get_list_resource, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/resource/:resource", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_get_resource, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/resource/", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_add_resource, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->url_prefix, "/resource/:resource", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_set_resource, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/resource/:resource", &callback_glewlwyd_check_scope_admin, (void*)config, NULL, &callback_glewlwyd_delete_resource, (void*)config);

  // Other configuration
  ulfius_add_endpoint_by_val(config->instance, "GET", "/", NULL, NULL, NULL, NULL, &callback_glewlwyd_root, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", "/api/", NULL, NULL, NULL, NULL, &callback_glewlwyd_api_description, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "OPTIONS", NULL, "*", NULL, NULL, NULL, &callback_glewlwyd_options, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->static_files_prefix, "*", NULL, NULL, NULL, &callback_glewlwyd_static_file, (void*)config);
  ulfius_set_default_endpoint(config->instance, NULL, NULL, NULL, &callback_default, (void*)config);

  // Set default headers
  u_map_put(config->instance->default_headers, "Access-Control-Allow-Origin", config->allow_origin);
  u_map_put(config->instance->default_headers, "Access-Control-Allow-Credentials", "true");
  u_map_put(config->instance->default_headers, "Cache-Control", "no-store");
  u_map_put(config->instance->default_headers, "Pragma", "no-cache");

  y_log_message(Y_LOG_LEVEL_INFO, "Start glewlwyd on port %d, prefix: %s, secure: %s", config->instance->port, config->url_prefix, config->use_secure_connection?"true":"false");
  
  if (config->use_secure_connection) {
    char * key_file = get_file_content(config->secure_connection_key_file);
    char * pem_file = get_file_content(config->secure_connection_pem_file);
    if (key_file != NULL && pem_file != NULL) {
      res = ulfius_start_secure_framework(config->instance, key_file, pem_file);
    } else {
      res = U_ERROR_PARAMS;
    }
    free(key_file);
    free(pem_file);
  } else {
    res = ulfius_start_framework(config->instance);
  }
  if (res == U_OK) {
    // Loop until stop signal is broadcasted
    while (global_handler_variable == GLEWLWYD_RUNNING) {
      sleep(1);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error starting glewlwyd webserver");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  exit_server(&config, GLEWLWYD_STOP);
  return 0;
}

/**
 * Exit properly the server by closing opened connections, databases and files
 */
void exit_server(struct config_elements ** config, int exit_value) {
  
  if (config != NULL && *config != NULL) {
    // Cleaning data
    free((*config)->config_file);
    free((*config)->url_prefix);
    free((*config)->log_file);
    free((*config)->allow_origin);
    free((*config)->static_files_path);
    free((*config)->static_files_prefix);
    free((*config)->jwt_decode_key);
    free((*config)->session_key);
    free((*config)->admin_scope);
    free((*config)->secure_connection_key_file);
    free((*config)->secure_connection_pem_file);
    jwt_free((*config)->jwt);
    u_map_clean_full((*config)->mime_types);
    if ((*config)->auth_ldap != NULL) {
      free((*config)->auth_ldap->uri);
      free((*config)->auth_ldap->bind_dn);
      free((*config)->auth_ldap->bind_passwd);
      free((*config)->auth_ldap->filter);
      free((*config)->auth_ldap->login_property);
      free((*config)->auth_ldap->scope_property);
      free((*config)->auth_ldap->base_search);
      free((*config)->auth_ldap->name_property);
      free((*config)->auth_ldap->email_property);
      free((*config)->auth_ldap);
    }
    h_close_db((*config)->conn);
    h_clean_connection((*config)->conn);
    ulfius_stop_framework((*config)->instance);
    ulfius_clean_instance((*config)->instance);
    free((*config)->instance);
    y_close_logs();
    
    free(*config);
    (*config) = NULL;
  }
  exit(exit_value);
}

/**
 * Initialize the application configuration based on the command line parameters
 */
int build_config_from_args(int argc, char ** argv, struct config_elements * config) {
  int next_option;
  const char * short_options = "c::p::u::m::l::f::h::";
  char * tmp = NULL, * to_free = NULL, * one_log_mode = NULL;
  static const struct option long_options[]= {
    {"config-file", optional_argument, NULL, 'c'},
    {"port", optional_argument, NULL, 'p'},
    {"url-prefix", optional_argument, NULL, 'u'},
    {"log-mode", optional_argument, NULL, 'm'},
    {"log-level", optional_argument, NULL, 'l'},
    {"log-file", optional_argument, NULL, 'f'},
    {"help", optional_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
  };
  
  if (config != NULL) {
    do {
      next_option = getopt_long(argc, argv, short_options, long_options, NULL);
      
      switch (next_option) {
        case 'c':
          if (optarg != NULL) {
            config->config_file = nstrdup(optarg);
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
            config->url_prefix = nstrdup(optarg);
            if (config->url_prefix == NULL) {
              fprintf(stderr, "Error allocating config->url_prefix, exiting\n");
              exit_server(&config, GLEWLWYD_STOP);
            }
          } else {
            fprintf(stderr, "Error!\nNo URL prefix specified\n");
            return 0;
          }
          break;
        case 'm':
          if (optarg != NULL) {
            tmp = nstrdup(optarg);
            if (tmp == NULL) {
              fprintf(stderr, "Error allocating log_mode, exiting\n");
              exit_server(&config, GLEWLWYD_STOP);
            }
            one_log_mode = strtok(tmp, ",");
            while (one_log_mode != NULL) {
              if (0 == strncmp("console", one_log_mode, strlen("console"))) {
                config->log_mode |= Y_LOG_MODE_CONSOLE;
              } else if (0 == strncmp("syslog", one_log_mode, strlen("syslog"))) {
                config->log_mode |= Y_LOG_MODE_SYSLOG;
              } else if (0 == strncmp("file", one_log_mode, strlen("file"))) {
                config->log_mode |= Y_LOG_MODE_FILE;
              }
              one_log_mode = strtok(NULL, ",");
            }
            free(to_free);
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
            config->log_file = nstrdup(optarg);
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
  fprintf(output, "\nGlewlwyd Messaging REST Webservice\n");
  fprintf(output, "\n");
  fprintf(output, "Messaging system using a JSON/REST interface\n");
  fprintf(output, "\n");
  fprintf(output, "-c --config-file=PATH\n");
  fprintf(output, "\tPath to configuration file\n");
  fprintf(output, "-p --port=PORT\n");
  fprintf(output, "\tPort to listen to\n");
  fprintf(output, "-u --url-prefix=PREFIX\n");
  fprintf(output, "\tURL prefix\n");
  fprintf(output, "-m --log-mode=MODE\n");
  fprintf(output, "\tLog Mode\n");
  fprintf(output, "\tconsole, syslog or file\n");
  fprintf(output, "\tIf you want multiple modes, separate them with a comma \",\"\n");
  fprintf(output, "\tdefault: console\n");
  fprintf(output, "-l --log-level=LEVEL\n");
  fprintf(output, "\tLog level\n");
  fprintf(output, "\tNONE, ERROR, WARNING, INFO, DEBUG\n");
  fprintf(output, "\tdefault: ERROR\n");
  fprintf(output, "-f --log-file=PATH\n");
  fprintf(output, "\tPath for log file if log mode file is specified\n");
  fprintf(output, "-h --help\n");
  fprintf(output, "\tPrint this message\n\n");
}

/**
 * handles signal catch to exit properly when ^C is used for example
 * I don't like global variables but it looks fine to people who designed this
 */
void exit_handler(int signal) {
  y_log_message(Y_LOG_LEVEL_INFO, "Glewlwyd caught a stop or kill signal (%d), exiting", signal);
  global_handler_variable = GLEWLWYD_STOP;
}

/**
 *
 * Read the content of a file and return it as a char *
 * returned value must be free'd after use
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
    buffer = malloc((length+1)*sizeof(char));
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
 * Initialize the application configuration based on the config file content
 * Read the config file, get mandatory variables and devices
 */
int build_config_from_file(struct config_elements * config) {
  
  config_t cfg;
  config_setting_t * root, * database, * auth, * jwt, * mime_type_list, * mime_type;
  const char * cur_prefix, * cur_log_mode, * cur_log_level, * cur_log_file = NULL, * one_log_mode, 
             * db_type, * db_sqlite_path, * db_mariadb_host = NULL, * db_mariadb_user = NULL, * db_mariadb_password = NULL, * db_mariadb_dbname = NULL, * cur_allow_origin = NULL, * cur_static_files_path = NULL, * cur_static_files_prefix = NULL, * cur_session_key = NULL, * cur_admin_scope = NULL,
             * cur_auth_ldap_uri = NULL, * cur_auth_ldap_bind_dn = NULL, * cur_auth_ldap_bind_passwd = NULL, * cur_auth_ldap_filter = NULL, * cur_auth_ldap_login_property = NULL, * cur_auth_ldap_scope_property = NULL, * cur_auth_ldap_base_search = NULL, * cur_auth_ldap_name_property = NULL, * cur_auth_ldap_email_property = NULL,
             * cur_rsa_key_file = NULL, * cur_rsa_pub_file = NULL, * cur_sha_secret = NULL,
             * extension = NULL, * mime_type_value = NULL,
             * cur_secure_connection_key_file = NULL, * cur_secure_connection_pem_file = NULL;
  int db_mariadb_port = 0;
  int cur_database_auth = 0, cur_ldap_auth = 0, cur_use_scope = 0, cur_use_rsa = 0, cur_use_sha = 0, cur_use_secure_connection = 0, i;
  
  config_init(&cfg);
  
  if (!config_read_file(&cfg, config->config_file)) {
    fprintf(stderr, "Error parsing config file %s\nOn line %d error: %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
    config_destroy(&cfg);
    return 0;
  }
  
  if (config->instance->port == -1) {
    // Get Port number to listen to
    config_lookup_int(&cfg, "port", &(config->instance->port));
  }
  
  if (config->url_prefix == NULL) {
    // Get prefix url
    if (config_lookup_string(&cfg, "url_prefix", &cur_prefix)) {
      config->url_prefix = nstrdup(cur_prefix);
      if (config->url_prefix == NULL) {
        fprintf(stderr, "Error allocating config->url_prefix, exiting\n");
        config_destroy(&cfg);
        return 0;
      }
    }
  }

  if (config->log_mode == Y_LOG_MODE_NONE) {
    // Get log mode
    if (config_lookup_string(&cfg, "log_mode", &cur_log_mode)) {
      one_log_mode = strtok((char *)cur_log_mode, ",");
      while (one_log_mode != NULL) {
        if (0 == strncmp("console", one_log_mode, strlen("console"))) {
          config->log_mode |= Y_LOG_MODE_CONSOLE;
        } else if (0 == strncmp("syslog", one_log_mode, strlen("syslog"))) {
          config->log_mode |= Y_LOG_MODE_SYSLOG;
        } else if (0 == strncmp("file", one_log_mode, strlen("file"))) {
          config->log_mode |= Y_LOG_MODE_FILE;
          // Get log file path
          if (config->log_file == NULL) {
            if (config_lookup_string(&cfg, "log_file", &cur_log_file)) {
              config->log_file = nstrdup(cur_log_file);
              if (config->log_file == NULL) {
                fprintf(stderr, "Error allocating config->log_file, exiting\n");
                config_destroy(&cfg);
                return 0;
              }
            }
          }
        }
        one_log_mode = strtok(NULL, ",");
      }
    }
  }
  
  if (config->log_level == Y_LOG_LEVEL_NONE) {
    // Get log level
    if (config_lookup_string(&cfg, "log_level", &cur_log_level)) {
      if (0 == strncmp("NONE", cur_log_level, strlen("NONE"))) {
        config->log_level = Y_LOG_LEVEL_NONE;
      } else if (0 == strncmp("ERROR", cur_log_level, strlen("ERROR"))) {
        config->log_level = Y_LOG_LEVEL_ERROR;
      } else if (0 == strncmp("WARNING", cur_log_level, strlen("WARNING"))) {
        config->log_level = Y_LOG_LEVEL_WARNING;
      } else if (0 == strncmp("INFO", cur_log_level, strlen("INFO"))) {
        config->log_level = Y_LOG_LEVEL_INFO;
      } else if (0 == strncmp("DEBUG", cur_log_level, strlen("DEBUG"))) {
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
    if (config_lookup_string(&cfg, "allow_origin", &cur_allow_origin)) {
      config->allow_origin = nstrdup(cur_allow_origin);
      if (config->allow_origin == NULL) {
        fprintf(stderr, "Error allocating config->allow_origin, exiting\n");
        config_destroy(&cfg);
        return 0;
      }
    }
  }
  
  config_lookup_int(&cfg, "refresh_token_expiation", (int *)&config->refresh_token_expiration);
  config_lookup_int(&cfg, "access_token_expiration", (int *)&config->access_token_expiration);
  config_lookup_int(&cfg, "session_expiration", (int *)&config->session_expiration);
  
  config_lookup_string(&cfg, "session_key", &cur_session_key);
  if (cur_session_key != NULL) {
    free(config->session_key);
    config->session_key = strdup(cur_session_key);
  }
  
  config_lookup_string(&cfg, "admin_scope", &cur_admin_scope);
  if (cur_admin_scope != NULL) {
    free(config->admin_scope);
    config->admin_scope = strdup(cur_admin_scope);
  }
  
  config_lookup_bool(&cfg, "use_scope", &cur_use_scope);
  config->use_scope = cur_use_scope;
  
  if (config->static_files_path == NULL) {
    // Get path that serve static files
    if (config_lookup_string(&cfg, "static_files_path", &cur_static_files_path)) {
      config->static_files_path = nstrdup(cur_static_files_path);
      if (config->static_files_path == NULL) {
        fprintf(stderr, "Error allocating config->static_files_path, exiting\n");
        config_destroy(&cfg);
        return 0;
      }
    }
  }

  if (config->static_files_prefix == NULL) {
    // Get prefix url
    if (config_lookup_string(&cfg, "static_files_prefix", &cur_static_files_prefix)) {
      config->static_files_prefix = nstrdup(cur_static_files_prefix);
      if (config->static_files_prefix == NULL) {
        fprintf(stderr, "Error allocating config->static_files_prefix, exiting\n");
        config_destroy(&cfg);
        return 0;
      }
    }
  }
  
  // Populate mime types u_map
  mime_type_list = config_lookup(&cfg, "static_files_mime_types");
  if (mime_type_list != NULL) {
    for (i=0; i<config_setting_length(mime_type_list); i++) {
      mime_type = config_setting_get_elem(mime_type_list, i);
      if (mime_type != NULL) {
        if (config_setting_lookup_string(mime_type, "extension", &extension) && config_setting_lookup_string(mime_type, "type", &mime_type_value)) {
          u_map_put(config->mime_types, extension, mime_type_value);
        }
      }
    }
  }
  
  if (config_lookup_bool(&cfg, "use_secure_connection", &cur_use_secure_connection)) {
    if (config_lookup_string(&cfg, "secure_connection_key_file", &cur_secure_connection_key_file) && config_lookup_string(&cfg, "secure_connection_pem_file", &cur_secure_connection_pem_file)) {
      config->use_secure_connection = cur_use_secure_connection;
      config->secure_connection_key_file = nstrdup(cur_secure_connection_key_file);
      config->secure_connection_pem_file = nstrdup(cur_secure_connection_pem_file);
    } else {
      fprintf(stderr, "Error secure connection is active but certificate is not valid, exiting\n");
      config_destroy(&cfg);
      return 0;
    }
  }
  
  root = config_root_setting(&cfg);
  database = config_setting_get_member(root, "database");
  if (database != NULL) {
    if (config_setting_lookup_string(database, "type", &db_type) == CONFIG_TRUE) {
      if (0 == strncmp(db_type, "sqlite3", strlen("sqlite3"))) {
        if (config_setting_lookup_string(database, "path", &db_sqlite_path) == CONFIG_TRUE) {
          config->conn = h_connect_sqlite(db_sqlite_path);
          if (config->conn == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error opening sqlite database %s\n", db_sqlite_path);
            return 0;
          }
        } else {
          config_destroy(&cfg);
          fprintf(stderr, "Error, no sqlite database specified\n");
          return 0;
        }
      } else if (0 == strncmp(db_type, "mariadb", strlen("mariadb"))) {
        config_setting_lookup_string(database, "host", &db_mariadb_host);
        config_setting_lookup_string(database, "user", &db_mariadb_user);
        config_setting_lookup_string(database, "password", &db_mariadb_password);
        config_setting_lookup_string(database, "dbname", &db_mariadb_dbname);
        config_setting_lookup_int(database, "port", &db_mariadb_port);
        config->conn = h_connect_mariadb(db_mariadb_host, db_mariadb_user, db_mariadb_password, db_mariadb_dbname, db_mariadb_port, NULL);
        if (config->conn == NULL) {
          fprintf(stderr, "Error opening mariadb database %s\n", db_mariadb_dbname);
          config_destroy(&cfg);
          return 0;
        }
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
  
  auth = config_setting_get_member(root, "authentication");
  if (auth != NULL) {
    config_setting_lookup_bool(auth, "database_auth", &cur_database_auth);
    config->has_auth_database = cur_database_auth;
    config_setting_lookup_bool(auth, "ldap_auth", &cur_ldap_auth);
    config->has_auth_ldap = cur_ldap_auth;
    
    if (config->has_auth_ldap) {
      config_setting_lookup_string(auth, "uri", &cur_auth_ldap_uri);
      config_setting_lookup_string(auth, "bind_dn", &cur_auth_ldap_bind_dn);
      config_setting_lookup_string(auth, "bind_passwd", &cur_auth_ldap_bind_passwd);
      config_setting_lookup_string(auth, "filter", &cur_auth_ldap_filter);
      config_setting_lookup_string(auth, "login_property", &cur_auth_ldap_login_property);
      config_setting_lookup_string(auth, "name_property", &cur_auth_ldap_name_property);
      config_setting_lookup_string(auth, "email_property", &cur_auth_ldap_email_property);
      if (config->use_scope) {
        config_setting_lookup_string(auth, "scope_property", &cur_auth_ldap_scope_property);
      }
      config_setting_lookup_string(auth, "base_search", &cur_auth_ldap_base_search);
      if (cur_auth_ldap_uri != NULL && cur_auth_ldap_bind_dn != NULL && cur_auth_ldap_bind_passwd != NULL && cur_auth_ldap_filter != NULL && cur_auth_ldap_login_property != NULL && (cur_auth_ldap_scope_property != NULL || !config->use_scope) && cur_auth_ldap_base_search != NULL && cur_auth_ldap_name_property != NULL && cur_auth_ldap_email_property != NULL) {
        config->auth_ldap = malloc(sizeof(struct _auth_ldap));
        if (config->auth_ldap == NULL) {
          config_destroy(&cfg);
          fprintf(stderr, "Error allocating resources for config->auth_ldap\n");
          return 0;
        } else {
          config->auth_ldap->uri = nstrdup(cur_auth_ldap_uri);
          if (config->auth_ldap->uri == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->uri\n");
            return 0;
          }
          config->auth_ldap->bind_dn = nstrdup(cur_auth_ldap_bind_dn);
          if (config->auth_ldap->bind_dn == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->bind_dn\n");
            return 0;
          }
          config->auth_ldap->bind_passwd = nstrdup(cur_auth_ldap_bind_passwd);
          if (config->auth_ldap->bind_passwd == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->bind_passwd\n");
            return 0;
          }
          config->auth_ldap->filter = nstrdup(cur_auth_ldap_filter);
          if (config->auth_ldap->filter == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->filter\n");
            return 0;
          }
          config->auth_ldap->login_property = nstrdup(cur_auth_ldap_login_property);
          if (config->auth_ldap->login_property == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->login_property\n");
            return 0;
          }
          config->auth_ldap->scope_property = nstrdup(cur_auth_ldap_scope_property);
          if (config->auth_ldap->scope_property == NULL && config->use_scope) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->scope_property\n");
            return 0;
          }
          config->auth_ldap->base_search = nstrdup(cur_auth_ldap_base_search);
          if (config->auth_ldap->base_search == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->base_search\n");
            return 0;
          }
          config->auth_ldap->name_property = nstrdup(cur_auth_ldap_name_property);
          if (config->auth_ldap->name_property == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->name_property\n");
            return 0;
          }
          config->auth_ldap->email_property = nstrdup(cur_auth_ldap_email_property);
          if (config->auth_ldap->email_property == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->email_property\n");
            return 0;
          }
        }
      } else {
        config_destroy(&cfg);
        fprintf(stderr, "Error, auth ldap error parameters\n");
        return 0;
      }
    }
  }

  jwt = config_setting_get_member(root, "jwt");
  if (auth != NULL) {
    config_setting_lookup_bool(jwt, "use_rsa", &cur_use_rsa);
    config_setting_lookup_bool(jwt, "use_sha", &cur_use_sha);
    if (cur_use_rsa) {
      config_setting_lookup_string(jwt, "rsa_key_file", &cur_rsa_key_file);
      config_setting_lookup_string(jwt, "rsa_pub_file", &cur_rsa_pub_file);
      if (cur_rsa_key_file != NULL && cur_rsa_pub_file != NULL) {
        char * key;
        size_t key_len;
        
        jwt_new(&(config->jwt));
        key = get_file_content(cur_rsa_key_file);
        if (key != NULL) {
          key_len = strlen(key);
          jwt_set_alg(config->jwt, JWT_ALG_RS512, (const unsigned char *)key, key_len);
          free(key);
        } else {
          config_destroy(&cfg);
          fprintf(stderr, "Error, rsa_key_file content incorrect\n");
          return 0;
        }
        
        config->jwt_decode_key = get_file_content(cur_rsa_pub_file);
        if (config->jwt_decode_key == NULL) {
          config_destroy(&cfg);
          fprintf(stderr, "Error, rsa_pub_file content incorrect\n");
          return 0;
        }
      } else {
        config_destroy(&cfg);
        fprintf(stderr, "Error, rsa_key_file or rsa_pub_file incorrect\n");
        return 0;
      }
    } else if (cur_use_sha) {
      jwt_new(&(config->jwt));
      config_setting_lookup_string(jwt, "sha_secret", &cur_sha_secret);
      if (cur_sha_secret != NULL) {
        jwt_set_alg(config->jwt, JWT_ALG_HS512, (const unsigned char *)cur_sha_secret, strlen(cur_sha_secret));
        config->jwt_decode_key = nstrdup(cur_sha_secret);
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
  
  if (config->url_prefix == NULL) {
    config->url_prefix = nstrdup(GLEWLWYD_DEFAULT_PREFIX);
    if (config->url_prefix == NULL) {
      fprintf(stderr, "Error allocating url_prefix, exit\n");
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
 * Return the filename extension
 */
const char * get_filename_ext(const char *path) {
    const char *dot = strrchr(path, '.');
    if(!dot || dot == path) return "*";
    if (strchr(dot, '?') != NULL) {
      *strchr(dot, '?') = '\0';
    }
    return dot;
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
 * IMPORTANT: be sure to free() the returned string after use 
 * Thanks Geek Hideout!
 * http://www.geekhideout.com/urlcode.shtml
 */
char * url_encode(char * str) {
  char * pstr = str, * buf = malloc(strlen(str) * 3 + 1), * pbuf = buf;
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
 * IMPORTANT: be sure to free() the returned string after use
 * Thanks Geek Hideout!
 * http://www.geekhideout.com/urlcode.shtml
 */
char * url_decode(char * str) {
  char * pstr = str, * buf = malloc(strlen(str) + 1), * pbuf = buf;
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
 * Converts a string into a md5 hash
 * Returned value must be free'd after use
 *
 */
char * str2md5(const char * str, int length) {
  int n;
  MD5_CTX c;
  unsigned char digest[16];
  char *out = (char*)malloc(33);

  MD5_Init(&c);

  while (length > 0) {
    if (length > 512) {
      MD5_Update(&c, str, 512);
    } else {
      MD5_Update(&c, str, length);
    }
    length -= 512;
    str += 512;
  }

  MD5_Final(digest, &c);

  for (n = 0; n < 16; ++n) {
    snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
  }

  return out;
}

/**
 *
 * Generates a query string based on url and post parameters of a request
 * Returned value must be free'd after use
 *
 */
char * generate_query_parameters(const struct _u_request * request) {
  char * query = NULL, * param, * tmp;
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
    param = msprintf("%s=%s", keys[i], u_map_get(&params, keys[i]));
    if (query == NULL) {
      query = nstrdup(param);
    } else {
      tmp = msprintf("%s&%s", query, param);
      free(query);
      query = tmp;
    }
    free(param);
  }
  
  u_map_clean(&params);
  
  return query;
}

/**
 *
 * Decode a u_map into a string
 * Returned value must be free'd after use
 *
 */
char * print_map(const struct _u_map * map) {
  char * line, * to_return = NULL;
  const char **keys, * value;
  int len, i;
  if (map != NULL) {
    keys = u_map_enum_keys(map);
    for (i=0; keys[i] != NULL; i++) {
      value = u_map_get(map, keys[i]);
      len = snprintf(NULL, 0, "key is %s, value is %s", keys[i], value);
      line = malloc((len+1)*sizeof(char));
      snprintf(line, (len+1), "key is %s, value is %s", keys[i], value);
      if (to_return != NULL) {
        len = strlen(to_return) + strlen(line) + 1;
        to_return = realloc(to_return, (len+1)*sizeof(char));
        if (strlen(to_return) > 0) {
          strcat(to_return, "\n");
        }
      } else {
                to_return = malloc((strlen(line) + 1)*sizeof(char));
                to_return[0] = 0;
      }
      strcat(to_return, line);
      free(line);
    }
    return to_return;
  } else {
    return NULL;
  }
}

/**
 * Generates a random string and store it in str
 */
char * rand_string(char * str, size_t str_size) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.\"!/$%?&*()_-+=<>{}[]'";
    size_t n;
    
    if (str_size > 0 && str != NULL) {
        --str_size;
        for (n = 0; n < str_size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[str_size] = '\0';
        return str;
    } else {
      return NULL;
    }
}

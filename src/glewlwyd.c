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

#include <ldap.h>
#include <getopt.h>
#include <signal.h>
#include <ctype.h>
#include <libconfig.h>
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
  struct config_elements * config = o_malloc(sizeof(struct config_elements));
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
  config->instance = o_malloc(sizeof(struct _u_instance));
  config->allow_origin = NULL;
  config->static_files_path = NULL;
  config->static_files_prefix = NULL;
  config->auth_ldap = NULL;
  config->auth_http = NULL;
  config->refresh_token_expiration = GLEWLWYD_REFRESH_TOKEN_EXP_DEFAULT;
  config->access_token_expiration = GLEWLWYD_ACCESS_TOKEN_EXP_DEFAULT;
  config->code_expiration = GLEWLWYD_CODE_EXPIRATION_DEFAULT;
  config->jwt_decode_key = NULL;
  config->jwt = NULL;
  config->session_key = o_strdup(GLEWLWYD_SESSION_KEY_DEFAULT);
  config->session_expiration = GLEWLWYD_SESSION_EXPIRATION_DEFAULT;
  config->admin_scope = o_strdup(GLEWLWYD_ADMIN_SCOPE);
  config->profile_scope = o_strdup(GLEWLWYD_PROFILE_SCOPE);
  config->additional_property_name = NULL;
  config->use_secure_connection = 0;
  config->secure_connection_key_file = NULL;
  config->secure_connection_pem_file = NULL;
  config->hash_algorithm = o_strdup(GLEWLWYD_DEFAULT_HASH_ALGORITHM);
  config->reset_password = 0;
  config->reset_password_config = NULL;
  config->login_url = NULL;
  config->grant_url = NULL;
  if (config->instance == NULL) {
    fprintf(stderr, "Memory error - config->instance\n");
    return 1;
  }
  ulfius_init_instance(config->instance, GLEWLWYD_DEFAULT_PORT, NULL, NULL);

  config->mime_types = o_malloc(sizeof(struct _u_map));
  if (config->mime_types == NULL) {
    y_log_message(Y_LOG_LEVEL_ERROR, "init - Error allocating resources for config->mime_types, aborting");
    exit_server(&config, GLEWLWYD_ERROR);
  }
  u_map_init(config->mime_types);
  u_map_put(config->mime_types, "*", "application/octet-stream");
  
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
  
  // At this point, we declare all API endpoints and configure 
  
  // Authorization endpoint
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_authorization, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_authorization, (void*)config);

  // Token endpoint
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/token/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_token, (void*)config);

  // Authentication
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/auth/user/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_validate_user_session, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/auth/user/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_user_session, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/auth/user/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_user_session, (void*)config);

  // Current user scope grant endpoints
  ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/auth/grant/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_user_session, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/auth/grant/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user_session_scope_grant, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/auth/grant/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_user_scope_grant, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/auth/grant/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_user_scope_delete, (void*)config);

  // Current user endpoints
  ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/profile/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user_session_profile, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->url_prefix, "/profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_user_profile, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/profile/refresh_token", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/profile/refresh_token", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_refresh_token_profile, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/profile/refresh_token", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_refresh_token_profile, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/profile/session", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/profile/session", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_session_profile, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/profile/session", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_session_profile, (void*)config);
  if (config->reset_password) {
    ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/profile/reset_password/:username", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_send_reset_user_profile, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->url_prefix, "/profile/reset_password/:username", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_reset_user_profile, (void*)config);
  }

  // Authorization type callbacks
  ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/authorization/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_scope_admin, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/authorization/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_authorization, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/authorization/:authorization_type", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_scope_admin, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/authorization/:authorization_type", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_authorization, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->url_prefix, "/authorization/:authorization_type", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_authorization, (void*)config);

  // Scope endpoints
  if (config->use_scope) {
    ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/scope/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_scope_admin, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/scope/:scope", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_scope_admin, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/scope/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_list_scope, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/scope/:scope", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_scope, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/scope/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_scope, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "PUT", config->url_prefix, "/scope/:scope", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_scope, (void*)config);
    ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/scope/:scope", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_scope, (void*)config);
  }

  // User endpoints
  ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/user/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_scope_admin, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/user/:username", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_scope_admin, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/user/:username/:action", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_scope_admin, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/user/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_list_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/user/:username", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/user/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->url_prefix, "/user/:username", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/user/:username", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/user/:username/refresh_token", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_refresh_token_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/user/:username/refresh_token", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_refresh_token_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/user/:username/session", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_session_user, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/user/:username/session", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_session_user, (void*)config);
  if (config->reset_password) {
    ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/user/:username/reset_password", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_send_reset_user, (void*)config);
  }

  // Client endpoints
  ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/client/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_scope_admin, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/client/:client_id", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_scope_admin, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/client/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_list_client, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/client/:client_id", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_client, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/client/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_client, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->url_prefix, "/client/:client_id", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_client, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/client/:client_id", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_client, (void*)config);

  // Resource endpoints
  ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/resource/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_scope_admin, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "*", config->url_prefix, "/resource/:resource", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_glewlwyd_check_scope_admin, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/resource/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_list_resource, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->url_prefix, "/resource/:resource", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_get_resource, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->url_prefix, "/resource/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_add_resource, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->url_prefix, "/resource/:resource", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_set_resource, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->url_prefix, "/resource/:resource", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_delete_resource, (void*)config);

  // Other configuration
  ulfius_add_endpoint_by_val(config->instance, "GET", "/", NULL, GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_root, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", "/config/", NULL, GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_server_configuration, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "OPTIONS", NULL, "*", GLEWLWYD_CALLBACK_PRIORITY_ZERO, &callback_glewlwyd_options, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->static_files_prefix, "*", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_glewlwyd_static_file, (void*)config);
  ulfius_set_default_endpoint(config->instance, &callback_default, (void*)config);

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

  if (config != NULL && *config != NULL) {
    // Cleaning data
    o_free((*config)->config_file);
    o_free((*config)->url_prefix);
    o_free((*config)->log_file);
    o_free((*config)->allow_origin);
    o_free((*config)->static_files_path);
    o_free((*config)->static_files_prefix);
    o_free((*config)->jwt_decode_key);
    o_free((*config)->session_key);
    o_free((*config)->admin_scope);
    o_free((*config)->profile_scope);
    o_free((*config)->secure_connection_key_file);
    o_free((*config)->secure_connection_pem_file);
    o_free((*config)->hash_algorithm);
    o_free((*config)->login_url);
    o_free((*config)->grant_url);
    o_free((*config)->additional_property_name);
    if ((*config)->reset_password_config != NULL) {
      o_free((*config)->reset_password_config->smtp_host);
      o_free((*config)->reset_password_config->smtp_user);
      o_free((*config)->reset_password_config->smtp_password);
      o_free((*config)->reset_password_config->email_from);
      o_free((*config)->reset_password_config->email_subject);
      o_free((*config)->reset_password_config->email_template);
      o_free((*config)->reset_password_config->page_url_prefix);
      o_free((*config)->reset_password_config);
    }
    jwt_free((*config)->jwt);
    u_map_clean_full((*config)->mime_types);
    if ((*config)->auth_ldap != NULL) {
      o_free((*config)->auth_ldap->uri);
      o_free((*config)->auth_ldap->bind_dn);
      o_free((*config)->auth_ldap->bind_passwd);
      
      o_free((*config)->auth_ldap->base_search_user);
      o_free((*config)->auth_ldap->filter_user_read);
      o_free((*config)->auth_ldap->login_property_user_read);
      o_free((*config)->auth_ldap->scope_property_user_read);
      o_free((*config)->auth_ldap->additional_property_value_read);
      o_free((*config)->auth_ldap->name_property_user_read);
      o_free((*config)->auth_ldap->email_property_user_read);
      o_free((*config)->auth_ldap->rdn_property_user_write);
      free_string_array((*config)->auth_ldap->login_property_user_write);
      free_string_array((*config)->auth_ldap->scope_property_user_write);
      free_string_array((*config)->auth_ldap->name_property_user_write);
      free_string_array((*config)->auth_ldap->email_property_user_write);
      free_string_array((*config)->auth_ldap->additional_property_value_write);
      o_free((*config)->auth_ldap->password_property_user_write);
      o_free((*config)->auth_ldap->password_algorithm_user_write);
      free_string_array((*config)->auth_ldap->object_class_user_write);
      
      o_free((*config)->auth_ldap->base_search_client);
      o_free((*config)->auth_ldap->filter_client_read);
      o_free((*config)->auth_ldap->client_id_property_client_read);
      o_free((*config)->auth_ldap->scope_property_client_read);
      o_free((*config)->auth_ldap->name_property_client_read);
      o_free((*config)->auth_ldap->description_property_client_read);
      o_free((*config)->auth_ldap->redirect_uri_property_client_read);
      o_free((*config)->auth_ldap->confidential_property_client_read);
      o_free((*config)->auth_ldap->rdn_property_client_write);
      free_string_array((*config)->auth_ldap->client_id_property_client_write);
      free_string_array((*config)->auth_ldap->scope_property_client_write);
      free_string_array((*config)->auth_ldap->name_property_client_write);
      free_string_array((*config)->auth_ldap->description_property_client_write);
      free_string_array((*config)->auth_ldap->redirect_uri_property_client_write);
      free_string_array((*config)->auth_ldap->confidential_property_client_write);
      o_free((*config)->auth_ldap->password_property_client_write);
      o_free((*config)->auth_ldap->password_algorithm_client_write);
      free_string_array((*config)->auth_ldap->object_class_client_write);
      
      o_free((*config)->auth_ldap);
    }
    if ((*config)->auth_http != NULL) {
      o_free((*config)->auth_http->url);
      o_free((*config)->auth_http);
    }
    h_close_db((*config)->conn);
    h_clean_connection((*config)->conn);
    ulfius_stop_framework((*config)->instance);
    ulfius_clean_instance((*config)->instance);
    o_free((*config)->instance);
    y_close_logs();
    
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
            config->url_prefix = o_strdup(optarg);
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
            tmp = o_strdup(optarg);
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
        case 'v':
					print_help(stdout);
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
  fprintf(output, "Copyright 2016-2017 Nicolas Mora <mail@babelouest.org>\n");
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
  fprintf(output, "\tdefault: ERROR\n");
  fprintf(output, "-f --log-file=PATH\n");
  fprintf(output, "\tPath for log file if log mode file is specified\n");
  fprintf(output, "-h --help\n");
  fprintf(output, "-v --version\n");
  fprintf(output, "\tPrint this message\n\n");
}

/**
 * handles signal catch to exit properly when ^C is used for example
 * I don't like global variables but it looks fine to people who designed this
 */
void exit_handler(int signal) {
  y_log_message(Y_LOG_LEVEL_INFO, "Glewlwyd caught a stop or kill signal (%d), exiting", signal);
  pthread_mutex_lock(&global_handler_close_lock);
  pthread_cond_signal(&global_handler_close_cond);
  pthread_mutex_unlock(&global_handler_close_lock);
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
 * Initialize the application configuration based on the config file content
 * Read the config file, get mandatory variables and devices
 */
int build_config_from_file(struct config_elements * config) {
  
  config_t cfg;
  config_setting_t * root = NULL, * database = NULL, * auth = NULL, * jwt = NULL, * mime_type_list = NULL, * mime_type = NULL, * reset_password_config = NULL;
  const char * cur_prefix = NULL, * cur_log_mode = NULL, * cur_log_level = NULL, * cur_log_file = NULL, * one_log_mode = NULL, * cur_hash_algorithm = NULL, 
             * db_type = NULL, * db_sqlite_path = NULL, * db_mariadb_host = NULL, * db_mariadb_user = NULL, * db_mariadb_password = NULL,
             * db_mariadb_dbname = NULL, * cur_allow_origin = NULL, * cur_static_files_path = NULL, * cur_static_files_prefix = NULL,
             * cur_session_key = NULL, * cur_admin_scope = NULL, * cur_profile_scope = NULL, * cur_additional_property_name = NULL, 
             * cur_auth_ldap_uri = NULL, * cur_auth_ldap_bind_dn = NULL, * cur_auth_ldap_bind_passwd = NULL,
             * cur_auth_ldap_base_search_user = NULL, * cur_auth_ldap_filter_user_read = NULL,
             * cur_auth_ldap_login_property_user_read = NULL, * cur_auth_ldap_name_property_user_read = NULL,
             * cur_auth_ldap_email_property_user_read = NULL, * cur_auth_ldap_scope_property_user_read = NULL,
             * cur_auth_ldap_additional_property_value_read = NULL, * cur_auth_ldap_additional_property_value_write = NULL,
             * cur_auth_ldap_rdn_property_user_write = NULL, * cur_auth_ldap_login_property_user_write = NULL,
             * cur_auth_ldap_name_property_user_write = NULL, * cur_auth_ldap_email_property_user_write = NULL,
             * cur_auth_ldap_scope_property_user_write = NULL, * cur_auth_ldap_password_property_user_write = NULL,
             * cur_auth_ldap_password_algorithm_user_write = NULL, * cur_auth_ldap_object_class_user_write = NULL,
             * cur_auth_ldap_base_search_client = NULL, * cur_auth_ldap_filter_client_read = NULL,
             * cur_auth_ldap_client_id_property_client_read = NULL, * cur_auth_ldap_name_property_client_read = NULL,
             * cur_auth_ldap_scope_property_client_read = NULL, * cur_auth_ldap_description_property_client_read = NULL,
             * cur_auth_ldap_redirect_uri_property_client_read = NULL, * cur_auth_ldap_confidential_property_client_read = NULL,
             * cur_auth_ldap_client_id_property_client_write = NULL, * cur_auth_ldap_rdn_property_client_write = NULL,
             * cur_auth_ldap_name_property_client_write = NULL, * cur_auth_ldap_scope_property_client_write = NULL,
             * cur_auth_ldap_description_property_client_write = NULL, * cur_auth_ldap_redirect_uri_property_client_write = NULL,
             * cur_auth_ldap_confidential_property_client_write = NULL, * cur_auth_ldap_password_property_client_write = NULL,
             * cur_auth_ldap_password_algorithm_client_write = NULL, * cur_auth_ldap_object_class_client_write = NULL,
             * cur_rsa_key_file = NULL, * cur_rsa_pub_file = NULL, * cur_ecdsa_key_file = NULL, * cur_ecdsa_pub_file = NULL, * cur_sha_secret = NULL,
             * extension = NULL, * mime_type_value = NULL, * cur_secure_connection_key_file = NULL, * cur_secure_connection_pem_file = NULL,
             * cur_grant_url = NULL, * cur_login_url = NULL, * cur_reset_password_smtp_host = NULL, * cur_reset_password_smtp_user = NULL,
             * cur_reset_password_smtp_password = NULL, * cur_reset_password_email_from = NULL, * cur_reset_password_email_subject = NULL,
             * cur_reset_password_email_template_path = NULL, * cur_reset_password_page_url_prefix = NULL,
             * cur_auth_http_auth_url = NULL;
  int db_mariadb_port = 0, cur_key_size = 512;
  int cur_http_auth = 0, cur_database_auth = 0, cur_ldap_auth = 0, cur_use_scope = 0, cur_use_rsa = 0, cur_use_ecdsa = 0, cur_use_sha = 0, cur_use_secure_connection = 0, cur_auth_ldap_user_write = 0, cur_auth_ldap_client_write = 0, cur_auth_http_check_server_certificate = 1, i;
  
  config_init(&cfg);
  
  if (!config_read_file(&cfg, config->config_file)) {
    fprintf(stderr, "Error parsing config file %s\nOn line %d error: %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
    config_destroy(&cfg);
    return 0;
  }
  
  if (config->instance->port == GLEWLWYD_DEFAULT_PORT) {
    int port;
    // Get Port number to listen to
    config_lookup_int(&cfg, "port", &port);
    config->instance->port = (uint)port;
  }
  
  if (config->url_prefix == NULL) {
    // Get prefix url
    if (config_lookup_string(&cfg, "url_prefix", &cur_prefix)) {
      config->url_prefix = o_strdup(cur_prefix);
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
              config->log_file = o_strdup(cur_log_file);
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
      config->allow_origin = o_strdup(cur_allow_origin);
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
  config_lookup_int(&cfg, "code_expiration", (int *)&config->code_expiration);
  
  config_lookup_string(&cfg, "session_key", &cur_session_key);
  if (cur_session_key != NULL) {
    o_free(config->session_key);
    config->session_key = strdup(cur_session_key);
  }
  
  config_lookup_string(&cfg, "admin_scope", &cur_admin_scope);
  if (cur_admin_scope != NULL) {
    o_free(config->admin_scope);
    config->admin_scope = strdup(cur_admin_scope);
  }
  
  config_lookup_string(&cfg, "profile_scope", &cur_profile_scope);
  if (cur_profile_scope != NULL) {
    o_free(config->profile_scope);
    config->profile_scope = strdup(cur_profile_scope);
  }
  
  config_lookup_string(&cfg, "additional_property_name", &cur_additional_property_name);
  if (cur_additional_property_name != NULL) {
    config->additional_property_name = strdup(cur_additional_property_name);
  }
  
  config_lookup_bool(&cfg, "use_scope", &cur_use_scope);
  config->use_scope = cur_use_scope;
  
  config_lookup_string(&cfg, "login_url", &cur_login_url);
  if (cur_login_url == NULL) {
    fprintf(stderr, "login_url is mandatory, exiting\n");
    config_destroy(&cfg);
    return 0;
  } else {
    config->login_url = strdup(cur_login_url);
    if (config->login_url == NULL) {
      fprintf(stderr, "Error allocating resources for config->login_url, exiting\n");
      config_destroy(&cfg);
      return 0;
    }
  }
  
  config_lookup_string(&cfg, "grant_url", &cur_grant_url);
  if (cur_grant_url == NULL) {
    fprintf(stderr, "grant_url is mandatory, exiting\n");
    config_destroy(&cfg);
    return 0;
  } else {
    config->grant_url = strdup(cur_grant_url);
    if (config->grant_url == NULL) {
      fprintf(stderr, "Error allocating resources for config->grant_url, exiting\n");
      config_destroy(&cfg);
      return 0;
    }
  }
  
  root = config_root_setting(&cfg);
  config_lookup_bool(&cfg, "reset_password", &config->reset_password);
  if (config->reset_password) {
    reset_password_config = config_setting_get_member(root, "reset_password_config");
    if (reset_password_config != NULL) {
      config->reset_password_config = o_malloc(sizeof(struct _reset_password_config));
      if (config->reset_password_config != NULL) {
        config->reset_password_config->smtp_host = NULL;
        config->reset_password_config->smtp_port = GLEWLWYD_RESET_PASSWORD_DEFAULT_SMTP_PORT;
        config->reset_password_config->smtp_use_tls = 0;
        config->reset_password_config->smtp_verify_certificate = 0;
        config->reset_password_config->smtp_user = NULL;
        config->reset_password_config->smtp_password = NULL;
        
        config->reset_password_config->token_expiration = GLEWLWYD_RESET_PASSWORD_DEFAULT_TOKEN_EXPIRATION;
        config->reset_password_config->email_from = NULL;
        config->reset_password_config->email_subject = NULL;
        config->reset_password_config->email_template = NULL;
        config->reset_password_config->page_url_prefix = NULL;
        
        if (config_setting_lookup_string(reset_password_config, "smtp_host", &cur_reset_password_smtp_host) == CONFIG_TRUE) {
          if ((config->reset_password_config->smtp_host = o_strdup(cur_reset_password_smtp_host)) == NULL) {
            fprintf(stderr, "Error allocating config->reset_password_config->smtp_host, exiting\n");
            config_destroy(&cfg);
            return 0;
          }
        }
        config_setting_lookup_int(reset_password_config, "smtp_port", (int *)&config->reset_password_config->smtp_port);
        config_setting_lookup_bool(reset_password_config, "smtp_use_tls", &config->reset_password_config->smtp_use_tls);
        config_setting_lookup_bool(reset_password_config, "smtp_verify_certificate", &config->reset_password_config->smtp_verify_certificate);
        if (config_setting_lookup_string(reset_password_config, "smtp_user", &cur_reset_password_smtp_user) == CONFIG_TRUE) {
          if ((config->reset_password_config->smtp_user = o_strdup(cur_reset_password_smtp_user)) == NULL) {
            fprintf(stderr, "Error allocating config->reset_password_config->smtp_user, exiting\n");
            config_destroy(&cfg);
            return 0;
          }
        }
        if (config_setting_lookup_string(reset_password_config, "smtp_password", &cur_reset_password_smtp_password) == CONFIG_TRUE) {
          if ((config->reset_password_config->smtp_password = o_strdup(cur_reset_password_smtp_password)) == NULL) {
            fprintf(stderr, "Error allocating config->reset_password_config->smtp_password, exiting\n");
            config_destroy(&cfg);
            return 0;
          }
        }
        config_setting_lookup_int(reset_password_config, "token_expiration", (int *)&config->reset_password_config->token_expiration);
        if (config_setting_lookup_string(reset_password_config, "email_from", &cur_reset_password_email_from) == CONFIG_TRUE) {
          if ((config->reset_password_config->email_from = o_strdup(cur_reset_password_email_from)) == NULL) {
            fprintf(stderr, "Error allocating config->reset_password_config->email_from, exiting\n");
            config_destroy(&cfg);
            return 0;
          }
        }
        if (config_setting_lookup_string(reset_password_config, "email_subject", &cur_reset_password_email_subject) == CONFIG_TRUE) {
          if ((config->reset_password_config->email_subject = o_strdup(cur_reset_password_email_subject)) == NULL) {
            fprintf(stderr, "Error allocating config->reset_password_config->email_subject, exiting\n");
            config_destroy(&cfg);
            return 0;
          }
        }
        if (config_setting_lookup_string(reset_password_config, "email_template", &cur_reset_password_email_template_path) == CONFIG_TRUE) {
          if ((config->reset_password_config->email_template = get_file_content(cur_reset_password_email_template_path)) == NULL) {
            fprintf(stderr, "Error email_template, exiting\n");
            config_destroy(&cfg);
            return 0;
          }
        }
        if (config_setting_lookup_string(reset_password_config, "page_url_prefix", &cur_reset_password_page_url_prefix) == CONFIG_TRUE) {
          if ((config->reset_password_config->page_url_prefix = o_strdup(cur_reset_password_page_url_prefix)) == NULL) {
            fprintf(stderr, "Error allocating config->reset_password_config->page_url_prefix, exiting\n");
            config_destroy(&cfg);
            return 0;
          }
        }
        
        if (config->reset_password_config->smtp_host == NULL || config->reset_password_config->email_from == NULL || config->reset_password_config->email_subject == NULL || config->reset_password_config->email_template == NULL || config->reset_password_config->page_url_prefix == NULL) {
          fprintf(stderr, "Error reset_password, mandatory parameters are missing, exiting %s %s %s %s %s\n", config->reset_password_config->smtp_host, config->reset_password_config->email_from, config->reset_password_config->email_subject, config->reset_password_config->email_template, config->reset_password_config->page_url_prefix);
          config_destroy(&cfg);
          return 0;
        }
      } else {
        fprintf(stderr, "Error allocating config->reset_password_config, exiting\n");
        config_destroy(&cfg);
        return 0;
      }
    } else {
      fprintf(stderr, "Error no reset_password_config values, exiting\n");
      config_destroy(&cfg);
      return 0;
    }
  }
  
  if (config->static_files_path == NULL) {
    // Get path that serve static files
    if (config_lookup_string(&cfg, "static_files_path", &cur_static_files_path)) {
      config->static_files_path = o_strdup(cur_static_files_path);
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
      config->static_files_prefix = o_strdup(cur_static_files_prefix);
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
      config->secure_connection_key_file = o_strdup(cur_secure_connection_key_file);
      config->secure_connection_pem_file = o_strdup(cur_secure_connection_pem_file);
    } else {
      fprintf(stderr, "Error secure connection is active but certificate is not valid, exiting\n");
      config_destroy(&cfg);
      return 0;
    }
  }
  
  // Get token hash algorithm
  if (config_lookup_string(&cfg, "hash_algorithm", &cur_hash_algorithm)) {
    o_free(config->hash_algorithm);
    config->hash_algorithm = o_strdup(cur_hash_algorithm);
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
  
  database = config_setting_get_member(root, "database");
  if (database != NULL) {
    if (config_setting_lookup_string(database, "type", &db_type) == CONFIG_TRUE) {
      if (0) {
        // I know, this is for the code below to work
#ifdef _HOEL_MARIADB
        } else if (0 == strncmp(db_type, "sqlite3", strlen("sqlite3"))) {
        if (config_setting_lookup_string(database, "path", &db_sqlite_path) == CONFIG_TRUE) {
          config->conn = h_connect_sqlite(db_sqlite_path);
          if (config->conn == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error opening sqlite database %s\n", db_sqlite_path);
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
#ifdef _HOEL_SQLITE
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
  
  auth = config_setting_get_member(root, "authentication");
  if (auth != NULL) {
    config_setting_lookup_bool(auth, "http_auth", &cur_http_auth);
    config->has_auth_http = cur_http_auth;
    if (config->has_auth_http &&
        config->use_scope) {
      config_destroy(&cfg);
      fprintf(stderr, "Error, due to security concerns you can not use authentication via HTTP together with scopes\n");
      return 0;
    }
    config_setting_lookup_bool(auth, "database_auth", &cur_database_auth);
    config->has_auth_database = cur_database_auth;
    config_setting_lookup_bool(auth, "ldap_auth", &cur_ldap_auth);
    config->has_auth_ldap = cur_ldap_auth;

    if (config->has_auth_http) {
      config_setting_lookup_string(auth, "http_auth_url", &cur_auth_http_auth_url);
      if (cur_auth_http_auth_url != NULL) {
        config->auth_http = o_malloc(sizeof(struct _auth_http));
        if (config->auth_http == NULL) {
          config_destroy(&cfg);
          fprintf(stderr, "Error allocating resources for config->auth_http\n");
          return 0;
        } else {
          config_setting_lookup_bool(auth, "http_auth_check_certificate", &cur_auth_http_check_server_certificate);
          config->auth_http->check_server_certificate = cur_auth_http_check_server_certificate;
          config->auth_http->url = o_strdup(cur_auth_http_auth_url);
          if (config->auth_http->url == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_http->url\n");
            return 0;
          }
        }
      } else {
        config_destroy(&cfg);
        fprintf(stderr, "Error, auth http error parameters\n");
        return 0;
      }
    }
    
    if (config->has_auth_ldap) {
      config_setting_lookup_string(auth, "uri", &cur_auth_ldap_uri);
      config_setting_lookup_string(auth, "bind_dn", &cur_auth_ldap_bind_dn);
      config_setting_lookup_string(auth, "bind_passwd", &cur_auth_ldap_bind_passwd);

      config_setting_lookup_string(auth, "base_search_user", &cur_auth_ldap_base_search_user);
      config_setting_lookup_string(auth, "filter_user_read", &cur_auth_ldap_filter_user_read);
      config_setting_lookup_string(auth, "login_property_user_read", &cur_auth_ldap_login_property_user_read);
      config_setting_lookup_string(auth, "name_property_user_read", &cur_auth_ldap_name_property_user_read);
      config_setting_lookup_string(auth, "email_property_user_read", &cur_auth_ldap_email_property_user_read);
      config_setting_lookup_string(auth, "additional_property_value_read", &cur_auth_ldap_additional_property_value_read);
      if (config->use_scope) {
        config_setting_lookup_string(auth, "scope_property_user_read", &cur_auth_ldap_scope_property_user_read);
      }
      
      config_setting_lookup_bool(auth, "ldap_user_write", &cur_auth_ldap_user_write);
      config_setting_lookup_string(auth, "rdn_property_user_write", &cur_auth_ldap_rdn_property_user_write);
      config_setting_lookup_string(auth, "login_property_user_write", &cur_auth_ldap_login_property_user_write);
      config_setting_lookup_string(auth, "name_property_user_write", &cur_auth_ldap_name_property_user_write);
      config_setting_lookup_string(auth, "email_property_user_write", &cur_auth_ldap_email_property_user_write);
      config_setting_lookup_string(auth, "additional_property_value_write", &cur_auth_ldap_additional_property_value_write);
      if (config->use_scope) {
        config_setting_lookup_string(auth, "scope_property_user_write", &cur_auth_ldap_scope_property_user_write);
      }
      config_setting_lookup_string(auth, "password_property_user_write", &cur_auth_ldap_password_property_user_write);
      config_setting_lookup_string(auth, "password_algorithm_user_write", &cur_auth_ldap_password_algorithm_user_write);
      config_setting_lookup_string(auth, "object_class_user_write", &cur_auth_ldap_object_class_user_write);
      
      config_setting_lookup_string(auth, "base_search_client", &cur_auth_ldap_base_search_client);
      config_setting_lookup_string(auth, "filter_client_read", &cur_auth_ldap_filter_client_read);
      config_setting_lookup_string(auth, "client_id_property_client_read", &cur_auth_ldap_client_id_property_client_read);
      config_setting_lookup_string(auth, "name_property_client_read", &cur_auth_ldap_name_property_client_read);
      config_setting_lookup_string(auth, "description_property_client_read", &cur_auth_ldap_description_property_client_read);
      config_setting_lookup_string(auth, "redirect_uri_property_client_read", &cur_auth_ldap_redirect_uri_property_client_read);
      config_setting_lookup_string(auth, "confidential_property_client_read", &cur_auth_ldap_confidential_property_client_read);
      if (config->use_scope) {
        config_setting_lookup_string(auth, "scope_property_client_read", &cur_auth_ldap_scope_property_client_read);
      }
      
      config_setting_lookup_bool(auth, "ldap_client_write", &cur_auth_ldap_client_write);
      config_setting_lookup_string(auth, "rdn_property_client_write", &cur_auth_ldap_rdn_property_client_write);
      config_setting_lookup_string(auth, "client_id_property_client_write", &cur_auth_ldap_client_id_property_client_write);
      config_setting_lookup_string(auth, "name_property_client_write", &cur_auth_ldap_name_property_client_write);
      config_setting_lookup_string(auth, "description_property_client_write", &cur_auth_ldap_description_property_client_write);
      config_setting_lookup_string(auth, "redirect_uri_property_client_write", &cur_auth_ldap_redirect_uri_property_client_write);
      config_setting_lookup_string(auth, "confidential_property_client_write", &cur_auth_ldap_confidential_property_client_write);
      if (config->use_scope) {
        config_setting_lookup_string(auth, "scope_property_client_write", &cur_auth_ldap_scope_property_client_write);
      }
      config_setting_lookup_string(auth, "password_property_client_write", &cur_auth_ldap_password_property_client_write);
      config_setting_lookup_string(auth, "password_algorithm_client_write", &cur_auth_ldap_password_algorithm_client_write);
      config_setting_lookup_string(auth, "object_class_client_write", &cur_auth_ldap_object_class_client_write);
      
      if (cur_auth_ldap_uri != NULL && 
          cur_auth_ldap_bind_dn != NULL && 
          cur_auth_ldap_bind_passwd != NULL && 
          
          cur_auth_ldap_base_search_user != NULL && 
          cur_auth_ldap_filter_user_read != NULL && 
          cur_auth_ldap_login_property_user_read != NULL && 
          cur_auth_ldap_name_property_user_read != NULL && 
          cur_auth_ldap_email_property_user_read != NULL && 
          cur_auth_ldap_additional_property_value_read != NULL && 
          (cur_auth_ldap_scope_property_user_read != NULL || !config->use_scope) && 
          
          (!cur_auth_ldap_user_write || 
          (cur_auth_ldap_rdn_property_user_write != NULL && 
          cur_auth_ldap_login_property_user_write != NULL && 
          cur_auth_ldap_name_property_user_write != NULL && 
          cur_auth_ldap_email_property_user_write != NULL && 
          cur_auth_ldap_additional_property_value_write != NULL && 
          (cur_auth_ldap_scope_property_user_write != NULL || !config->use_scope) && 
          cur_auth_ldap_password_property_user_write != NULL && 
          cur_auth_ldap_password_algorithm_user_write != NULL && 
          cur_auth_ldap_object_class_user_write != NULL)) && 
          
          cur_auth_ldap_base_search_client != NULL && 
          cur_auth_ldap_filter_client_read != NULL && 
          cur_auth_ldap_client_id_property_client_read != NULL && 
          cur_auth_ldap_name_property_client_read != NULL && 
          cur_auth_ldap_description_property_client_read != NULL && 
          cur_auth_ldap_redirect_uri_property_client_read != NULL && 
          cur_auth_ldap_confidential_property_client_read != NULL && 
          (cur_auth_ldap_scope_property_client_read != NULL || !config->use_scope) && 
          
          (!cur_auth_ldap_client_write || 
          (cur_auth_ldap_rdn_property_client_write != NULL && 
          cur_auth_ldap_client_id_property_client_write != NULL && 
          cur_auth_ldap_name_property_client_write != NULL && 
          cur_auth_ldap_description_property_client_write != NULL && 
          cur_auth_ldap_redirect_uri_property_client_write != NULL && 
          cur_auth_ldap_confidential_property_client_write != NULL && 
          (cur_auth_ldap_scope_property_client_write != NULL || !config->use_scope) && 
          cur_auth_ldap_password_property_client_write != NULL && 
          cur_auth_ldap_password_algorithm_client_write != NULL && 
          cur_auth_ldap_object_class_client_write != NULL))) {
        config->auth_ldap = o_malloc(sizeof(struct _auth_ldap));
        if (config->auth_ldap == NULL) {
          config_destroy(&cfg);
          fprintf(stderr, "Error allocating resources for config->auth_ldap\n");
          return 0;
        } else {
          memset(config->auth_ldap, 0, sizeof(struct _auth_ldap));
          
          config->auth_ldap->uri = o_strdup(cur_auth_ldap_uri);
          if (config->auth_ldap->uri == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->uri\n");
            return 0;
          }
          config->auth_ldap->bind_dn = o_strdup(cur_auth_ldap_bind_dn);
          if (config->auth_ldap->bind_dn == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->bind_dn\n");
            return 0;
          }
          config->auth_ldap->bind_passwd = o_strdup(cur_auth_ldap_bind_passwd);
          if (config->auth_ldap->bind_passwd == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->bind_passwd\n");
            return 0;
          }
          
          config->auth_ldap->base_search_user = o_strdup(cur_auth_ldap_base_search_user);
          if (config->auth_ldap->base_search_user == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->base_search_user\n");
            return 0;
          }
          config->auth_ldap->filter_user_read = o_strdup(cur_auth_ldap_filter_user_read);
          if (config->auth_ldap->filter_user_read == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->filter_user_read\n");
            return 0;
          }
          config->auth_ldap->login_property_user_read = o_strdup(cur_auth_ldap_login_property_user_read);
          if (config->auth_ldap->login_property_user_read == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->login_property_user_read\n");
            return 0;
          }
          if (config->use_scope) {
            config->auth_ldap->scope_property_user_read = o_strdup(cur_auth_ldap_scope_property_user_read);
            if (config->auth_ldap->scope_property_user_read == NULL) {
              config_destroy(&cfg);
              fprintf(stderr, "Error allocating resources for config->auth_ldap->scope_property_user_read\n");
              return 0;
            }
          }
          config->auth_ldap->name_property_user_read = o_strdup(cur_auth_ldap_name_property_user_read);
          if (config->auth_ldap->name_property_user_read == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->name_property_user_read\n");
            return 0;
          }
          config->auth_ldap->email_property_user_read = o_strdup(cur_auth_ldap_email_property_user_read);
          if (config->auth_ldap->email_property_user_read == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->email_property_user_read\n");
            return 0;
          }
          config->auth_ldap->additional_property_value_read = o_strdup(cur_auth_ldap_additional_property_value_read);
          if (config->auth_ldap->additional_property_value_read == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->additional_property_value_read\n");
            return 0;
          }
          config->auth_ldap->user_write = cur_auth_ldap_user_write;
          config->auth_ldap->rdn_property_user_write = o_strdup(cur_auth_ldap_rdn_property_user_write);
          if (config->auth_ldap->rdn_property_user_write == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->rdn_property_user_write\n");
            return 0;
          }
          if (split_string(cur_auth_ldap_login_property_user_write, ",", &config->auth_ldap->login_property_user_write) < 1) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->login_property_user_write\n");
            return 0;
          }
          if (config->use_scope) {
            if (split_string(cur_auth_ldap_scope_property_user_write, ",", &config->auth_ldap->scope_property_user_write) < 1) {
              config_destroy(&cfg);
              fprintf(stderr, "Error allocating resources for config->auth_ldap->scope_property_user_write\n");
              return 0;
            }
          }
          if (split_string(cur_auth_ldap_name_property_user_write, ",", &config->auth_ldap->name_property_user_write) < 1) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->name_property_user_write\n");
            return 0;
          }
          if (split_string(cur_auth_ldap_email_property_user_write, ",", &config->auth_ldap->email_property_user_write) < 1) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->email_property_user_write\n");
            return 0;
          }
          if (split_string(cur_auth_ldap_additional_property_value_write, ",", &config->auth_ldap->additional_property_value_write) < 1) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->additional_property_value_write\n");
            return 0;
          }
          config->auth_ldap->password_property_user_write = o_strdup(cur_auth_ldap_password_property_user_write);
          if (config->auth_ldap->password_property_user_write == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->password_property_user_write\n");
            return 0;
          }
          config->auth_ldap->password_algorithm_user_write = o_strdup(cur_auth_ldap_password_algorithm_user_write);
          if (config->auth_ldap->password_algorithm_user_write == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->password_algorithm_user_write\n");
            return 0;
          } else if (strcmp("SHA1", config->auth_ldap->password_algorithm_user_write) &&
                     strcmp("SSHA", config->auth_ldap->password_algorithm_user_write) &&
                     strcmp("SHA224", config->auth_ldap->password_algorithm_user_write) &&
                     strcmp("SSHA224", config->auth_ldap->password_algorithm_user_write) &&
                     strcmp("SHA256", config->auth_ldap->password_algorithm_user_write) &&
                     strcmp("SSHA256", config->auth_ldap->password_algorithm_user_write) &&
                     strcmp("SHA384", config->auth_ldap->password_algorithm_user_write) &&
                     strcmp("SSHA384", config->auth_ldap->password_algorithm_user_write) &&
                     strcmp("SHA512", config->auth_ldap->password_algorithm_user_write) &&
                     strcmp("SSHA512", config->auth_ldap->password_algorithm_user_write) &&
                     strcmp("MD5", config->auth_ldap->password_algorithm_user_write) &&
                     strcmp("SMD5", config->auth_ldap->password_algorithm_user_write) &&
                     strcmp("CRYPT", config->auth_ldap->password_algorithm_user_write)) {
            config_destroy(&cfg);
            fprintf(stderr, "Error user algorithm name unknown\n");
            return 0;
          }
          if (split_string(cur_auth_ldap_object_class_user_write, ",", &config->auth_ldap->object_class_user_write) < 1) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->object_class_user_write\n");
            return 0;
          }
          
          config->auth_ldap->base_search_client = o_strdup(cur_auth_ldap_base_search_client);
          if (config->auth_ldap->base_search_client == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->base_search_client\n");
            return 0;
          }
          config->auth_ldap->filter_client_read = o_strdup(cur_auth_ldap_filter_client_read);
          if (config->auth_ldap->filter_client_read == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->filter_client_read\n");
            return 0;
          }
          config->auth_ldap->client_id_property_client_read = o_strdup(cur_auth_ldap_client_id_property_client_read);
          if (config->auth_ldap->client_id_property_client_read == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->client_id_property_client_read\n");
            return 0;
          }
          if (config->use_scope) {
            config->auth_ldap->scope_property_client_read = o_strdup(cur_auth_ldap_scope_property_client_read);
            if (config->auth_ldap->scope_property_client_read == NULL) {
              config_destroy(&cfg);
              fprintf(stderr, "Error allocating resources for config->auth_ldap->scope_property_client_read\n");
              return 0;
            }
          }
          config->auth_ldap->name_property_client_read = o_strdup(cur_auth_ldap_name_property_client_read);
          if (config->auth_ldap->name_property_client_read == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->name_property_client_read\n");
            return 0;
          }
          config->auth_ldap->description_property_client_read = o_strdup(cur_auth_ldap_description_property_client_read);
          if (config->auth_ldap->description_property_client_read == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->description_property_client_read\n");
            return 0;
          }
          config->auth_ldap->redirect_uri_property_client_read = o_strdup(cur_auth_ldap_redirect_uri_property_client_read);
          if (config->auth_ldap->redirect_uri_property_client_read == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->redirect_uri_property_client_read\n");
            return 0;
          }
          config->auth_ldap->confidential_property_client_read = o_strdup(cur_auth_ldap_confidential_property_client_read);
          if (config->auth_ldap->confidential_property_client_read == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->confidential_property_client_read\n");
            return 0;
          }
          config->auth_ldap->client_write = cur_auth_ldap_client_write;
          config->auth_ldap->rdn_property_client_write = o_strdup(cur_auth_ldap_rdn_property_client_write);
          if (config->auth_ldap->rdn_property_client_write == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->rdn_property_client_write\n");
            return 0;
          }
          if (split_string(cur_auth_ldap_client_id_property_client_write, ",", &config->auth_ldap->client_id_property_client_write) < 1) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->client_id_property_client_write\n");
            return 0;
          }
          if (config->use_scope) {
            if (split_string(cur_auth_ldap_scope_property_client_write, ",", &config->auth_ldap->scope_property_client_write) < 1) {
              config_destroy(&cfg);
              fprintf(stderr, "Error allocating resources for config->auth_ldap->scope_property_client_write\n");
              return 0;
            }
          }
          if (split_string(cur_auth_ldap_name_property_client_write, ",", &config->auth_ldap->name_property_client_write) < 1) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->name_property_client_write\n");
            return 0;
          }
          if (split_string(cur_auth_ldap_description_property_client_write, ",", &config->auth_ldap->description_property_client_write) < 1) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->description_property_client_write\n");
            return 0;
          }
          if (split_string(cur_auth_ldap_redirect_uri_property_client_write, ",", &config->auth_ldap->redirect_uri_property_client_write) < 1) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->redirect_uri_property_client_write\n");
            return 0;
          }
          if (split_string(cur_auth_ldap_confidential_property_client_write, ",", &config->auth_ldap->confidential_property_client_write) < 1) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->confidential_property_client_write\n");
            return 0;
          }
          config->auth_ldap->password_property_client_write = o_strdup(cur_auth_ldap_password_property_client_write);
          if (config->auth_ldap->password_property_client_write == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->password_property_client_write\n");
            return 0;
          }
          config->auth_ldap->password_algorithm_client_write = o_strdup(cur_auth_ldap_password_algorithm_client_write);
          if (config->auth_ldap->password_algorithm_client_write == NULL) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->password_algorithm_client_write\n");
            return 0;
          } else if (strcmp("SHA1", config->auth_ldap->password_algorithm_client_write) &&
                     strcmp("SSHA", config->auth_ldap->password_algorithm_client_write) &&
                     strcmp("SHA224", config->auth_ldap->password_algorithm_client_write) &&
                     strcmp("SSHA224", config->auth_ldap->password_algorithm_client_write) &&
                     strcmp("SHA256", config->auth_ldap->password_algorithm_client_write) &&
                     strcmp("SSHA256", config->auth_ldap->password_algorithm_client_write) &&
                     strcmp("SHA384", config->auth_ldap->password_algorithm_client_write) &&
                     strcmp("SSHA384", config->auth_ldap->password_algorithm_client_write) &&
                     strcmp("SHA512", config->auth_ldap->password_algorithm_client_write) &&
                     strcmp("SSHA512", config->auth_ldap->password_algorithm_client_write) &&
                     strcmp("MD5", config->auth_ldap->password_algorithm_client_write) &&
                     strcmp("SMD5", config->auth_ldap->password_algorithm_client_write) &&
                     strcmp("CRYPT", config->auth_ldap->password_algorithm_client_write)) {
            config_destroy(&cfg);
            fprintf(stderr, "Error user algorithm name unknown\n");
            return 0;
          }
          if (split_string(cur_auth_ldap_object_class_client_write, ",", &config->auth_ldap->object_class_client_write) < 1) {
            config_destroy(&cfg);
            fprintf(stderr, "Error allocating resources for config->auth_ldap->object_class_client_write\n");
            return 0;
          }
        }
      } else {
        config_destroy(&cfg);
        fprintf(stderr, "Error, auth ldap error parameters\n");
        return 0;
      }
    }
  } else {
    config_destroy(&cfg);
    fprintf(stderr, "Error, no auth parameters\n");
    return 0;
  }

  jwt = config_setting_get_member(root, "jwt");
  if (jwt != NULL) {
    config_setting_lookup_bool(jwt, "use_rsa", &cur_use_rsa);
    config_setting_lookup_bool(jwt, "use_ecdsa", &cur_use_ecdsa);
    config_setting_lookup_bool(jwt, "use_sha", &cur_use_sha);
    config_setting_lookup_int(jwt, "key_size", &cur_key_size);
    if (cur_key_size != 256 && cur_key_size != 384 && cur_key_size != 512) {
      config_destroy(&cfg);
      fprintf(stderr, "Error, key_size incorrect, values available are 256, 384 or 512\n");
      return 0;
    }
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
          if (cur_key_size == 256) {
            jwt_set_alg(config->jwt, JWT_ALG_RS256, (const unsigned char *)key, key_len);
          } else if (cur_key_size == 384) {
            jwt_set_alg(config->jwt, JWT_ALG_RS384, (const unsigned char *)key, key_len);
          } else if (cur_key_size == 512) {
            jwt_set_alg(config->jwt, JWT_ALG_RS512, (const unsigned char *)key, key_len);
          }
          o_free(key);
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
    } else if (cur_use_ecdsa) {
      config_setting_lookup_string(jwt, "ecdsa_key_file", &cur_ecdsa_key_file);
      config_setting_lookup_string(jwt, "ecdsa_pub_file", &cur_ecdsa_pub_file);
      if (cur_ecdsa_key_file != NULL && cur_ecdsa_pub_file != NULL) {
        char * key;
        size_t key_len;
        
        jwt_new(&(config->jwt));
        key = get_file_content(cur_ecdsa_key_file);
        if (key != NULL) {
          key_len = strlen(key);
          if (cur_key_size == 256) {
            jwt_set_alg(config->jwt, JWT_ALG_ES256, (const unsigned char *)key, key_len);
          } else if (cur_key_size == 384) {
            jwt_set_alg(config->jwt, JWT_ALG_ES384, (const unsigned char *)key, key_len);
          } else if (cur_key_size == 512) {
            jwt_set_alg(config->jwt, JWT_ALG_ES512, (const unsigned char *)key, key_len);
          }
          o_free(key);
        } else {
          config_destroy(&cfg);
          fprintf(stderr, "Error, ecdsa_key_file content incorrect\n");
          return 0;
        }
        
        config->jwt_decode_key = get_file_content(cur_ecdsa_pub_file);
        if (config->jwt_decode_key == NULL) {
          config_destroy(&cfg);
          fprintf(stderr, "Error, ecdsa_pub_file content incorrect\n");
          return 0;
        }
      } else {
        config_destroy(&cfg);
        fprintf(stderr, "Error, ecdsa_key_file or ecdsa_pub_file incorrect\n");
        return 0;
      }
    } else if (cur_use_sha) {
      jwt_new(&(config->jwt));
      config_setting_lookup_string(jwt, "sha_secret", &cur_sha_secret);
      if (cur_sha_secret != NULL) {
        if (cur_key_size == 256) {
          jwt_set_alg(config->jwt, JWT_ALG_HS256, (const unsigned char *)cur_sha_secret, strlen(cur_sha_secret));
        } else if (cur_key_size == 384) {
          jwt_set_alg(config->jwt, JWT_ALG_HS384, (const unsigned char *)cur_sha_secret, strlen(cur_sha_secret));
        } else if (cur_key_size == 512) {
          jwt_set_alg(config->jwt, JWT_ALG_HS512, (const unsigned char *)cur_sha_secret, strlen(cur_sha_secret));
        }
        config->jwt_decode_key = o_strdup(cur_sha_secret);
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
    fprintf(stderr, "Error, no jwt parameters\n");
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
  
  if (config->url_prefix == NULL) {
    config->url_prefix = o_strdup(GLEWLWYD_DEFAULT_PREFIX);
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

/**
 * 
 * Escapes any special chars (RFC 4515) from a string representing a
 * a search filter assertion value.
 * 
 * You must o_free the returned value after use
 *
 */
char * escape_ldap(const char * input) {
  char * tmp, * to_return = NULL;
  size_t len, i;
  
  if (input != NULL) {
    to_return = strdup("");
    len = strlen(input);
    for (i=0; i < len && to_return != NULL; i++) {
      unsigned char c = input[i];
      if (c == '*') {
        // escape asterisk
        tmp = msprintf("%s\\2a", to_return);
        o_free(to_return);
        to_return = tmp;
      } else if (c == '(') {
        // escape left parenthesis
        tmp = msprintf("%s\\28", to_return);
        o_free(to_return);
        to_return = tmp;
      } else if (c == ')') {
        // escape right parenthesis
        tmp = msprintf("%s\\29", to_return);
        o_free(to_return);
        to_return = tmp;
      } else if (c == '\\') {
        // escape backslash
        tmp = msprintf("%s\\5c", to_return);
        o_free(to_return);
        to_return = tmp;
      } else if ((c & 0x80) == 0) {
        // regular 1-byte UTF-8 char
        tmp = msprintf("%s%c", to_return, c);
        o_free(to_return);
        to_return = tmp;
      } else if (((c & 0xE0) == 0xC0) && i < (len-2)) { 
        // higher-order 2-byte UTF-8 chars
        tmp = msprintf("%s\\%02x\\%02x", to_return, input[i], input[i+1]);
        o_free(to_return);
        to_return = tmp;
      } else if (((c & 0xF0) == 0xE0) && i < (len-3)) { 
        // higher-order 3-byte UTF-8 chars
        tmp = msprintf("%s\\%02x\\%02x\\%02x", to_return, input[i], input[i+1], input[i+2]);
        o_free(to_return);
        to_return = tmp;
      } else if (((c & 0xF8) == 0xF0) && i < (len-4)) { 
        // higher-order 4-byte UTF-8 chars
        tmp = msprintf("%s\\%02x\\%02x\\%02x\\%02x", to_return, input[i], input[i+1], input[i+2], input[i+3]);
        o_free(to_return);
        to_return = tmp;
      }
    }
  }
  return to_return;
}

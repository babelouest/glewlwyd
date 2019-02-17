/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * Declarations for constants and prototypes
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

#ifndef __GLEWLWYD_H_
#define __GLEWLWYD_H_

#define _GLEWLWYD_VERSION_ "2.0.0"

#include <jansson.h>

#ifndef _GNU_SOURCE
 #define _GNU_SOURCE
#endif

#ifndef __USE_GNU
 #define __USE_GNU
#endif

#include <stdio.h>

/** Angharad libraries **/
#include <ulfius.h>
#include <yder.h>
#include <hoel.h>

#include "glewlwyd-common.h"

#if MHD_VERSION < 0x00093800
  #error Libmicrohttpd version 0.9.38 minimum is required, you can download it at http://ftp.gnu.org/gnu/libmicrohttpd/
#endif

#define GLEWLWYD_LOG_NAME "Glewlwyd"

// Configuration default values
#define GLEWLWYD_DEFAULT_PORT               4593
#define GLEWLWYD_DEFAULT_PREFIX             "api"
#define GLEWLWYD_DEFAULT_ALLOW_ORIGIN       "*"
#define GLEWLWYD_DEFAULT_ADMIN_SCOPE        "g_admin"
#define GLEWLWYD_DEFAULT_PROFILE_SCOPE      "g_profile"
#define GLEWLWYD_DEFAULT_HASH_ALGORITHM     "SHA256"

#define GLEWLWYD_DEFAULT_SALT_LENGTH 16

#define GLEWLWYD_DEFAULT_SESSION_KEY "GLEWLWYD2_SESSION_ID"
#define GLEWLWYD_DEFAULT_SESSION_EXPIRATION_COOKIE 5256000 // 10 years
#define GLEWLWYD_DEFAULT_SESSION_EXPIRATION_PASSWORD 40320 // 4 weeks
#define GLEWLWYD_RESET_PASSWORD_DEFAULT_SESSION_EXPIRATION 2592000

#define GLEWLWYD_RUNNING  0
#define GLEWLWYD_STOP     1
#define GLEWLWYD_ERROR    2

#define G_OK                 0
#define G_ERROR              1
#define G_ERROR_UNAUTHORIZED 2
#define G_ERROR_PARAM        3
#define G_ERROR_DB           4
#define G_ERROR_MEMORY       5
#define G_ERROR_NOT_FOUND    6

// Data tables
#define GLEWLWYD_TABLE_USER_MODULE_INSTANCE                               "g_user_module_instance"
#define GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE                   "g_user_auth_scheme_module_instance"
#define GLEWLWYD_TABLE_CLIENT_MODULE_INSTANCE                             "g_client_module_instance"
#define GLEWLWYD_TABLE_PLUGIN_MODULE_INSTANCE                             "g_plugin_module_instance"
#define GLEWLWYD_TABLE_USER_SESSION                                       "g_user_session"
#define GLEWLWYD_TABLE_USER_SESSION_SCHEME                                "g_user_session_scheme"
#define GLEWLWYD_TABLE_SCOPE                                              "g_scope"
#define GLEWLWYD_TABLE_USER_AUTH_SCHEME_GROUP                             "g_user_auth_scheme_group"
#define GLEWLWYD_TABLE_USER_AUTH_SCHEME_GROUP_AUTH_SCHEME_MODULE_INSTANCE "g_user_auth_scheme_group_auth_scheme_module_instance"
#define GLEWLWYD_TABLE_USER_AUTH_SCHEME_GROUP_SCOPE                       "g_user_auth_scheme_group_scope"
#define GLEWLWYD_TABLE_CLIENT_USER_SCOPE                                  "g_client_user_scope"

// Callback priority
#define GLEWLWYD_CALLBACK_PRIORITY_ZERO           0
#define GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION 1
#define GLEWLWYD_CALLBACK_PRIORITY_APPLICATION    2
#define GLEWLWYD_CALLBACK_PRIORITY_CLOSE          3
#define GLEWLWYD_CALLBACK_PRIORITY_PLUGIN         4
#define GLEWLWYD_CALLBACK_PRIORITY_FILE           100
#define GLEWLWYD_CALLBACK_PRIORITY_GZIP           101

pthread_mutex_t global_handler_close_lock;
pthread_cond_t  global_handler_close_cond;

// Main functions and misc functions
int  build_config_from_args(int argc, char ** argv, struct config_elements * config);
int  build_config_from_file(struct config_elements * config);
int  check_config(struct config_elements * config);
void exit_handler(int handler);
void exit_server(struct config_elements ** config, struct config_plugin * config_p, int exit_value);
void print_help(FILE * output);
char * generate_hash(struct config_elements * config, const char * digest, const char * password);
char * get_file_content(const char * file_path);
int    load_user_module_instance_list(struct config_elements * config);
int    init_user_module_list(struct config_elements * config);
int    load_user_auth_scheme_module_instance_list(struct config_elements * config);
int    init_user_auth_scheme_module_list(struct config_elements * config);
int    init_client_module_list(struct config_elements * config);
int    load_client_module_instance_list(struct config_elements * config);
int    init_plugin_module_list(struct config_elements * config, struct config_plugin * config_p);
int    load_plugin_module_instance_list(struct config_elements * config, struct config_plugin * config_p);
struct _client_module_instance * get_client_module_instance(struct config_elements * config, const char * name);
struct _user_module_instance * get_user_module_instance(struct config_elements * config, const char * name);
struct _user_auth_scheme_module_instance * get_user_auth_scheme_module_instance(struct config_elements * config, const char * type, const char * name);

// Modules generic functions
int module_parameters_check(const char * module_parameters);
int module_instance_parameters_check(const char * module_parameters, const char * instance_parameters);

// Validate user login/password credentials
json_t * auth_check_user_credentials_scope(struct config_elements * config, const char * username, const char * password, const char * scope_list);
json_t * auth_check_user_credentials(struct config_elements * config, const char * username, const char * password);
json_t * auth_check_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, json_t * scheme_parameters);
json_t * auth_trigger_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, json_t * trigger_parameters);

// Session
int user_session_update(struct config_elements * config, const char * session_uid, const char * username, const char * scheme_type, const char * scheme_name);
json_t * get_session_for_username(struct config_elements * config, const char * session_uid, const char * username);
json_t * get_user_for_session(struct config_elements * config, const char * session_uid);
json_t * get_users_for_session(struct config_elements * config, const char * session_uid);
int user_session_delete(struct config_elements * config, const char * session_uid);

// User
json_t * get_user(struct config_elements * config, const char * username);
int user_has_scope(json_t * j_user, const char * scope);

// Client
json_t * get_client(struct config_elements * config, const char * client_id);
json_t * auth_check_client_credentials(struct config_elements * config, const char * client_id, const char * password);

// Scope
json_t * get_scope_list(struct config_elements * config);
json_t * get_scope(struct config_elements * config, const char * scope);
json_t * get_auth_scheme_list_from_scope(struct config_elements * config, const char * scope);
json_t * get_auth_scheme_list_from_scope_list(struct config_elements * config, const char * scope_list);
json_t * get_validated_auth_scheme_list_from_scope_list(struct config_elements * config, const char * scope_list, const char * session_uid);
json_t * get_client_user_scope_grant(struct config_elements * config, const char * client_id, const char * username, const char * scope_list);
json_t * get_granted_scopes_for_client(struct config_elements * config, json_t * j_user, const char * client_id, const char * scope_list);
int set_granted_scopes_for_client(struct config_elements * config, json_t * j_user, const char * client_id, const char * scope_list);
json_t * get_scope_list_allowed_for_session(struct config_elements * config, const char * scope_list, const char * session_uid);

// Plugin functions
int glewlwyd_callback_add_plugin_endpoint(struct config_plugin * config, const char * method, const char * prefix, const char * url, unsigned int priority, int (* callback)(const struct _u_request * request, struct _u_response * response, void * user_data), void * user_data);
int glewlwyd_callback_remove_plugin_endpoint(struct config_plugin * config, const char * method, const char * prefix, const char * url);
json_t * glewlwyd_callback_is_session_valid(struct config_plugin * config, const struct _u_request * request, const char * scope_list);
json_t * glewlwyd_callback_is_user_valid(struct config_plugin * config, const char * username, const char * password, const char * scope_list);
json_t * glewlwyd_callback_is_client_valid(struct config_plugin * config, const char * client_id, const char * password, const char * scope_list);
json_t * glewlwyd_callback_get_client_granted_scopes(struct config_plugin * config, const char * client_id, const char * username, const char * scope_list);
char * glewlwyd_callback_get_login_url(struct config_plugin * config, const char * client_id, const char * scope_list, const char * callback_url);
char * glewlwyd_callback_get_plugin_external_url(struct config_plugin * config, const char * name);
char * glewlwyd_callback_generate_hash(struct config_plugin * config, const char * data);

// Callback functions

int callback_glewlwyd_check_user_session (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_check_admin_session (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_close_check_session (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_user_auth (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_auth_trigger (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_get_session (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_get_schemes_from_scopes (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_delete_session (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_get_user_session_scope_grant (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_set_user_session_scope_grant (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_options (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_server_configuration (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_default (const struct _u_request * request, struct _u_response * response, void * user_data);

#endif

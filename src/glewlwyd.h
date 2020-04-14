/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Declarations for constants and prototypes
 *
 * Copyright 2016-2020 Nicolas Mora <mail@babelouest.org>
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

#define _GLEWLWYD_VERSION_ "2.3.0"

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
#define GLEWLWYD_DEFAULT_PORT                              4593
#define GLEWLWYD_DEFAULT_API_PREFIX                        "api"
#define GLEWLWYD_DEFAULT_ALLOW_ORIGIN                      "*"
#define GLEWLWYD_DEFAULT_ADMIN_SCOPE                       "g_admin"
#define GLEWLWYD_DEFAULT_PROFILE_SCOPE                     "g_profile"
#define GLEWLWYD_DEFAULT_HASH_ALGORITHM                    digest_SHA256
#define GLEWLWYD_DEFAULT_LOGIN_URL                         "login.html"
#define GLEWLWYD_DEFAULT_SESSION_KEY                       "GLEWLWYD2_SESSION_ID"
#define GLEWLWYD_DEFAULT_SESSION_EXPIRATION_COOKIE         5256000 // 10 years

#define GLEWLWYD_DEFAULT_SESSION_EXPIRATION_PASSWORD       40320   // 4 weeks
#define GLEWLWYD_RESET_PASSWORD_DEFAULT_SESSION_EXPIRATION 2592000 // 30 days
#define GLEWLWYD_SESSION_ID_LENGTH                         128

#define GLEWLWYD_RUNNING     0
#define GLEWLWYD_STOP        1
#define GLEWLWYD_ERROR       2

#define G_OK                 0
#define G_ERROR              1
#define G_ERROR_UNAUTHORIZED 2
#define G_ERROR_PARAM        3
#define G_ERROR_DB           4
#define G_ERROR_MEMORY       5
#define G_ERROR_NOT_FOUND    6

// Data tables
#define GLEWLWYD_TABLE_USER_MODULE_INSTANCE                    "g_user_module_instance"
#define GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE        "g_user_auth_scheme_module_instance"
#define GLEWLWYD_TABLE_CLIENT_MODULE_INSTANCE                  "g_client_module_instance"
#define GLEWLWYD_TABLE_PLUGIN_MODULE_INSTANCE                  "g_plugin_module_instance"
#define GLEWLWYD_TABLE_USER_SESSION                            "g_user_session"
#define GLEWLWYD_TABLE_USER_SESSION_SCHEME                     "g_user_session_scheme"
#define GLEWLWYD_TABLE_SCOPE                                   "g_scope"
#define GLEWLWYD_TABLE_SCOPE_GROUP                             "g_scope_group"
#define GLEWLWYD_TABLE_SCOPE_GROUP_AUTH_SCHEME_MODULE_INSTANCE "g_scope_group_auth_scheme_module_instance"
#define GLEWLWYD_TABLE_CLIENT_USER_SCOPE                       "g_client_user_scope"

// Module management
#define GLEWLWYD_MODULE_ACTION_STOP  0
#define GLEWLWYD_MODULE_ACTION_START 1

// Environment variables names
#define GLEWLWYD_ENV_PORT                       "GLWD_PORT"
#define GLEWLWYD_ENV_BIND_ADDRESS               "GLWD_BIND_ADDRESS"
#define GLEWLWYD_ENV_API_PREFIX                 "GLWD_API_PREFIX"
#define GLEWLWYD_ENV_EXTERNAL_URL               "GLWD_EXTERNAL_URL"
#define GLEWLWYD_ENV_LOGIN_URL                  "GLWD_LOGIN_URL"
#define GLEWLWYD_ENV_PROFILE_DELETE             "GLWD_PROFILE_DELETE"
#define GLEWLWYD_ENV_STATIC_FILES_PATH          "GLWD_STATIC_FILES_PATH"
#define GLEWLWYD_ENV_STATIC_FILES_MIME_TYPES    "GLWD_STATIC_FILES_MIME_TYPES"
#define GLEWLWYD_ENV_ALLOW_ORIGIN               "GLWD_ALLOW_ORIGIN"
#define GLEWLWYD_ENV_LOG_MODE                   "GLWD_LOG_MODE"
#define GLEWLWYD_ENV_LOG_LEVEL                  "GLWD_LOG_LEVEL"
#define GLEWLWYD_ENV_LOG_FILE                   "GLWD_LOG_FILE"
#define GLEWLWYD_ENV_COOKIE_DOMAIN              "GLWD_COOKIE_DOMAIN"
#define GLEWLWYD_ENV_COOKIE_SECURE              "GLWD_COOKIE_SECURE"
#define GLEWLWYD_ENV_SESSION_EXPIRATION         "GLWD_SESSION_EXPIRATION"
#define GLEWLWYD_ENV_SESSION_KEY                "GLWD_SESSION_KEY"
#define GLEWLWYD_ENV_ADMIN_SCOPE                "GLWD_ADMIN_SCOPE"
#define GLEWLWYD_ENV_PROFILE_SCOPE              "GLWD_PROFILE_SCOPE"
#define GLEWLWYD_ENV_USER_MODULE_PATH           "GLWD_USER_MODULE_PATH"
#define GLEWLWYD_ENV_CLIENT_MODULE_PATH         "GLWD_CLIENT_MODULE_PATH"
#define GLEWLWYD_ENV_AUTH_SCHEME_MODUE_PATH     "GLWD_AUTH_SCHEME_MODUE_PATH"
#define GLEWLWYD_ENV_PLUGIN_MODULE_PATH         "GLWD_PLUGIN_MODULE_PATH"
#define GLEWLWYD_ENV_USE_SECURE_CONNECTION      "GLWD_USE_SECURE_CONNECTION"
#define GLEWLWYD_ENV_SECURE_CONNECTION_KEY_FILE "GLWD_SECURE_CONNECTION_KEY_FILE"
#define GLEWLWYD_ENV_SECURE_CONNECTION_PEM_FILE "GLWD_SECURE_CONNECTION_PEM_FILE"
#define GLEWLWYD_ENV_SECURE_CONNECTION_CA_FILE  "GLWD_SECURE_CONNECTION_CA_FILE"
#define GLEWLWYD_ENV_HASH_ALGORITHM             "GLWD_HASH_ALGORITHM"
#define GLEWLWYD_ENV_DATABASE_TYPE              "GLWD_DATABASE_TYPE"
#define GLEWLWYD_ENV_DATABASE_MARIADB_HOST      "GLWD_DATABASE_MARIADB_HOST"
#define GLEWLWYD_ENV_DATABASE_MARIADB_USER      "GLWD_DATABASE_MARIADB_USER"
#define GLEWLWYD_ENV_DATABASE_MARIADB_PASSWORD  "GLWD_DATABASE_MARIADB_PASSWORD"
#define GLEWLWYD_ENV_DATABASE_MARIADB_DBNAME    "GLWD_DATABASE_MARIADB_DBNAME"
#define GLEWLWYD_ENV_DATABASE_MARIADB_PORT      "GLWD_DATABASE_MARIADB_PORT"
#define GLEWLWYD_ENV_DATABASE_SQLITE3_PATH      "GLWD_DATABASE_SQLITE3_PATH"
#define GLEWLWYD_ENV_DATABASE_POSTGRE_CONNINFO  "GLWD_DATABASE_POSTGRE_CONNINFO"

// Main functions and misc functions
int build_config_from_env(struct config_elements * config);
int  build_config_from_file(struct config_elements * config);
int build_config_from_args(int argc, char ** argv, struct config_elements * config, int * use_config_file, int * use_config_env);
int  check_config(struct config_elements * config);
void* signal_thread(void *arg);
void exit_server(struct config_elements ** config, int exit_value);
void print_help(FILE * output);
char * get_file_content(const char * file_path);
int    load_user_module_instance_list(struct config_elements * config);
int    init_user_module_list(struct config_elements * config);
int    load_user_auth_scheme_module_instance_list(struct config_elements * config);
int    init_user_auth_scheme_module_list(struct config_elements * config);
int    init_client_module_list(struct config_elements * config);
int    load_client_module_instance_list(struct config_elements * config);
int    init_plugin_module_list(struct config_elements * config);
int    load_plugin_module_instance_list(struct config_elements * config);
struct _client_module_instance * get_client_module_instance(struct config_elements * config, const char * name);
struct _client_module * get_client_module_lib(struct config_elements * config, const char * name);
struct _user_module_instance * get_user_module_instance(struct config_elements * config, const char * name);
struct _user_module * get_user_module_lib(struct config_elements * config, const char * name);
struct _user_auth_scheme_module_instance * get_user_auth_scheme_module_instance(struct config_elements * config, const char * name);
struct _user_auth_scheme_module * get_user_auth_scheme_module_lib(struct config_elements * config, const char * name);
struct _plugin_module_instance * get_plugin_module_instance(struct config_elements * config, const char * name);
struct _plugin_module * get_plugin_module_lib(struct config_elements * config, const char * name);

// Modules generic functions
int module_parameters_check(const char * module_parameters);
int module_instance_parameters_check(const char * module_parameters, const char * instance_parameters);

// Validate user login/password credentials
json_t * auth_check_user_credentials(struct config_elements * config, const char * username, const char * password);
json_t * auth_check_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, json_t * scheme_parameters, const struct _u_request * request);
json_t * auth_register_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, int delegate, json_t * j_register_parameters, const struct _u_request * request);
json_t * auth_register_get_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, const struct _u_request * request);
json_t * auth_trigger_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, json_t * register_parameters, const struct _u_request * request);

// Session
int user_session_update(struct config_elements * config, const char * session_uid, const char * user_agent, const char * issued_for, const char * username, const char * scheme_name);
json_t * get_session_for_username(struct config_elements * config, const char * session_uid, const char * username);
json_t * get_current_user_for_session(struct config_elements * config, const char * session_uid);
json_t * get_users_for_session(struct config_elements * config, const char * session_uid);
int user_session_delete(struct config_elements * config, const char * session_uid, const char * username);
char * get_session_id(struct config_elements * config, const struct _u_request * request);
char * generate_session_id();
json_t * get_user_session_list(struct config_elements * config, const char * username, const char * pattern, size_t offset, size_t limit, const char * sort);
int delete_user_session_from_hash(struct config_elements * config, const char * username, const char * session_hash);

// Profile
json_t * user_set_profile(struct config_elements * config, const char * username, json_t * j_profile);
int user_delete_profile(struct config_elements * config, const char * username);
json_t * user_get_profile(struct config_elements * config, const char * username);
int user_update_password(struct config_elements * config, const char * username, const char * old_password, const char * new_password);
int user_set_password(struct config_elements * config, const char * username, const char * new_password);
json_t * get_scheme_list_for_user(struct config_elements * config, const char * username);

// User
int user_has_scope(json_t * j_user, const char * scope);

// Client
json_t * auth_check_client_credentials(struct config_elements * config, const char * client_id, const char * password);

// Scope
json_t * get_auth_scheme_list_from_scope(struct config_elements * config, const char * scope);
json_t * get_auth_scheme_list_from_scope_list(struct config_elements * config, const char * scope_list);
json_t * get_validated_auth_scheme_list_from_scope_list(struct config_elements * config, const char * scope_list, const char * session_uid);
int is_scope_list_valid_for_session(struct config_elements * config, const char * scope_list, const char * session_uid);
json_t * get_client_user_scope_grant(struct config_elements * config, const char * client_id, const char * username, const char * scope_list);
json_t * get_granted_scopes_for_client(struct config_elements * config, json_t * j_user, const char * client_id, const char * scope_list);
int set_granted_scopes_for_client(struct config_elements * config, json_t * j_user, const char * client_id, const char * scope_list);
json_t * get_scope_list_allowed_for_session(struct config_elements * config, const char * scope_list, const char * session_uid);

// Module types
json_t * get_module_type_list(struct config_elements * config);

// User module functions
json_t * get_user_module_list(struct config_elements * config);
json_t * get_user_module(struct config_elements * config, const char * name);
json_t * is_user_module_valid(struct config_elements * config, json_t * j_module, int add);
json_t * add_user_module(struct config_elements * config, json_t * j_module);
int set_user_module(struct config_elements * config, const char * name, json_t * j_module);
int delete_user_module(struct config_elements * config, const char * name);
json_t * manage_user_module(struct config_elements * config, const char * name, int action);

// User auth scheme module functions
json_t * get_user_auth_scheme_module_list(struct config_elements * config);
json_t * get_user_auth_scheme_module(struct config_elements * config, const char * name);
json_t * is_user_auth_scheme_module_valid(struct config_elements * config, json_t * j_module, int add);
json_t * add_user_auth_scheme_module(struct config_elements * config, json_t * j_module);
int set_user_auth_scheme_module(struct config_elements * config, const char * name, json_t * j_module);
int delete_user_auth_scheme_module(struct config_elements * config, const char * name);
json_t * manage_user_auth_scheme_module(struct config_elements * config, const char * name, int action);

// Client module functions
json_t * get_client_module_list(struct config_elements * config);
json_t * get_client_module(struct config_elements * config, const char * name);
json_t * is_client_module_valid(struct config_elements * config, json_t * j_module, int add);
json_t * add_client_module(struct config_elements * config, json_t * j_module);
int set_client_module(struct config_elements * config, const char * name, json_t * j_module);
int delete_client_module(struct config_elements * config, const char * name);
json_t * manage_client_module(struct config_elements * config, const char * name, int action);

// Plugin module functions
json_t * get_plugin_module_list_for_user(struct config_elements * config);
json_t * get_plugin_module_list(struct config_elements * config);
json_t * get_plugin_module(struct config_elements * config, const char * name);
json_t * is_plugin_module_valid(struct config_elements * config, json_t * j_module, int add);
json_t * add_plugin_module(struct config_elements * config, json_t * j_module);
int set_plugin_module(struct config_elements * config, const char * name, json_t * j_module);
int delete_plugin_module(struct config_elements * config, const char * name);
json_t * manage_plugin_module(struct config_elements * config, const char * name, int action);

// Plugin functions
int glewlwyd_callback_add_plugin_endpoint(struct config_plugin * config, const char * method, const char * name, const char * url, unsigned int priority, int (* callback)(const struct _u_request * request, struct _u_response * response, void * user_data), void * user_data);
int glewlwyd_callback_remove_plugin_endpoint(struct config_plugin * config, const char * method, const char * name, const char * url);
json_t * glewlwyd_callback_check_session_valid(struct config_plugin * config, const struct _u_request * request, const char * scope_list);
json_t * glewlwyd_callback_check_user_valid(struct config_plugin * config, const char * username, const char * password, const char * scope_list);
json_t * glewlwyd_callback_check_client_valid(struct config_plugin * config, const char * client_id, const char * password);
json_t * glewlwyd_callback_get_client_granted_scopes(struct config_plugin * config, const char * client_id, const char * username, const char * scope_list);
int glewlwyd_callback_trigger_session_used(struct config_plugin * config, const struct _u_request * request, const char * scope_list);
time_t glewlwyd_callback_get_session_age(struct config_plugin * config, const struct _u_request * request, const char * scope_list);
char * glewlwyd_callback_get_login_url(struct config_plugin * config, const char * client_id, const char * scope_list, const char * callback_url, struct _u_map * additional_parameters);
char * glewlwyd_callback_get_plugin_external_url(struct config_plugin * config, const char * name);
char * glewlwyd_callback_generate_hash(struct config_plugin * config, const char * data);
json_t * glewlwyd_plugin_callback_get_user_list(struct config_plugin * config, const char * pattern, size_t offset, size_t limit);
json_t * glewlwyd_plugin_callback_get_user(struct config_plugin * config, const char * username);
json_t * glewlwyd_plugin_callback_get_user_profile(struct config_plugin * config, const char * username);
json_t * glewlwyd_plugin_callback_is_user_valid(struct config_plugin * config, const char * username, json_t * j_user, int add);
int glewlwyd_plugin_callback_add_user(struct config_plugin * config, json_t * j_user);
int glewlwyd_plugin_callback_set_user(struct config_plugin * config, const char * username, json_t * j_user);
int glewlwyd_plugin_callback_user_update_password(struct config_plugin * config, const char * username, const char * password);
int glewlwyd_plugin_callback_delete_user(struct config_plugin * config, const char * username);
json_t * glewlwyd_plugin_callback_get_client_list(struct config_plugin * config, const char * pattern, size_t offset, size_t limit);
json_t * glewlwyd_plugin_callback_get_client(struct config_plugin * config, const char * client_id);
json_t * glewlwyd_plugin_callback_is_client_valid(struct config_plugin * config, const char * client_id, json_t * j_client, int add);
int glewlwyd_plugin_callback_add_client(struct config_plugin * config, json_t * j_client);
int glewlwyd_plugin_callback_set_client(struct config_plugin * config, const char * client_id, json_t * j_client);
int glewlwyd_plugin_callback_delete_client(struct config_plugin * config, const char * client_id);
json_t * glewlwyd_plugin_callback_scheme_register(struct config_plugin * config, const char * mod_name, const struct _u_request * http_request, const char * username, json_t * j_scheme_data);
json_t * glewlwyd_plugin_callback_scheme_register_get(struct config_plugin * config, const char * mod_name, const struct _u_request * http_request, const char * username);
int glewlwyd_plugin_callback_scheme_can_use(struct config_plugin * config, const char * mod_name, const char * username);
int glewlwyd_plugin_callback_scheme_deregister(struct config_plugin * config, const char * mod_name, const char * username);

// User CRUD functions
json_t * get_user_list(struct config_elements * config, const char * pattern, size_t offset, size_t limit, const char * source);
json_t * get_user(struct config_elements * config, const char * username, const char * source);
json_t * get_user_profile(struct config_elements * config, const char * username, const char * source);
json_t * is_user_valid(struct config_elements * config, const char * username, json_t * j_user, int add, const char * source);
int add_user(struct config_elements * config, json_t * j_user, const char * source);
int set_user(struct config_elements * config, const char * username, json_t * j_user, const char * source);
int delete_user(struct config_elements * config, const char * username, const char * source);
json_t * glewlwyd_module_callback_get_user(struct config_module * config, const char * username);
int glewlwyd_module_callback_set_user(struct config_module * config, const char * username, json_t * j_user);
int glewlwyd_module_callback_check_user_password(struct config_module * config, const char * username, const char * password);
json_t * glewlwyd_module_callback_check_user_session(struct config_module * config, const struct _u_request * request, const char * username);

// Client CRUD functions
json_t * get_client_list(struct config_elements * config, const char * pattern, size_t offset, size_t limit, const char * source);
json_t * get_client(struct config_elements * config, const char * client_id, const char * source);
json_t * is_client_valid(struct config_elements * config, const char * client_id, json_t * j_client, int add, const char * source);
int add_client(struct config_elements * config, json_t * j_client, const char * source);
int set_client(struct config_elements * config, const char * client_id, json_t * j_client, const char * source);
int delete_client(struct config_elements * config, const char * client_id, const char * source);

// Scope CRUD functions
json_t * get_scope_list(struct config_elements * config, const char * pattern, size_t offset, size_t limit);
json_t * get_scope(struct config_elements * config, const char * scope);
json_t * is_scope_valid(struct config_elements * config, json_t * j_scope, int add);
int add_scope(struct config_elements * config, json_t * j_scope);
int set_scope(struct config_elements * config, const char * scope, json_t * j_scope);
int delete_scope(struct config_elements * config, const char * scope);

// Callback functions

int callback_glewlwyd_check_user_session (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_check_admin_session (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_check_admin_session_delegate (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_close_check_session (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_check_user_profile_valid (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_user_auth (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_auth_trigger (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_get_schemes_from_scopes (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_delete_session (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_user_get_profile (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_update_profile (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_delete_profile (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_update_password (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_get_plugin_list (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_get_session_list (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_get_scheme_list (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_delete_session (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_auth_register (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_auth_register_get (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_user_auth_register_delegate (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_auth_register_get_delegate (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_get_user_session_scope_grant (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_set_user_session_scope_grant (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_options (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_server_configuration (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_get_module_type_list (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_get_user_module_list (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_get_user_module (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_add_user_module (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_set_user_module (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_delete_user_module (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_manage_user_module (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_get_user_auth_scheme_module_list (const struct _u_request * request, struct _u_response * response, void * user_auth_scheme_data);
int callback_glewlwyd_get_user_auth_scheme_module (const struct _u_request * request, struct _u_response * response, void * user_auth_scheme_data);
int callback_glewlwyd_add_user_auth_scheme_module (const struct _u_request * request, struct _u_response * response, void * user_auth_scheme_data);
int callback_glewlwyd_set_user_auth_scheme_module (const struct _u_request * request, struct _u_response * response, void * user_auth_scheme_data);
int callback_glewlwyd_delete_user_auth_scheme_module (const struct _u_request * request, struct _u_response * response, void * user_auth_scheme_data);
int callback_glewlwyd_manage_user_auth_scheme_module (const struct _u_request * request, struct _u_response * response, void * user_auth_scheme_data);

int callback_glewlwyd_get_client_module_list (const struct _u_request * request, struct _u_response * response, void * client_data);
int callback_glewlwyd_get_client_module (const struct _u_request * request, struct _u_response * response, void * client_data);
int callback_glewlwyd_add_client_module (const struct _u_request * request, struct _u_response * response, void * client_data);
int callback_glewlwyd_set_client_module (const struct _u_request * request, struct _u_response * response, void * client_data);
int callback_glewlwyd_delete_client_module (const struct _u_request * request, struct _u_response * response, void * client_data);
int callback_glewlwyd_manage_client_module (const struct _u_request * request, struct _u_response * response, void * client_data);

int callback_glewlwyd_get_plugin_module_list (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_get_plugin_module (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_add_plugin_module (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_set_plugin_module (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_delete_plugin_module (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_manage_plugin_module (const struct _u_request * request, struct _u_response * response, void * plugin_data);

int callback_glewlwyd_get_user_list (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_get_user (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_add_user (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_set_user (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_delete_user (const struct _u_request * request, struct _u_response * response, void * plugin_data);

int callback_glewlwyd_get_client_list (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_get_client (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_add_client (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_set_client (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_delete_client (const struct _u_request * request, struct _u_response * response, void * plugin_data);

int callback_glewlwyd_get_scope_list (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_get_scope (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_add_scope (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_set_scope (const struct _u_request * request, struct _u_response * response, void * plugin_data);
int callback_glewlwyd_delete_scope (const struct _u_request * request, struct _u_response * response, void * plugin_data);

int callback_default (const struct _u_request * request, struct _u_response * response, void * user_data);

#endif

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

#define _GLEWLWYD_VERSION_ "1.4.9"

#include <jansson.h>
#include <jwt.h>

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

#include "glewlwyd_resource.h"
#include "static_file_callback.h"

#if MHD_VERSION < 0x00093800
  #error Libmicrohttpd version 0.9.38 minimum is required, you can download it at http://ftp.gnu.org/gnu/libmicrohttpd/
#endif

#define GLEWLWYD_LOG_NAME "Glewlwyd"
#define GLEWLWYD_CHECK_JWT_USERNAME "myrddin"

// Configuration default values
#define GLEWLWYD_DEFAULT_PORT               4593
#define GLEWLWYD_DEFAULT_PREFIX             "api"
#define GLEWLWYD_DEFAULT_ALLOW_ORIGIN       "*"
#define GLEWLWYD_DEFAULT_SALT_LENGTH        16
#define GLEWLWYD_DEFAULT_ADMIN_SCOPE        "g_admin"
#define GLEWLWYD_DEFAULT_PROFILE_SCOPE      "g_profile"
#define GLEWLWYD_DEFAULT_HASH_ALGORITHM     "SHA256"
#define GLEWLWYD_PREFIX_BEARER              "Bearer "

#define GLEWLWYD_RESET_PASSWORD_DEFAULT_SMTP_PORT        25
#define GLEWLWYD_RESET_PASSWORD_DEFAULT_TOKEN_EXPIRATION 604800

#define GLEWLWYD_DEFAULT_SESSION_KEY "GLEWLWYD_SESSION_ID"
#define GLEWLWYD_DEFAULT_SESSION_EXPIRATION_COOKIE 5256000 // 10 years
#define GLEWLWYD_DEFAULT_SESSION_EXPIRATION_PASSWORD 40320 // 4 weeks

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
#define GLEWLWYD_TABLE_USER_MODULE_INSTANCE "g_user_module_instance"
#define GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE "g_user_auth_scheme_module_instance"
#define GLEWLWYD_TABLE_USER_SESSION "g_user_session"
#define GLEWLWYD_TABLE_USER_SESSION_SCHEME "g_user_session_scheme"


// Callback priority
#define GLEWLWYD_CALLBACK_PRIORITY_ZERO           0
#define GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION 1
#define GLEWLWYD_CALLBACK_PRIORITY_APPLICATION    2
#define GLEWLWYD_CALLBACK_PRIORITY_FILE           3
#define GLEWLWYD_CALLBACK_PRIORITY_GZIP           4

pthread_mutex_t global_handler_close_lock;
pthread_cond_t  global_handler_close_cond;

typedef enum {
  digest_SHA1,
  digest_SHA224,
  digest_SHA256,
  digest_SHA384,
  digest_SHA512,
  digest_MD5,
} digest_algorithm;

struct config_elements;

struct _user_module {
  void      * file_handle;
  char      * parameters;
  char      * name;
  int      (* user_module_load)(struct config_elements * config, char ** name, char ** parameters);
  int      (* user_module_unload)(struct config_elements * config);
  int      (* user_module_init)(struct config_elements * config, const char * parameters, void ** cls);
  int      (* user_module_close)(struct config_elements * config, void * cls);
  char **  (* user_module_get_list)(const char * pattern, uint limit, uint offset, uint * total, void * cls);
  char *   (* user_module_get)(const char * username, void * cls);
  int      (* user_module_add)(const char * user, void * cls);
  int      (* user_module_update)(const char * username, const char * user, void * cls);
  int      (* user_module_delete)(const char * username, void * cls);
  int      (* user_module_check_password)(const char * username, const char * password, void * cls);
  int      (* user_module_update_password)(const char * username, const char * new_password, void * cls);
};

struct _user_module_instance {
  char                * name;
  struct _user_module * module;
  void                * cls;
  short int             enabled;
};

struct _client_module {
  void      * file_handle;
  char      * name;
  char      * parameters;
  int      (* client_module_load)(struct config_elements * config, char ** name, char ** parameters);
  int      (* client_module_unload)(struct config_elements * config);
  int      (* client_module_init)(struct config_elements * config, const char * parameters, void ** cls);
  int      (* client_module_close)(struct config_elements * config, void * cls);
  char **  (* client_module_get_list)(const char * pattern, uint limit, uint offset, uint * total, void * cls);
  char *   (* client_module_get)(const char * client_id, void * cls);
  int      (* client_module_add)(const char * client, void * cls);
  int      (* client_module_update)(const char * client_id, const char * client, void * cls);
  int      (* client_module_delete)(const char * client_id, void * cls);
  int      (* client_module_check_password)(const char * client_id, const char * password, void * cls);
  int      (* client_module_update_password)(const char * client_id, const char * new_password, void * cls);
};

struct _client_module_instance {
  char                  * name;
  struct _client_module * module;
  void                  * cls;
  short int               enabled;
};

struct _user_auth_scheme_module {
  void      * file_handle;
  char      * name;
  char      * parameters;
  int      (* user_auth_scheme_module_load)(struct config_elements * config, char ** name, char ** parameters);
  int      (* user_auth_scheme_module_unload)(struct config_elements * config);
  int      (* user_auth_scheme_module_init)(struct config_elements * config, const char * parameters, void ** cls);
  int      (* user_auth_scheme_module_close)(struct config_elements * config, void * cls);
  int      (* user_auth_scheme_module_validate)(const char * username, const char * scheme_data, void * cls);
};

struct _user_auth_scheme_module_instance {
  char                            * name;
  struct _user_auth_scheme_module * module;
  void                            * cls;
  short int                         enabled;
};

struct config_elements {
  char *                                      config_file;
  unsigned int                                port;
  char *                                      api_prefix;
  unsigned long                               log_mode;
  unsigned long                               log_level;
  char *                                      log_file;
  struct _static_file_config *                static_file_config;
  struct _glewlwyd_resource_config *          glewlwyd_resource_config_admin;
  struct _glewlwyd_resource_config *          glewlwyd_resource_config_profile;
  char *                                      allow_origin;
  unsigned int                                use_secure_connection;
  char *                                      secure_connection_key_file;
  char *                                      secure_connection_pem_file;
  struct _h_connection *                      conn;
  struct _u_instance *                        instance;
  char *                                      session_key;
  unsigned int                                session_expiration;
  unsigned int                                salt_length;
  char *                                      hash_algorithm;
  char *                                      login_url;
  char *                                      grant_url;
  char *                                      user_module_path;
  uint                                        user_module_list_size;
  struct _user_module **                      user_module_list;
  uint                                        user_module_instance_list_size;
  struct _user_module_instance **             user_module_instance_list;
  char *                                      client_module_path;
  uint                                        client_module_list_size;
  struct _client_module **                    client_module_list;
  uint                                        client_module_instance_list_size;
  struct _client_module_instance **           client_module_instance_list;
  char *                                      user_auth_scheme_module_path;
  uint                                        user_auth_scheme_module_list_size;
  struct _user_auth_scheme_module **          user_auth_scheme_module_list;
  uint                                        user_auth_scheme_module_instance_list_size;
  struct _user_auth_scheme_module_instance ** user_auth_scheme_module_instance_list;
};

// Main functions and misc functions
int  build_config_from_args(int argc, char ** argv, struct config_elements * config);
int  build_config_from_file(struct config_elements * config);
int  check_config(struct config_elements * config);
void exit_handler(int handler);
void exit_server(struct config_elements ** config, int exit_value);
void print_help(FILE * output);
char * url_decode(char *str);
char * url_encode(char *str);
char * generate_query_parameters(const struct _u_request * request);
const char * get_ip_source(const struct _u_request * request);
char * rand_string(char * str, size_t size);
char * generate_hash(struct config_elements * config, const char * digest, const char * password);
char * get_file_content(const char * file_path);
char * generate_hash(struct config_elements * config, const char * digest, const char * password);
int    load_user_module_instance_list(struct config_elements * config);
int    init_user_module_list(struct config_elements * config);
int    load_user_auth_scheme_module_instance_list(struct config_elements * config);
int    init_user_auth_scheme_module_list(struct config_elements * config);
int    init_client_module_list(struct config_elements * config);
int    load_client_module_instance_list(struct config_elements * config);
struct _client_module_instance * get_client_module_instance(struct config_elements * config, const char * name);
struct _user_module_instance * get_user_module_instance(struct config_elements * config, const char * name);
struct _user_auth_scheme_module_instance * get_user_auth_scheme_module_instance(struct config_elements * config, const char * name);

// Modules generic functions
int module_parameters_check(const char * module_parameters);
int module_instance_parameters_check(const char * module_parameters, const char * instance_parameters);

// Validate user login/password credentials
json_t * auth_check_user_credentials_scope(struct config_elements * config, const char * username, const char * password, const char * scope_list);
json_t * auth_check_user_credentials(struct config_elements * config, const char * username, const char * password);
json_t * auth_check_user_scheme(struct config_elements * config, const char * scheme, const char * username, json_t * scheme_parameters);

// Session
int update_session(struct config_elements * config, const char * session_uid, const char * username, const char * scheme_name, uint expiration);
json_t * get_session_for_username(struct config_elements * config, const char * session_uid, const char * username);
json_t * get_session(struct config_elements * config, const char * session_uid);

// Validate user scope
json_t * auth_check_user_scope(struct config_elements * config, const char * username, const char * scope_list);

// Validate client login/password credentials
json_t * auth_check_client_credentials(struct config_elements * config, const char * client_id, const char * password);

// Validate client scope
json_t * auth_check_client_scope(struct config_elements * config, const char * client_id, const char * scope_list);

// Validate authorization
json_t * session_check(struct config_elements * config, const char * session_value);
json_t * session_or_access_token_check(struct config_elements * config, const char * session_value, const char * header_value);

json_t * get_user_scope_grant(struct config_elements * config, const char * username);

int grant_client_user_scope_access(struct config_elements * config, const char * client_id, const char * username, const char * scope_list);
int delete_client_user_scope_access(struct config_elements * config, const char * client_id, const char * username, const char * scope_list);

// Scope crud
json_t * get_scope_list(struct config_elements * config);
json_t * get_scope(struct config_elements * config, const char * scope);
json_t * is_scope_valid(struct config_elements * config, json_t * j_scope, int add);
int add_scope(struct config_elements * config, json_t * j_scope);
int set_scope(struct config_elements * config, const char * scope, json_t * j_scope);
int delete_scope(struct config_elements * config, const char * scope);

// User CRUD
json_t * get_user_list(struct config_elements * config, uint64_t user_source_id, const char * search, uint offset, uint limit);
json_t * get_user(struct config_elements * config, uint64_t user_source_id, const char * username);
json_t * is_user_valid(struct config_elements * config, const char * user, json_t * j_user, int add);
int add_user(struct config_elements * config, uint64_t user_source_id, json_t * j_user);
int update_user(struct config_elements * config, uint64_t user_source_id, const char * user, json_t * j_user);
int delete_user(struct config_elements * config, uint64_t user_source_id, const char * user);
int is_reset_user_profile_valid(struct config_elements * config, const char * username, const char * token, const char * password);
int set_user_profile(struct config_elements * config, const char * username, json_t * profile);
int send_reset_user_profile_email(struct config_elements * config, const char * username);
int reset_user_profile(struct config_elements * config, const char * username, const char * token, const char * password);

// Client CRUD
json_t * get_client_list(struct config_elements * config, uint64_t client_source_id, const char * search, uint offset, uint limit);
json_t * get_client(struct config_elements * config, uint64_t client_source_id, const char * client_id);
json_t * is_client_valid(struct config_elements * config, json_t * j_client, int add);
int add_client(struct config_elements * config, uint64_t client_source_id, json_t * j_client);
int update_client(struct config_elements * config, uint64_t client_source_id, const char * client, json_t * j_client);
int delete_client(struct config_elements * config, uint64_t client_source_id, const char * client);

// Resource CRUD
json_t * get_resource_list(struct config_elements * config, uint offset, uint limit);
json_t * get_resource(struct config_elements * config, const char * resource);
json_t * is_resource_valid(struct config_elements * config, json_t * j_resource, int add);
int add_resource(struct config_elements * config, json_t * j_resource);
int set_resource(struct config_elements * config, const char * resource, json_t * j_resource);
int delete_resource(struct config_elements * config, const char * resource);

// Callback functions

int callback_glewlwyd_validate_user (const struct _u_request * request, struct _u_response * response, void * user_data);
#ifdef DEBUG
int callback_glewlwyd_check_user (const struct _u_request * request, struct _u_response * response, void * user_data); // TODO: Remove on release
#endif

int callback_glewlwyd_options (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_server_configuration (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_default (const struct _u_request * request, struct _u_response * response, void * user_data);

#endif

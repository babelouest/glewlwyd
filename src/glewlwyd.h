/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * OAuth2 authentiation server
 * Users are authenticated with a LDAP server
 * or users stored in the database 
 * Provides Json Web Tokens (jwt)
 * 
 * Declarations for constants and prototypes
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

#ifndef __GLEWLWYD_H_
#define __GLEWLWYD_H_

#define _GLEWLWYD_VERSION_ "1.2.3"

#include <jansson.h>
#include <jwt.h>

#ifndef _GNU_SOURCE
 #define _GNU_SOURCE
#endif

#ifndef __USE_GNU
 #define __USE_GNU
#endif

#include <crypt.h>
#include <stdio.h>

/** Angharad libraries **/
#define U_DISABLE_WEBSOCKET
#include <ulfius.h>
#include <yder.h>

#define _HOEL_MARIADB
#define _HOEL_SQLITE
#include <hoel.h>

#if MHD_VERSION < 0x00093800
	#error Libmicrohttpd version 0.9.38 minimum is required, you can download it at http://ftp.gnu.org/gnu/libmicrohttpd/
#endif

#define _GLEWLWYD_VERSION 1.1
#define GLEWLWYD_LOG_NAME "Glewlwyd"

// Configuration default values
#define GLEWLWYD_DEFAULT_PREFIX             "glewlwyd"
#define GLEWLWYD_DEFAULT_PORT               4593
#define GLEWLWYD_REFRESH_TOKEN_EXP_DEFAULT  1209600
#define GLEWLWYD_ACCESS_TOKEN_EXP_DEFAULT   3600
#define GLEWLWYD_SESSION_KEY_DEFAULT        "GLEWLWYD_SESSION_ID"
#define GLEWLWYD_SESSION_EXPIRATION_DEFAULT 2419200
#define GLEWLWYD_CODE_EXPIRATION_DEFAULT    600
#define GLEWLWYD_SALT_LENGTH                16
#define GLEWLWYD_ADMIN_SCOPE                "g_admin"
#define GLEWLWYD_PROFILE_SCOPE              "g_profile"
#define GLEWLWYD_DEFAULT_LIMIT              20
#define GLEWLWYD_PREFIX_BEARER              "Bearer "
#define GLEWLWYD_DEFAULT_HASH_ALGORITHM     "MD5"

#define GLEWLWYD_RESET_PASSWORD_DEFAULT_SMTP_PORT        25
#define GLEWLWYD_RESET_PASSWORD_DEFAULT_TOKEN_EXPIRATION 604800

#define GLEWLWYD_RUNNING  0
#define GLEWLWYD_STOP     1
#define GLEWLWYD_ERROR    2

#define G_OK                 0
#define G_ERROR              1
#define G_ERROR_UNAUTHORIZED 2
#define G_ERROR_PARAM        3
#define G_ERROR_DB           4
#define G_ERROR_MEMORY       5
#define G_ERROR_NOT_FOUND	   6

// Data tables
#define GLEWLWYD_TABLE_CLIENT                    "g_client"
#define GLEWLWYD_TABLE_SCOPE                     "g_scope"
#define GLEWLWYD_TABLE_USER                      "g_user"
#define GLEWLWYD_TABLE_RESOURCE                  "g_resource"
#define GLEWLWYD_TABLE_REDIRECT_URI              "g_redirect_uri"
#define GLEWLWYD_TABLE_REFRESH_TOKEN             "g_refresh_token"
#define GLEWLWYD_TABLE_ACCESS_TOKEN              "g_access_token"
#define GLEWLWYD_TABLE_SESSION                   "g_session"
#define GLEWLWYD_TABLE_CODE                      "g_code"
#define GLEWLWYD_TABLE_AUTHORIZATION_TYPE        "g_authorization_type"
#define GLEWLWYD_TABLE_RESET_PASSWORD            "g_reset_password"

// Link tables
#define GLEWLWYD_TABLE_CLIENT_USER_SCOPE         "g_client_user_scope"
#define GLEWLWYD_TABLE_CLIENT_AUTHORIZATION_TYPE "g_client_authorization_type"
#define GLEWLWYD_TABLE_RESOURCE_SCOPE            "g_resource_scope"
#define GLEWLWYD_TABLE_USER_SCOPE                "g_user_scope"
#define GLEWLWYD_TABLE_CLIENT_SCOPE              "g_client_scope"
#define GLEWLWYD_TABLE_CODE_SCOPE                "g_code_scope"
#define GLEWLWYD_TABLE_REFRESH_TOKEN_SCOPE       "g_refresh_token_scope"

// Authorization types available
#define GLEWLWYD_AUHORIZATION_TYPE_AUTHORIZATION_CODE                  0
#define GLEWLWYD_AUHORIZATION_TYPE_CODE                                1
#define GLEWLWYD_AUHORIZATION_TYPE_IMPLICIT                            2
#define GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS 3
#define GLEWLWYD_AUHORIZATION_TYPE_CLIENT_CREDENTIALS                  4
#define GLEWLWYD_AUHORIZATION_TYPE_REFRESH_TOKEN                       5

// Callback priority
#define GLEWLWYD_CALLBACK_PRIORITY_ZERO           0
#define GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION 1
#define GLEWLWYD_CALLBACK_PRIORITY_APPLICATION    2

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

struct _auth_http {
  char *            url;
};

struct _auth_ldap {
  char *            uri;
  char *            bind_dn;
  char *            bind_passwd;
  struct crypt_data cur_crypt_data;
  
  char *  base_search_user;
  char *  filter_user_read;
  char *  login_property_user_read;
  char *  scope_property_user_read;
  char *  name_property_user_read;
  char *  email_property_user_read;
  char *  additional_property_value_read;
  int     user_write;
  char *  rdn_property_user_write;
  char ** login_property_user_write;
  char ** scope_property_user_write;
  char ** name_property_user_write;
  char ** email_property_user_write;
  char ** additional_property_value_write;
  char *  password_property_user_write;
  char *  password_algorithm_user_write;
  char ** object_class_user_write;
  
  char *  base_search_client;
  char *  filter_client_read;
  char *  client_id_property_client_read;
  char *  scope_property_client_read;
  char *  name_property_client_read;
  char *  description_property_client_read;
  char *  redirect_uri_property_client_read;
  char *  confidential_property_client_read;
  int     client_write;
  char *  rdn_property_client_write;
  char ** client_id_property_client_write;
  char ** scope_property_client_write;
  char ** name_property_client_write;
  char ** description_property_client_write;
  char ** redirect_uri_property_client_write;
  char ** confidential_property_client_write;
  char *  password_property_client_write;
  char *  password_algorithm_client_write;
  char ** object_class_client_write;
};

struct _reset_password_config {
  char * smtp_host;
  unsigned int smtp_port;
  int smtp_use_tls;
  int smtp_verify_certificate;
  char * smtp_user;
  char * smtp_password;
  
  unsigned int token_expiration;
  char * email_from;
  char * email_subject;
  char * email_template;
  char * page_url_prefix;
};

struct config_elements {
  char *                          config_file;
  char *                          url_prefix;
  unsigned long                   log_mode;
  unsigned long                   log_level;
  char *                          log_file;
  char *                          allow_origin;
  char *                          static_files_path;
  char *                          static_files_prefix;
  unsigned int                    use_scope;
  unsigned int                    use_secure_connection;
  char *                          secure_connection_key_file;
  char *                          secure_connection_pem_file;
  unsigned int                    has_auth_http;
  unsigned int                    has_auth_database;
  unsigned int                    has_auth_ldap;
  struct _auth_http *             auth_http;
  struct _auth_ldap *             auth_ldap;
  struct _u_map *                 mime_types;
  struct _h_connection *          conn;
  struct _u_instance *            instance;
  jwt_t *                         jwt;
  char *                          jwt_decode_key;
  char *                          session_key;
  unsigned int                    session_expiration;
  unsigned int                    refresh_token_expiration;
  unsigned int                    access_token_expiration;
  unsigned int                    code_expiration;
  char *                          admin_scope;
  char *                          profile_scope;
  char *                          hash_algorithm;
  int                             reset_password;
  struct _reset_password_config * reset_password_config;
  char *                          login_url;
  char *                          grant_url;
  char *                          additional_property_name;
};

// Main functions and misc functions
int  build_config_from_args(int argc, char ** argv, struct config_elements * config);
int  build_config_from_file(struct config_elements * config);
int  check_config(struct config_elements * config);
void exit_handler(int handler);
void exit_server(struct config_elements ** config, int exit_value);
void print_help(FILE * output);
const char * get_filename_ext(const char *path);
char * get_file_content(const char * file_path);
char * url_decode(char *str);
char * url_encode(char *str);
char * generate_query_parameters(const struct _u_request * request);
const char * get_ip_source(const struct _u_request * request);
char * rand_string(char * str, size_t size);
char * rand_crypt_salt(char * str, size_t str_size);
char * generate_hash(struct config_elements * config, const char * digest, const char * password);
char * escape_ldap(const char * input);

// OAuth2 for input parameters validation
int check_auth_type_auth_code_grant (const struct _u_request * request, struct _u_response * response, void * user_data);
int check_auth_type_access_token_request (const struct _u_request * request, struct _u_response * response, void * user_data);
int check_auth_type_implicit_grant (const struct _u_request * request, struct _u_response * response, void * user_data);
int check_auth_type_resource_owner_pwd_cred (const struct _u_request * request, struct _u_response * response, void * user_data);
int check_auth_type_client_credentials_grant (const struct _u_request * request, struct _u_response * response, void * user_data);
int get_access_token_from_refresh (const struct _u_request * request, struct _u_response * response, void * user_data);
int delete_refresh_token (const struct _u_request * request, struct _u_response * response, void * user_data);
json_t * validate_authorization_code(struct config_elements * config, const char * authorization_code, const char * client_id, const char * redirect_uri, const char * ip_source);

// OAuth2 callback functions
int callback_glewlwyd_authorization (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_token (const struct _u_request * request, struct _u_response * response, void * user_data);

// Authorization callbacks functions
int callback_glewlwyd_check_user (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_check_user_session (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_check_scope_admin (const struct _u_request * request, struct _u_response * response, void * user_data);

// Validate user login/password credentials
json_t * auth_check_user_credentials_scope(struct config_elements * config, const char * username, const char * password, const char * scope_list);
json_t * auth_check_user_credentials(struct config_elements * config, const char * username, const char * password);
json_t * auth_check_user_credentials_http(struct config_elements * config, const char * username, const char * password);
json_t * auth_check_user_credentials_database(struct config_elements * config, const char * username, const char * password);
json_t * auth_check_user_credentials_ldap(struct config_elements * config, const char * username, const char * password);

// Validate user scope
json_t * auth_check_user_scope(struct config_elements * config, const char * username, const char * scope_list);
json_t * auth_check_user_scope_http(struct config_elements * config, const char * username, const char * scope_list);
json_t * auth_check_user_scope_database(struct config_elements * config, const char * username, const char * scope_list);
json_t * auth_check_user_scope_ldap(struct config_elements * config, const char * username, const char * scope_list);

// Validate client login/password credentials
json_t * auth_check_client_credentials(struct config_elements * config, const char * client_id, const char * password);
json_t * auth_check_client_credentials_http(struct config_elements * config, const char * client_id, const char * password);
json_t * auth_check_client_credentials_database(struct config_elements * config, const char * client_id, const char * password);
json_t * auth_check_client_credentials_ldap(struct config_elements * config, const char * client_id, const char * password);

// Validate client scope
json_t * auth_check_client_scope(struct config_elements * config, const char * client_id, const char * scope_list);
json_t * auth_check_client_scope_database(struct config_elements * config, const char * client_id, const char * scope_list);
json_t * auth_check_client_scope_ldap(struct config_elements * config, const char * client_id, const char * scope_list);
json_t * auth_check_client_scope_http(struct config_elements * config, const char * client_id, const char * scope_list);

// Validate client on a user oauth2 request
json_t * client_check(struct config_elements * config, const char * client_id, const char * client_id_header, const char * client_password_header, const char * redirect_uri, const int auth_type);
int auth_check_client_user_scope(struct config_elements * config, const char * client_id, const char * username, const char * scope_list);

// Validate authorization
json_t * session_check(struct config_elements * config, const char * session_value);
json_t * access_token_check_scope_profile(struct config_elements * config, const char * header_value);
json_t * access_token_check_scope_admin(struct config_elements * config, const char * header_value);
json_t * session_or_access_token_check(struct config_elements * config, const char * session_value, const char * header_value);

json_t * get_user_scope_grant(struct config_elements * config, const char * username);
json_t * get_user_scope_grant_http(struct config_elements * config, const char * username);
json_t * get_user_scope_grant_database(struct config_elements * config, const char * username);
json_t * get_user_scope_grant_ldap(struct config_elements * config, const char * username);

json_t * get_authorization_type(struct config_elements * config, const char * authorization_type);
int set_authorization_type(struct config_elements * config, const char * authorization_type, json_t * j_authorization_type);
json_t * is_authorization_type_valid(struct config_elements * config, json_t * j_authorization_type);
int is_authorization_type_enabled(struct config_elements * config, uint authorization_type);

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
json_t * get_user_list(struct config_elements * config, const char * source, const char * search, long int offset, long int limit);
json_t * get_user_list_http(struct config_elements * config, const char * search, long int offset, long int limit);
json_t * get_user_list_ldap(struct config_elements * config, const char * search, long int offset, long int limit);
json_t * get_user_list_database(struct config_elements * config, const char * search, long int offset, long int limit);
json_t * get_user(struct config_elements * config, const char * username, const char * source);
json_t * get_user_database(struct config_elements * config, const char * username);
json_t * get_user_ldap(struct config_elements * config, const char * username);
json_t * get_user_http(struct config_elements * config, const char * username);
json_t * is_user_valid(struct config_elements * config, json_t * j_user, int add);
int add_user(struct config_elements * config, json_t * j_user);
int add_user_http(struct config_elements * config, json_t * j_user);
int add_user_ldap(struct config_elements * config, json_t * j_user);
int add_user_database(struct config_elements * config, json_t * j_user);
int set_user(struct config_elements * config, const char * user, json_t * j_user, const char * source);
int set_user_ldap(struct config_elements * config, const char * user, json_t * j_user);
int set_user_database(struct config_elements * config, const char * user, json_t * j_user);
int delete_user(struct config_elements * config, const char * user, const char * source);
int delete_user_ldap(struct config_elements * config, const char * user);
int delete_user_database(struct config_elements * config, const char * user);
json_t * is_user_profile_valid(struct config_elements * config, const char * username, json_t * profile);
int is_reset_user_profile_valid(struct config_elements * config, const char * username, const char * token, const char * password);
int set_user_profile(struct config_elements * config, const char * username, json_t * profile);
int set_user_profile_ldap(struct config_elements * config, const char * username, json_t * profile);
int set_user_profile_database(struct config_elements * config, const char * username, json_t * profile);
int send_reset_user_profile_email(struct config_elements * config, const char * username, const char * ip_source);
int reset_user_profile(struct config_elements * config, const char * username, const char * token, const char * password);

// Client CRUD
json_t * get_client_list(struct config_elements * config, const char * source, const char * search, long int offset, long int limit);
json_t * get_client_list_http(struct config_elements * config, const char * search, long int offset, long int limit);
json_t * get_client_list_ldap(struct config_elements * config, const char * search, long int offset, long int limit);
json_t * get_client_list_database(struct config_elements * config, const char * search, long int offset, long int limit);
json_t * get_client(struct config_elements * config, const char * client_id, const char * source);
json_t * get_client_database(struct config_elements * config, const char * client_id);
json_t * get_client_ldap(struct config_elements * config, const char * client_id);
json_t * is_client_valid(struct config_elements * config, json_t * j_client, int add);
int add_client(struct config_elements * config, json_t * j_client);
int add_client_ldap(struct config_elements * config, json_t * j_client);
int add_client_database(struct config_elements * config, json_t * j_client);
int add_client_http(struct config_elements * config, json_t * j_client);
int set_client(struct config_elements * config, const char * client, json_t * j_client, const char * source);
int set_client_ldap(struct config_elements * config, const char * client, json_t * j_client);
int set_client_database(struct config_elements * config, const char * client, json_t * j_client);
int delete_client(struct config_elements * config, const char * client, const char * source);
int delete_client_ldap(struct config_elements * config, const char * client);
int delete_client_database(struct config_elements * config, const char * client);

// Resource CRUD
json_t * get_resource_list(struct config_elements * config);
json_t * get_resource(struct config_elements * config, const char * resource);
json_t * is_resource_valid(struct config_elements * config, json_t * j_resource, int add);
int add_resource(struct config_elements * config, json_t * j_resource);
int set_resource(struct config_elements * config, const char * resource, json_t * j_resource);
int delete_resource(struct config_elements * config, const char * resource);

// Refesh token CRUD
json_t * get_refresh_token_list(struct config_elements * config, const char * username, int valid, long int offset, long int limit);
int revoke_token(struct config_elements * config, const char * username, const char * token_hash);

// Session CRUD
json_t * get_session_list(struct config_elements * config, const char * username, int valid, long int offset, long int limit);
int get_session(struct config_elements * config, const char * username, const char * session_hash);
int revoke_session(struct config_elements * config, const char * username, const char * session_hash);

// Tokens generation and store digest
char * generate_refresh_token(struct config_elements * config, const char * client_id, const char * username, const uint auth_type, const char * ip_source, const char * scope_list, time_t now);
char * generate_access_token(struct config_elements * config, const char * refresh_token, const char * username, const uint auth_type, const char * ip_source, const char * scope_list, const char * additional_property_name, const char * additional_property_value, time_t now);
char * generate_session_token(struct config_elements * config, const char * username, const char * ip_source, time_t now);
char * generate_authorization_code(struct config_elements * config, const char * username, const char * client_id, const char * scope_list, const char * redirect_uri, const char * ip_source);
char * generate_client_access_token(struct config_elements * config, const char * client_id, const char * ip_source, const char * scope_list, time_t now);
char * generate_user_reset_password_token(struct config_elements * config, const char * username, const char * ip_source);

// Token serialization functions
int serialize_refresh_token(struct config_elements * config, const char * client_id, const char * username, const uint auth_type, const char * ip_source, const char * refresh_token, const char * scope_list, time_t now);
int serialize_access_token(struct config_elements * config, const uint auth_type, const char * ip_source, const char * refresh_token, const char * scope_list);
int serialize_session_token(struct config_elements * config, const char * username, const char * ip_source, const char * session_token, time_t now);

// Callback functions
int callback_glewlwyd_validate_user_session (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_delete_user_session (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_get_user_session_scope_grant (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_set_user_scope_grant (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_user_scope_delete (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_get_user_session_profile (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_set_user_profile (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_send_reset_user_profile (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_reset_user_profile (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_get_refresh_token_profile (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_delete_refresh_token_profile (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_get_session_profile (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_delete_session_profile (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_get_list_user (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_get_user (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_add_user (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_set_user (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_delete_user (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_get_refresh_token_user (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_delete_refresh_token_user (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_get_session_user (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_delete_session_user (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_send_reset_user (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_get_list_client (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_get_client (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_add_client (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_set_client (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_delete_client (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_get_list_scope (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_get_scope (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_add_scope (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_set_scope (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_delete_scope (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_get_list_resource (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_get_resource (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_add_resource (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_set_resource (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_delete_resource (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_get_authorization (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_set_authorization (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_glewlwyd_options (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_static_file (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_root (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_glewlwyd_server_configuration (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_default (const struct _u_request * request, struct _u_response * response, void * user_data);

#endif
